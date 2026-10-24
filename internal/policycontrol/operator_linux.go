//go:build linux

package policycontrol

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

type Activation struct {
	Command  PolicyCommand
	reply    chan policyReply
	answered *atomic.Bool
}

// Respond accepts one closed-vocabulary response. The caller must classify the
// command and perform/observe the actual policy-store and child-ACK operations;
// neither enqueueing nor replying through this transport performs activation.
func (r Activation) Respond(status PolicyStatus, code string) error {
	answer := policyReply{Version: 1, Status: status, Code: code}
	if !answer.valid() || r.reply == nil || r.answered == nil {
		return errors.New("invalid operator response")
	}
	if !r.answered.CompareAndSwap(false, true) {
		return errors.New("operator response already supplied")
	}
	r.reply <- answer
	return nil
}

type Server struct {
	listener    *net.UnixListener
	path        string
	info        os.FileInfo
	view        atomic.Value
	requests    chan Activation
	errors      chan error
	stop        chan struct{}
	once        sync.Once
	slots       chan struct{}
	mu          sync.Mutex
	closed      bool
	connections map[*net.UnixConn]struct{}
	wg          sync.WaitGroup
}

// Listen is deliberately not called by any current command. A future root
// supervisor must first hold its exclusive durable policy-state lock, retain it
// until Close returns, and arrange the dedicated private runtime directory.
// It cannot select a tenant-facing address, path or protocol through this API.
func Listen(initial PolicyStatus) (*Server, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, errors.New("root managed operator required")
	}
	return startPolicyOperator(OperatorSocket, initial)
}

func (s *Server) Requests() <-chan Activation { return s.requests }
func (s *Server) Errors() <-chan error        { return s.errors }

func operatorPeer(c *net.UnixConn, uid uint32, pid int) error {
	r, e := c.SyscallConn()
	if e != nil {
		return e
	}
	var u *unix.Ucred
	var inner error
	e = r.Control(func(fd uintptr) { u, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if e != nil || inner != nil || u == nil || u.Uid != uid || u.Pid <= 0 || (pid > 0 && int(u.Pid) != pid) {
		return errors.New("operator peer rejected")
	}
	return nil
}
func privateOperatorSocket(st os.FileInfo, uid uint32) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && st.Mode()&os.ModeSocket != 0 && s.Mode&07777 == 0600 && s.Uid == uid && s.Nlink == 1
}
func privateOperatorParent(st os.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && st.IsDir() && s.Uid == uint32(os.Geteuid()) && s.Mode&07777 == 0700
}
func startPolicyOperator(path string, initial PolicyStatus) (*Server, error) {
	if !initial.Valid() || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "operator.sock" {
		return nil, errors.New("invalid operator initial status or path")
	}
	dir, e := privatefile.ExistingDirectory(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	before, e := os.Lstat(dir)
	if e != nil || !privateOperatorParent(before) {
		return nil, errors.New("private operator directory required")
	}
	// Caller already owns the exclusive, identity-checked policy state lock.
	// Never adopt a live endpoint or unlink an unknown file to obtain its name.
	if st, e := os.Lstat(path); e == nil {
		if !privateOperatorSocket(st, uint32(os.Geteuid())) {
			return nil, errors.New("unknown operator endpoint")
		}
		c, ce := net.DialTimeout("unixpacket", path, 100*time.Millisecond)
		if ce == nil {
			c.Close()
			return nil, errors.New("live operator endpoint")
		}
		if !errors.Is(ce, unix.ECONNREFUSED) {
			return nil, errors.New("operator endpoint unconfirmed")
		}
		now, e := os.Lstat(path)
		if e != nil || !os.SameFile(st, now) {
			return nil, errors.New("operator endpoint changed")
		}
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	l, e := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if e != nil {
		return nil, e
	}
	l.SetUnlinkOnClose(false)
	info, e := os.Lstat(path)
	if e != nil {
		l.Close()
		return nil, e
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || info.Mode()&os.ModeSocket == 0 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		l.Close()
		return nil, errors.New("operator socket changed during creation")
	}
	cleanup := func() {
		l.Close()
		if now, e := os.Lstat(path); e == nil && os.SameFile(now, info) {
			_ = os.Remove(path)
		}
	}
	if e = os.Chmod(path, 0600); e != nil {
		cleanup()
		return nil, e
	}
	now, e := os.Lstat(dir)
	if e != nil || !os.SameFile(before, now) {
		cleanup()
		return nil, errors.New("operator directory changed")
	}
	s := &Server{listener: l, path: path, info: info, requests: make(chan Activation, 4), errors: make(chan error, 1), stop: make(chan struct{}), slots: make(chan struct{}, 4), connections: make(map[*net.UnixConn]struct{})}
	s.view.Store(initial)
	s.wg.Add(1)
	go s.accept()
	return s, nil
}
func (s *Server) Publish(v PolicyStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !validPolicyTransition(s.Status(), v) {
		return errors.New("invalid operator progress transition")
	}
	s.view.Store(v)
	return nil
}
func (s *Server) Status() PolicyStatus { return s.view.Load().(PolicyStatus) }
func (s *Server) Close() {
	s.once.Do(func() {
		close(s.stop)
		s.listener.Close()
		s.mu.Lock()
		s.closed = true
		for c := range s.connections {
			c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
		if now, e := os.Lstat(s.path); e == nil && os.SameFile(now, s.info) {
			_ = os.Remove(s.path)
		}
	})
}
func (s *Server) accept() {
	defer s.wg.Done()
	for {
		c, e := s.listener.AcceptUnix()
		if e != nil {
			select {
			case <-s.stop:
				return
			default:
			}
			select {
			case s.errors <- errors.New("operator listener failed"):
			default:
			}
			return
		}
		if operatorPeer(c, uint32(os.Geteuid()), 0) != nil {
			c.Close()
			continue
		}
		select {
		case s.slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			<-s.slots
			c.Close()
			return
		}
		s.connections[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() { s.mu.Lock(); delete(s.connections, c); s.mu.Unlock(); <-s.slots; c.Close() }()
			s.handle(c)
		}()
	}
}
func operatorPacket(c *net.UnixConn) ([]byte, error) {
	b := make([]byte, OperatorPacketLimit+1)
	oob := make([]byte, unix.CmsgSpace(4*4))
	raw, e := c.SyscallConn()
	if e != nil {
		return nil, e
	}
	var n, on, flags int
	var inner error
	// Atomic CLOEXEC, including hostile SCM_RIGHTS received concurrently with a
	// future child exec. Every received right is closed and the packet rejected.
	e = raw.Read(func(fd uintptr) bool {
		n, on, flags, _, inner = unix.Recvmsg(int(fd), b, oob, unix.MSG_CMSG_CLOEXEC)
		return inner != unix.EAGAIN && inner != unix.EWOULDBLOCK
	})
	if e != nil || inner != nil {
		return nil, errors.Join(e, inner)
	}
	msgs, pe := unix.ParseSocketControlMessage(oob[:on])
	for _, m := range msgs {
		fds, fe := unix.ParseUnixRights(&m)
		if fe != nil {
			pe = fe
		}
		for _, fd := range fds {
			unix.Close(fd)
		}
	}
	if pe != nil || on != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n == 0 || n > OperatorPacketLimit {
		return nil, errors.New("invalid operator packet")
	}
	return b[:n], nil
}
func (s *Server) handle(c *net.UnixConn) {
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	answer := policyReply{Version: 1, Code: "INVALID"}
	raw, e := operatorPacket(c)
	var command PolicyCommand
	if e == nil && strictjson.Decode(raw, &command) == nil && command.Valid() {
		if command.Operation == "status" {
			answer = policyReply{Version: 1, Status: s.Status()}
		} else {
			request := Activation{Command: command, reply: make(chan policyReply, 1), answered: &atomic.Bool{}}
			select {
			case s.requests <- request:
				select {
				case answer = <-request.reply:
				case <-s.stop:
					answer.Code = "UNAVAILABLE"
				case <-time.After(1500 * time.Millisecond):
					answer.Code = "BUSY"
				}
			default:
				answer.Code = "BUSY"
			}
		}
	}
	if !answer.valid() {
		answer = policyReply{Version: 1, Code: "UNAVAILABLE"}
	}
	b, _ := json.Marshal(answer)
	_, _ = c.Write(b)
}

// RequestPolicy is local root-only control, not the tenant TLS API. The path
// and protocol are fixed; kernel peer PID binds it to the observed manager main.
func RequestPolicy(ctx context.Context, expectedPID int, command PolicyCommand) (PolicyStatus, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || expectedPID <= 1 {
		return PolicyStatus{}, errors.New("root managed operator required")
	}
	return requestPolicyAt(ctx, OperatorSocket, uint32(0), expectedPID, command)
}
func requestPolicyAt(ctx context.Context, path string, uid uint32, pid int, command PolicyCommand) (PolicyStatus, error) {
	var zero PolicyStatus
	if !command.Valid() || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "operator.sock" || pid <= 1 {
		return zero, errors.New("invalid operator command or binding")
	}
	dir, e := privatefile.ExistingDirectory(filepath.Dir(path))
	if e != nil {
		return zero, e
	}
	st, e := os.Lstat(dir)
	if e != nil || !privateOperatorParent(st) {
		return zero, errors.New("private operator parent required")
	}
	before, e := os.Lstat(path)
	if e != nil || !privateOperatorSocket(before, uid) {
		return zero, errors.New("private operator socket required")
	}
	d := net.Dialer{Timeout: time.Second}
	conn, e := d.DialContext(ctx, "unixpacket", path)
	if e != nil {
		return zero, e
	}
	defer conn.Close()
	c := conn.(*net.UnixConn)
	after, e := os.Lstat(path)
	if e != nil || !os.SameFile(before, after) || operatorPeer(c, uid, pid) != nil {
		return zero, errors.New("operator endpoint identity changed")
	}
	now, e := os.Lstat(dir)
	if e != nil || !os.SameFile(st, now) || !privateOperatorParent(now) {
		return zero, errors.New("operator parent identity changed")
	}
	deadline := time.Now().Add(2 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	_ = c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	b, e := json.Marshal(command)
	if e != nil || len(b) > OperatorPacketLimit {
		return zero, errors.New("invalid operator payload")
	}
	if _, e = c.Write(b); e != nil {
		return zero, e
	}
	raw, e := operatorPacket(c)
	if e != nil {
		return zero, e
	}
	var reply policyReply
	if strictjson.Decode(raw, &reply) != nil || !reply.valid() || reply.Code != "" {
		return zero, errors.New("policy activation unconfirmed")
	}
	if command.Operation == "activate" && (reply.Status.DurableEpoch != command.TargetEpoch || reply.Status.SnapshotSHA256 != command.SnapshotSHA256 || reply.Status.Phase == "fenced") {
		return zero, errors.New("policy activation target unconfirmed")
	}
	return reply.Status, nil
}
