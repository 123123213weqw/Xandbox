//go:build linux

package gateway

import (
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func childPrivileges(s Snapshot) error {
	if os.Getuid() != int(s.UID) || os.Geteuid() != int(s.UID) || os.Getgid() != int(s.GID) || os.Getegid() != int(s.GID) || s.UID == 0 {
		return errors.New("unprivileged gateway identity required")
	}
	groups, e := os.Getgroups()
	if e != nil || len(groups) != 0 {
		return errors.New("gateway supplemental groups forbidden")
	}
	var data [2]unix.CapUserData
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if unix.Capget(&header, &data[0]) != nil {
		return errors.New("cannot verify gateway capabilities")
	}
	for _, c := range data {
		if c.Effective != 0 || c.Permitted != 0 || c.Inheritable != 0 {
			return errors.New("gateway capabilities must be empty")
		}
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); e != 0 {
		return errors.New("cannot set gateway no-new-privileges")
	}
	for _, limit := range []struct {
		kind  int
		value uint64
	}{{unix.RLIMIT_NOFILE, 192}, {unix.RLIMIT_NPROC, 64}, {unix.RLIMIT_CORE, 0}, {unix.RLIMIT_FSIZE, 0}} {
		if unix.Setrlimit(limit.kind, &unix.Rlimit{Cur: limit.value, Max: limit.value}) != nil {
			return errors.New("cannot bound gateway resource limits")
		}
	}
	cwd, e := os.Stat(".")
	root, re := os.Stat("/")
	if e != nil || re != nil || !os.SameFile(cwd, root) {
		return errors.New("gateway working directory outside executable root")
	}
	// The child can see only /gateway. No proc/dev/config/state mounts or files.
	entries, e := os.ReadDir("/")
	if e != nil || len(entries) != 1 || entries[0].Name() != "gateway" {
		return errors.New("gateway executable-only root required")
	}
	return nil
}
func RunChild() error {
	var st unix.Stat_t
	if unix.Fstat(3, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("gateway control descriptor required")
	}
	peer, e := unix.GetsockoptUcred(3, unix.SOL_SOCKET, unix.SO_PEERCRED)
	kind, ke := unix.GetsockoptInt(3, unix.SOL_SOCKET, unix.SO_TYPE)
	if e != nil || ke != nil || kind != unix.SOCK_SEQPACKET || peer.Uid != 0 || peer.Pid != int32(os.Getppid()) || peer.Pid <= 1 {
		return errors.New("root-created inherited gateway capability required")
	}
	ipcFD, e := unix.FcntlInt(3, unix.F_DUPFD_CLOEXEC, 5)
	if e != nil {
		return errors.New("gateway control duplicate failed")
	}
	ipcFile := os.NewFile(uintptr(ipcFD), "inherited-gateway-capability")
	defer ipcFile.Close()
	policyFD, e := unix.FcntlInt(4, unix.F_DUPFD_CLOEXEC, 5)
	if e != nil {
		return errors.New("gateway sealed policy required")
	}
	file := os.NewFile(uintptr(policyFD), "initial-policy")
	defer file.Close()
	snapshot, e := readSnapshot(file)
	file.Close()
	if e != nil {
		return e
	}
	unix.Close(3)
	unix.Close(4)
	if e = childPrivileges(snapshot); e != nil {
		return e
	}
	p, e := NewPolicy(snapshot, nil, time.Now())
	if e != nil {
		return e
	}
	store := &Store{}
	if e = store.Publish(p); e != nil {
		return e
	}
	conn, e := net.FileConn(ipcFile)
	if e != nil {
		return e
	}
	ipcFile.Close()
	ipc, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return errors.New("gateway packet socket required")
	}
	client := &controlClient{conn: ipc, store: store, done: make(chan struct{})}
	defer client.fail()
	frontend := NewFrontend(store, client.Dial)
	defer frontend.CloseIdle()
	client.closeIdle = frontend.CloseIdle
	listener, e := net.Listen("tcp", snapshot.Listen)
	if e != nil {
		return errors.New("gateway TLS listen failed")
	}
	limited := newBoundListener(listener)
	defer limited.Close()
	server := &http.Server{Handler: frontend, TLSConfig: store.TLSConfig(), TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	defer server.Close()
	go client.read()
	stopped := make(chan error, 1)
	go func() { stopped <- server.Serve(tls.NewListener(limited, server.TLSConfig)) }()
	if client.write(frame{op: opReady, request: snapshot.Epoch}) != nil {
		return errors.New("gateway readiness failed")
	}
	select {
	case <-client.done:
		return errors.New("gateway root capability lost")
	case <-stopped:
		return errors.New("gateway TLS server ended")
	}
}

type boundListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
	mu    sync.Mutex
	rate  bucket
}

func newBoundListener(l net.Listener) *boundListener {
	return &boundListener{Listener: l, slots: make(chan struct{}, MaxConnections), done: make(chan struct{}), rate: bucket{tokens: 32, last: time.Now()}}
}
func (l *boundListener) Close() error { l.once.Do(func() { close(l.done) }); return l.Listener.Close() }
func (l *boundListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	// Rate admission BEFORE Accept/handshake. No rejected-connection busy spin.
	for {
		l.mu.Lock()
		ok := l.rate.allow(time.Now(), 16, 32)
		l.mu.Unlock()
		if ok {
			break
		}
		select {
		case <-l.done:
			<-l.slots
			return nil, net.ErrClosed
		case <-time.After(63 * time.Millisecond):
		}
	}
	conn, e := l.Listener.Accept()
	if e != nil {
		<-l.slots
		return nil, e
	}
	return &boundedConn{Conn: conn, until: time.Now().Add(ConnectionLifetime), release: func() { <-l.slots }}, nil
}

type boundedConn struct {
	net.Conn
	until   time.Time
	release func()
	once    sync.Once
}

func (c *boundedConn) Close() error { e := c.Conn.Close(); c.once.Do(c.release); return e }
func (c *boundedConn) clamp(t time.Time) time.Time {
	if t.IsZero() || t.After(c.until) {
		return c.until
	}
	return t
}
func (c *boundedConn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(c.clamp(t)) }
func (c *boundedConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(c.clamp(t)) }
func (c *boundedConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(c.clamp(t)) }
