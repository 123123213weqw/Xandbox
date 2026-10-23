//go:build linux

package gateway

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

type lease struct {
	conn  *net.UnixConn
	until time.Time
}
type incoming struct {
	value frame
	fd    int
	err   error
}

func connectTenant(ctx context.Context, path string, dir os.FileInfo) (*net.UnixConn, error) {
	current, e := socketParent(path)
	if e != nil || !os.SameFile(dir, current) {
		return nil, errors.New("tenant socket directory changed")
	}
	before, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || before.Mode()&os.ModeSocket == 0 || before.Mode().Perm() != 0600 {
		return nil, errors.New("private root tenant socket required")
	}
	d := net.Dialer{Timeout: time.Second}
	conn, e := d.DialContext(ctx, "unix", path)
	if e != nil {
		return nil, e
	}
	u := conn.(*net.UnixConn)
	after, e := os.Lstat(path)
	if e != nil || !os.SameFile(before, after) {
		u.Close()
		return nil, errors.New("tenant socket identity changed")
	}
	raw, e := u.SyscallConn()
	if e != nil {
		u.Close()
		return nil, e
	}
	var peer *unix.Ucred
	var inner error
	e = raw.Control(func(fd uintptr) { peer, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if e != nil || inner != nil || peer == nil || peer.Uid != 0 || peer.Pid <= 0 {
		u.Close()
		return nil, errors.New("root tenant peer required")
	}
	return u, nil
}
func sendConnection(c *net.UnixConn, f frame, conn *net.UnixConn) error {
	raw, e := conn.SyscallConn()
	if e != nil {
		return e
	}
	var inner error
	e = raw.Control(func(fd uintptr) { inner = writeFrame(c, f, int(fd)) })
	return errors.Join(e, inner)
}
func closeLease(l lease) {
	raw, e := l.conn.SyscallConn()
	if e == nil {
		_ = raw.Control(func(fd uintptr) { _ = unix.Shutdown(int(fd), unix.SHUT_RDWR) })
	}
	_ = l.conn.Close()
}
func leaseID(active map[uint64]lease) (uint64, error) {
	for i := 0; i < 4; i++ {
		var b [8]byte
		if _, e := rand.Read(b[:]); e != nil {
			return 0, e
		}
		n := binary.LittleEndian.Uint64(b[:])
		if n != 0 {
			if _, exists := active[n]; !exists {
				return n, nil
			}
		}
	}
	return 0, errors.New("lease entropy collision")
}

// Go-created files already use CLOEXEC. Also constrain any descriptors the
// root command itself inherited from an external launcher: ExtraFiles alone
// does not close arbitrary non-CLOEXEC descriptors above its mapped range.
func sanitizeInheritedFDs() error { return unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC) }

func childCommand(c Config, childFD, policyFD *os.File) *exec.Cmd {
	cmd := exec.Command("/gateway", "-child")
	cmd.Dir = "/" // chroot does not change cwd; never inherit an outside directory.
	cmd.Env = []string{"PATH=/", "GOMAXPROCS=2", "GOTRACEBACK=none"}
	cmd.ExtraFiles = []*os.File{childFD, policyFD}
	// Nil standard streams become /dev/null opened by os/exec before chroot.
	// Never delegate caller-provided stdio files/sockets/directory capabilities.
	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: c.EmptyRoot, Credential: &syscall.Credential{Uid: c.UID, Gid: c.GID, Groups: []uint32{}}, Pdeathsig: syscall.SIGKILL}
	return cmd
}

// RunRoot is a fixed connector supervisor, NOT an HTTP/TLS listener. Its child
// runs after setuid/setgid inside a root-owned read-only executable-only chroot.
// No controller changes or state-directory DAC delegation are needed.
func RunRoot(configPath string) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("root gateway supervisor required")
	}
	c, e := loadConfig(configPath)
	if e != nil {
		return e
	}
	if e = checkChildRoot(c.EmptyRoot); e != nil {
		return errors.New("invalid gateway executable root")
	}
	dir, e := socketParent(c.TenantSocket)
	if e != nil {
		return errors.New("invalid tenant socket binding")
	}
	data, e := rootFile(c.BackendAuthFile, 65536)
	if e != nil {
		return errors.New("cannot read backend authority")
	}
	var authConfig access.Config
	if strictjson.Decode(data, &authConfig) != nil {
		return errors.New("invalid backend authority")
	}
	authority, e := access.New(authConfig)
	if e != nil {
		return errors.New("invalid backend authority")
	}
	initial, e := c.snapshot(c.PolicyRevision, authority)
	if e != nil {
		return e
	}
	state, e := openPolicyState(c.StateDir, gatewayBinding(c, data))
	if e != nil {
		return errors.New("gateway durable policy state rejected")
	}
	defer state.Close()
	if e = state.Commit(initial); e != nil {
		return errors.New("gateway durable policy commit rejected")
	}
	policyFD, e := sealedSnapshot(initial)
	if e != nil {
		return errors.New("cannot seal gateway policy")
	}
	defer policyFD.Close()
	parent, child, e := packetPair()
	if e != nil {
		return e
	}
	defer parent.Close()
	defer child.Close()
	childFD, e := child.File()
	if e != nil {
		return e
	}
	defer childFD.Close()
	cmd := childCommand(c, childFD, policyFD)
	if e = sanitizeInheritedFDs(); e != nil {
		return errors.New("cannot constrain gateway descriptor inheritance")
	}
	if e = cmd.Start(); e != nil {
		return errors.New("cannot start unprivileged gateway child")
	}
	childFD.Close()
	child.Close()
	policyFD.Close()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	active := make(map[uint64]lease)
	reaped := false
	defer func() {
		for _, l := range active {
			closeLease(l)
		}
		parent.Close()
		if !reaped {
			_ = cmd.Process.Kill()
			<-exited
		}
	}()
	messages := make(chan incoming, 1)
	stopRead := make(chan struct{})
	defer close(stopRead)
	go func() {
		for {
			f, fd, e := readFrame(parent)
			select {
			case messages <- incoming{f, fd, e}:
			case <-stopRead:
				if fd >= 0 {
					unix.Close(fd)
				}
				return
			}
			if e != nil {
				return
			}
		}
	}()
	term := make(chan os.Signal, 2)
	reload := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(term)
	defer signal.Stop(reload)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	epoch := c.PolicyRevision
	waiting := epoch
	readyBy := time.Now().Add(5 * time.Second)
	lastConnect := uint64(0)
	heartbeatAt := time.Now().Add(time.Second)
	now := time.Now()
	allRate := bucket{tokens: 256, last: now}
	connectRate := bucket{tokens: 32, last: now}
	for {
		if !time.Now().Before(heartbeatAt) {
			if e := writeFrame(parent, frame{op: opHeartbeat, request: epoch}, -1); e != nil {
				return errors.New("gateway heartbeat failed")
			}
			heartbeatAt = time.Now().Add(time.Second)
		}
		select {
		case <-term:
			// The root parent has no HTTP requests to drain; closing its IPC capability
			// closes the child listener and shuts down all brokered controller sockets.
			return nil
		case <-reload:
			if waiting != 0 {
				return errors.New("gateway reload already pending")
			}
			next, e := loadConfig(configPath)
			if e != nil || !c.sameBinding(next) {
				return errors.New("gateway reload rejected; closing ingress")
			}
			if epoch == ^uint64(0) || next.PolicyRevision != epoch+1 {
				return errors.New("gateway reload revision rejected; closing ingress")
			}
			epoch = next.PolicyRevision
			if epoch == 0 {
				return errors.New("gateway policy epoch exhausted")
			}
			s, e := next.snapshot(epoch, authority)
			if e != nil {
				return errors.New("gateway reload rejected; closing ingress")
			}
			if e = state.Commit(s); e != nil {
				return errors.New("gateway reload persistence rejected; closing ingress")
			}
			fd, e := sealedSnapshot(s)
			if e != nil {
				return errors.New("gateway reload rejected; closing ingress")
			}
			e = writeFrame(parent, frame{op: opPolicy, request: epoch}, int(fd.Fd()))
			fd.Close()
			if e != nil {
				return errors.New("gateway policy transfer failed")
			}
			c = next
			waiting = epoch
			readyBy = time.Now().Add(2 * time.Second)
		case <-tick.C:
			now = time.Now()
			if waiting != 0 && now.After(readyBy) {
				return errors.New("gateway child readiness deadline exceeded")
			}
			for id, l := range active {
				if !now.Before(l.until) {
					closeLease(l)
					delete(active, id)
				}
			}
		case e = <-exited:
			reaped = true
			if e == nil {
				return errors.New("gateway child ended unexpectedly")
			}
			return errors.New("gateway child failed")
		case msg := <-messages:
			if msg.fd >= 0 {
				unix.Close(msg.fd)
				return errors.New("child supplied an unexpected descriptor")
			}
			if msg.err != nil {
				return errors.New("gateway child capability closed")
			}
			q := msg.value
			now = time.Now()
			if !allRate.allow(now, 128, 256) {
				return errors.New("gateway child control budget exceeded")
			}
			switch q.op {
			case opReady:
				if q.lease != 0 || waiting == 0 || q.request != waiting {
					return errors.New("invalid gateway readiness acknowledgement")
				}
				waiting = 0
			case opRelease:
				if q.request != 0 || q.lease == 0 {
					return errors.New("invalid gateway lease release")
				}
				if l, ok := active[q.lease]; ok {
					closeLease(l)
					delete(active, q.lease)
				}
			case opConnect:
				if q.lease != 0 || q.request == 0 || q.request <= lastConnect {
					return errors.New("invalid gateway connect sequence")
				}
				lastConnect = q.request
				if waiting != 0 || len(active) >= MaxLeases || !connectRate.allow(now, 16, 32) {
					if e = writeFrame(parent, frame{op: opUnavailable, request: q.request}, -1); e != nil {
						return e
					}
					continue
				}
				conn, e := connectTenant(context.Background(), c.TenantSocket, dir)
				if e != nil {
					if e = writeFrame(parent, frame{op: opUnavailable, request: q.request}, -1); e != nil {
						return e
					}
					continue
				}
				id, e := leaseID(active)
				if e != nil {
					conn.Close()
					return e
				}
				active[id] = lease{conn: conn, until: time.Now().Add(LeaseLifetime)}
				if e = sendConnection(parent, frame{op: opConnected, request: q.request, lease: id}, conn); e != nil {
					return e
				}
			default:
				return errors.New("invalid gateway child control operation")
			}
		}
	}
}

// A child can request only a connection to the already-bound tenant socket.
// RELEASE has no response, so closing transport idle connections never waits
// recursively for this reader goroutine to deliver an acknowledgement.
type controlClient struct {
	conn      *net.UnixConn
	store     *Store
	closeIdle func()
	done      chan struct{}
	once      sync.Once
	writeMu   sync.Mutex
	dialMu    sync.Mutex
	pendingMu sync.Mutex
	pending   chan incoming
	pendingID uint64
}

func (c *controlClient) fail() { c.once.Do(func() { close(c.done); c.conn.Close() }) }
func (c *controlClient) write(f frame) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	e := writeFrame(c.conn, f, -1)
	if e != nil {
		c.fail()
	}
	return e
}
func (c *controlClient) read() {
	defer c.fail()
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		f, fd, e := readFrame(c.conn)
		if e != nil {
			return
		}
		switch f.op {
		case opHeartbeat:
			current := c.store.Current()
			if fd >= 0 {
				unix.Close(fd)
				return
			}
			if current == nil || f.request != current.snapshot.Epoch || f.lease != 0 {
				return
			}
		case opPolicy:
			if fd < 0 || f.lease != 0 {
				if fd >= 0 {
					unix.Close(fd)
				}
				return
			}
			file := os.NewFile(uintptr(fd), "sealed-policy")
			s, e := readSnapshot(file)
			file.Close()
			if e != nil || s.Epoch != f.request {
				return
			}
			p, e := NewPolicy(s, nil, time.Now())
			if e != nil || c.store.Publish(p) != nil {
				return
			}
			c.closeIdle()
			if c.write(frame{op: opReady, request: s.Epoch}) != nil {
				return
			}
		case opConnected, opUnavailable:
			if f.op == opConnected && (fd < 0 || f.lease == 0) || f.op == opUnavailable && (fd >= 0 || f.lease != 0) {
				if fd >= 0 {
					unix.Close(fd)
				}
				return
			}
			c.pendingMu.Lock()
			ch, id := c.pending, c.pendingID
			c.pendingMu.Unlock()
			if ch == nil || f.request != id {
				if fd >= 0 {
					unix.Close(fd)
				}
				return
			}
			select {
			case ch <- incoming{value: f, fd: fd}:
			case <-c.done:
				if fd >= 0 {
					unix.Close(fd)
				}
				return
			}
		default:
			if fd >= 0 {
				unix.Close(fd)
			}
			return
		}
	}
}
func (c *controlClient) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" || address != "tenant.local:80" {
		return nil, errors.New("fixed tenant upstream required")
	}
	c.dialMu.Lock()
	defer c.dialMu.Unlock()
	select {
	case <-c.done:
		return nil, errors.New("gateway broker closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	c.pendingMu.Lock()
	c.pendingID++
	id := c.pendingID
	ch := make(chan incoming, 1)
	c.pending = ch
	c.pendingMu.Unlock()
	defer func() { c.pendingMu.Lock(); c.pending = nil; c.pendingMu.Unlock() }()
	if id == 0 || c.write(frame{op: opConnect, request: id}) != nil {
		return nil, errors.New("gateway broker unavailable")
	}
	select {
	case msg := <-ch:
		if ctx.Err() != nil {
			if msg.fd >= 0 {
				unix.Close(msg.fd)
			}
			if msg.value.lease != 0 {
				_ = c.write(frame{op: opRelease, lease: msg.value.lease})
			}
			return nil, ctx.Err()
		}
		if msg.value.op != opConnected {
			return nil, errors.New("gateway connection capacity unavailable")
		}
		f := os.NewFile(uintptr(msg.fd), "tenant-api-connection")
		conn, e := net.FileConn(f)
		f.Close()
		if e != nil {
			_ = c.write(frame{op: opRelease, lease: msg.value.lease})
			return nil, e
		}
		return &leasedConn{Conn: conn, client: c, id: msg.value.lease}, nil
	case <-c.done:
		return nil, errors.New("gateway broker closed")
	case <-ctx.Done():
		// A caller cancellation is not a supervisor failure. Drain the one bounded
		// response and release its capability before another dial can reuse this
		// channel. No orphan-response goroutine or unbounded pending map is needed.
		select {
		case msg := <-ch:
			if msg.fd >= 0 {
				unix.Close(msg.fd)
			}
			if msg.value.lease != 0 {
				_ = c.write(frame{op: opRelease, lease: msg.value.lease})
			}
			return nil, ctx.Err()
		case <-c.done:
			return nil, errors.New("gateway broker closed")
		case <-time.After(3 * time.Second):
			c.fail()
			return nil, errors.New("gateway broker response deadline exceeded")
		}
	}
}

type leasedConn struct {
	net.Conn
	client *controlClient
	id     uint64
	once   sync.Once
}

func (c *leasedConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { _ = c.client.write(frame{op: opRelease, lease: c.id}) })
	return e
}
