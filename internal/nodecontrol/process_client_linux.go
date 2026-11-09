//go:build linux

package nodecontrol

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type processLease struct {
	mu   sync.RWMutex
	file *os.File // The lock prevents close/FD reuse racing an alive/peer check.
}

func (p *processLease) alive() error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.aliveLocked()
}
func (p *processLease) aliveLocked() error {
	if p.file == nil {
		return ErrProcessPin
	}
	return pollLiveProcess(int32(p.file.Fd()), unix.Poll)
}

// Go/runtime or ordinary signals may interrupt even this nonblocking probe.
// EINTR is NOT death and never means success: retry the actual kernel probe
// with the same leased FD. The finite budget prevents a signal storm spinning
// indefinitely; exhaustion remains an error/uncertain RPC outcome. Production
// always supplies unix.Poll; the unexported seam permits deterministic tests.
func pollLiveProcess(fd int32, poll func([]unix.PollFd, int) (int, error)) error {
	for attempts := 0; attempts < 4; attempts++ {
		fds := []unix.PollFd{{Fd: fd, Events: unix.POLLIN}}
		n, e := poll(fds, 0)
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if e != nil {
			return fmt.Errorf("operator pidfd poll: %w", e)
		}
		if n != 0 {
			return ErrProcessPin
		}
		return nil
	}
	return fmt.Errorf("operator pidfd poll interrupted repeatedly: %w", unix.EINTR)
}
func (p *processLease) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.file != nil {
		p.file.Close()
		p.file = nil
	}
}
func (p *processLease) peer(c *net.UnixConn, pid int) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if e := p.aliveLocked(); e != nil {
		return e
	}
	r, e := c.SyscallConn()
	if e != nil {
		return e
	}
	var cred *unix.Ucred
	var cause error
	if e = r.Control(func(fd uintptr) { cred, cause = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); e != nil {
		return e
	}
	if cause != nil {
		return cause
	}
	if cred == nil || int(cred.Pid) != pid || !authorizedUID(cred.Uid) {
		return ErrProcessPin
	}
	return p.aliveLocked()
}
func processRead(path string, max int64) ([]byte, error) {
	in, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer in.Close()
	b, e := io.ReadAll(io.LimitReader(in, max+1))
	if e != nil {
		return nil, e
	}
	if len(b) == 0 || int64(len(b)) > max {
		return nil, ErrProcessPin
	}
	return b, nil
}
func processStart(raw []byte, pid int) (uint64, error) {
	if !bytes.HasPrefix(raw, []byte(strconv.Itoa(pid)+" (")) {
		return 0, ErrProcessPin
	}
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 || end+2 >= len(raw) || raw[end+1] != ' ' {
		return 0, ErrProcessPin
	}
	fields := strings.Fields(string(raw[end+2:]))
	if len(fields) < 20 {
		return 0, ErrProcessPin
	}
	n, e := strconv.ParseUint(fields[19], 10, 64)
	if e != nil || n == 0 || strconv.FormatUint(n, 10) != fields[19] {
		return 0, ErrProcessPin
	}
	return n, nil
}

// NewPinnedClient opens pidfd BEFORE reading any incarnation metadata. It
// neither signals the process nor executes a program or creates a state root.
// PID/executable/placement ownership must also be proved by the lifecycle caller.
func NewPinnedClient(stateDir string, pid int) (*PinnedClient, error) {
	if pid <= 1 {
		return nil, ErrProcessPin
	}
	fd, e := unix.PidfdOpen(pid, 0)
	if e != nil {
		return nil, e
	}
	lease := &processLease{file: os.NewFile(uintptr(fd), "operator-pidfd")}
	ok := false
	defer func() {
		if !ok {
			lease.close()
		}
	}()
	if e = lease.alive(); e != nil {
		return nil, e
	}
	boot, e := processRead("/proc/sys/kernel/random/boot_id", 64)
	if e != nil {
		return nil, e
	}
	raw, e := processRead("/proc/"+strconv.Itoa(pid)+"/stat", 8192)
	if e != nil {
		return nil, e
	}
	ticks, e := processStart(raw, pid)
	if e != nil {
		return nil, e
	}
	id := ProcessIdentity{PID: pid, BootID: strings.TrimSpace(string(boot)), StartTicks: ticks}
	if !id.Valid() {
		return nil, ErrProcessPin
	}
	if e = lease.alive(); e != nil {
		return nil, e
	}
	client, e := newClient(stateDir, func(conn *net.UnixConn) error { return lease.peer(conn, pid) })
	if e != nil {
		return nil, e
	}
	client.live = lease.alive
	ok = true
	return &PinnedClient{client: client, id: id, release: lease.close}, nil
}
