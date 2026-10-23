//go:build linux && xandbox_host_fixture

package main

// TEST ONLY. Inject errno at a fixed ordinary daemon's quotactl_fd boundary.
// This is neither a security policy nor physical media fault injection. All
// successful calls CONTINUE into the real kernel; no syscall is emulated.
import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

// Linux v6.8 include/uapi/linux/seccomp.h. Reject unexpected kernel sizes.
type quotaNotifData struct {
	NR   int32
	Arch uint32
	IP   uint64
	Args [6]uint64
}
type quotaNotif struct {
	ID         uint64
	PID, Flags uint32
	Data       quotaNotifData
}
type quotaNotifResponse struct {
	ID    uint64
	Value int64
	Error int32
	Flags uint32
}
type quotaNotifSizes struct{ Notification, Response, Data uint16 }

const quotaNotifIDValid = 0x40082102 // _IOW('!', 2, __u64)

const quotaBarrierCase = "reserve-barrier-hang"

var quotaSyscallCases = [...]string{"reserve-set-eio", "reserve-read-erofs", "reserve-sync-eio", "clear-set-eio", "clear-sync-erofs", "clear-read-eio"}

func quotaSyscallBase(name string) (string, error) {
	if name == quotaBarrierCase {
		return "/srv/sq/" + name, nil
	}
	for _, allowed := range quotaSyscallCases {
		if name == allowed {
			return "/srv/sq/" + name, nil
		}
	}
	return "", errors.New("fixed quota syscall case required")
}
func quotaSyscallRuntime(name string) (string, error) {
	if name == quotaBarrierCase {
		return "/srv/sr/6", nil
	}
	for i, allowed := range quotaSyscallCases {
		if name == allowed {
			return "/srv/sr/" + strconv.Itoa(i), nil
		}
	}
	return "", errors.New("fixed quota syscall runtime required")
}
func quotaNotifyProgram() ([]unix.SockFilter, error) { return quotaNotifyProgramOn(false) }
func quotaNotifyProgramOn(barrier bool) ([]unix.SockFilter, error) {
	if runtime.GOARCH != "amd64" {
		return nil, errors.New("fixed x86_64 L1 observer required")
	}
	p := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.AUDIT_ARCH_X86_64, Jt: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, K: 0x40000000, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_QUOTACTL_FD), Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_USER_NOTIF},
	}
	if barrier {
		p = append(p, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_SYNCFS), Jf: 1}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_USER_NOTIF})
	}
	return append(p, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW}), nil
}
func quotaNotifySizes() error {
	var sizes quotaNotifSizes
	_, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_GET_NOTIF_SIZES, 0, uintptr(unsafe.Pointer(&sizes)))
	runtime.KeepAlive(&sizes)
	if e != 0 {
		return e
	}
	if uintptr(sizes.Notification) != unsafe.Sizeof(quotaNotif{}) || uintptr(sizes.Response) != unsafe.Sizeof(quotaNotifResponse{}) || uintptr(sizes.Data) != unsafe.Sizeof(quotaNotifData{}) {
		return errors.New("unexpected kernel notification UAPI sizes")
	}
	return nil
}
func runQuotaSyscallDaemon(name string) error {
	if e := requireQuotaChild(); e != nil {
		return e
	}
	base, e := quotaSyscallBase(name)
	if e != nil {
		return e
	}
	var socket unix.Stat_t
	if e = unix.Fstat(3, &socket); e != nil || socket.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("fixed listener transfer socket required")
	}
	if e = quotaNotifySizes(); e != nil {
		return e
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, unix.CAP_SYS_RESOURCE, 0); e != 0 {
		return e
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); e != 0 {
		return e
	}
	p, e := quotaNotifyProgramOn(name == quotaBarrierCase)
	if e != nil {
		return e
	}
	program := unix.SockFprog{Len: uint16(len(p)), Filter: &p[0]}
	// TSYNC+NEW_LISTENER needs TSYNC_ESRCH to disambiguate failure from an FD.
	// No per-thread or unfiltered fallback if synchronization is unsupported.
	flags := unix.SECCOMP_FILTER_FLAG_NEW_LISTENER | unix.SECCOMP_FILTER_FLAG_TSYNC | unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH | unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, uintptr(flags), uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(p)
	runtime.KeepAlive(&program)
	if errno != 0 {
		return errno
	}
	if e = unix.Sendmsg(3, []byte{1}, unix.UnixRights(int(fd)), nil, 0); e != nil {
		unix.Close(int(fd))
		return e
	}
	unix.Close(int(fd))
	unix.Close(3)
	return unix.Exec("/srv/assets/sandboxd", []string{"sandboxd", "-backend", "firecracker", "-state-dir", base + "/s", "-auth-file", "/srv/config/auth.json", "-firecracker-config", base + "/backend.json", "-max-instances", "1"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
}

type quotaNotifyState struct {
	name                                      string
	armed, seenSet                            bool
	continued, injected                       int
	err                                       error
	ref                                       sandbox.Ref
	owner                                     []byte
	baselineSaved, seenSync, barrierContinued bool
	barrierTID                                uint32
	barrierFD                                 uint64
}

// No tracee pointer is dereferenced. A subsequent syscall plus independent
// kernel readback establish the preceding SET's state, not SEND alone.
func (s *quotaNotifyState) wants(command uint64) bool {
	if !s.armed {
		return false
	}
	switch s.name {
	case "reserve-set-eio", "clear-set-eio":
		return command == 0x80000802
	case "reserve-read-erofs", "clear-read-eio":
		return s.seenSet && command == 0x80000702
	case "reserve-sync-eio", "clear-sync-erofs":
		return s.seenSet && command == 0x80000102
	}
	return false
}
func (s *quotaNotifyState) response(id uint64, inject bool) quotaNotifResponse {
	r := quotaNotifResponse{ID: id, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
	if inject {
		r.Flags = 0
		r.Error = -int32(unix.EIO)
		if strings.HasSuffix(s.name, "-erofs") {
			r.Error = -int32(unix.EROFS)
		}
	}
	return r
}

type quotaNotifier struct {
	mu                          sync.Mutex
	state                       quotaNotifyState
	fd, pid                     int
	identity, base, runtimeRoot string
	stop                        chan struct{}
	done                        chan struct{}
	mapper                      *stateMapper
	barrier                     *quotaBarrierPlan
}

func quotaNotifyIO(fd int, request uint, p unsafe.Pointer) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), uintptr(p))
	runtime.KeepAlive(p)
	if e != 0 {
		return e
	}
	return nil
}
func (o *quotaNotifier) inspect(q quotaNotif) error {
	if e := requireNode(); e != nil {
		return e
	}
	isBarrier := o.state.name == quotaBarrierCase && q.Data.NR == int32(unix.SYS_SYNCFS)
	if q.ID == 0 || q.PID == 0 || q.Flags != 0 || q.Data.Arch != unix.AUDIT_ARCH_X86_64 || (!isBarrier && q.Data.NR != int32(unix.SYS_QUOTACTL_FD)) || q.Data.Args[0] > 511 {
		return errors.New("unexpected fixed notification")
	}
	if !isBarrier && (q.Data.Args[4] != 0 || q.Data.Args[5] != 0) {
		return errors.New("unexpected extra quota arguments")
	}
	if !isBarrier {
		cmd, id := q.Data.Args[1], q.Data.Args[2]
		if (cmd == 0x80000102) != (q.Data.Args[3] == 0) {
			return errors.New("unexpected quota value pointer role")
		}
		switch cmd {
		case 0x80000102, 0x80000402:
			if id != 0 {
				return errors.New("unexpected global quota selector")
			}
		case 0x80000702, 0x80000802:
			if id < uint64(quotaFirst) || id >= uint64(quotaFirst+3) {
				return errors.New("unexpected project selector")
			}
		default:
			return errors.New("unexpected quota command")
		}
	}
	start, e := processStart(o.pid)
	if e != nil || start != o.identity {
		return errors.New("owned notifier daemon identity changed")
	}
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", q.PID))
	if e != nil {
		return e
	}
	want := "Tgid:\t" + strconv.Itoa(o.pid)
	found := false
	for _, line := range strings.Split(string(b), "\n") {
		if line == want {
			found = true
		}
	}
	if !found {
		return errors.New("notification not from our direct daemon thread group")
	}
	root, e := os.Stat(o.runtimeRoot)
	if e != nil {
		return e
	}
	anchor, e := os.Stat(fmt.Sprintf("/proc/%d/fd/%d", o.pid, q.Data.Args[0]))
	if e != nil {
		return e
	}
	if !root.IsDir() || !os.SameFile(root, anchor) {
		return errors.New("notification anchor does not match fixed owned runtime")
	}
	end, e := processStart(o.pid)
	if e != nil || end != o.identity {
		return errors.New("daemon identity changed during observation")
	}
	return quotaNotifyIO(o.fd, quotaNotifIDValid, unsafe.Pointer(&q.ID))
}
func (o *quotaNotifier) serve() {
	defer close(o.done)
	defer unix.Close(o.fd)
	for {
		select {
		case <-o.stop:
			return
		default:
		}
		poll := []unix.PollFd{{Fd: int32(o.fd), Events: unix.POLLIN}}
		_, e := unix.Poll(poll, 100)
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if e != nil {
			o.fail(e)
			return
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			if poll[0].Revents&(unix.POLLHUP|unix.POLLERR) != 0 {
				return
			}
			continue
		}
		var q quotaNotif
		if e = quotaNotifyIO(o.fd, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&q)); errors.Is(e, unix.EINTR) || errors.Is(e, unix.ENOENT) {
			continue
		}
		if e != nil {
			o.fail(e)
			return
		}
		if e = o.inspect(q); errors.Is(e, unix.ENOENT) {
			continue
		}
		if e != nil {
			o.fail(e)
			return
		}
		o.mu.Lock()
		if o.state.continued+o.state.injected >= 4096 {
			o.state.err = errors.New("fixed syscall notification bound exceeded")
			o.mu.Unlock()
			return
		}
		barrierTarget := o.state.name == quotaBarrierCase && o.state.armed && q.Data.NR == int32(unix.SYS_SYNCFS)
		if o.state.name == quotaBarrierCase && o.state.armed {
			e = o.prepareBarrier(q)
		}
		inject := o.state.name != quotaBarrierCase && o.state.wants(q.Data.Args[1])
		if inject {
			e = o.boundary(q)
		}
		if e != nil {
			o.state.err = e
			o.mu.Unlock()
			return
		}
		r := o.state.response(q.ID, inject)
		e = quotaNotifyIO(o.fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&r))
		if e == nil {
			if barrierTarget {
				o.state.barrierContinued = true
				o.state.barrierTID = q.PID
				o.state.barrierFD = q.Data.Args[0]
				o.state.armed = false
			}
			if inject {
				o.state.injected++
				if strings.HasPrefix(o.state.name, "reserve-") {
					o.state.armed = false
				}
			} else {
				o.state.continued++
			}
			if q.Data.NR == int32(unix.SYS_QUOTACTL_FD) && q.Data.Args[1] == 0x80000102 {
				o.state.seenSync = true
			}
			if q.Data.NR == int32(unix.SYS_QUOTACTL_FD) && q.Data.Args[1] == 0x80000802 {
				o.state.seenSet = true
			}
		} else if !errors.Is(e, unix.ENOENT) {
			o.state.err = e
		}
		o.mu.Unlock()
		if e != nil && !errors.Is(e, unix.ENOENT) {
			return
		}
	}
}
func (o *quotaNotifier) fail(e error) { o.mu.Lock(); o.state.err = e; o.mu.Unlock() }
func (o *quotaNotifier) arm() {
	o.mu.Lock()
	o.state.armed = true
	o.state.seenSet = false
	o.mu.Unlock()
}
func (o *quotaNotifier) disarm()                    { o.mu.Lock(); o.state.armed = false; o.mu.Unlock() }
func (o *quotaNotifier) snapshot() quotaNotifyState { o.mu.Lock(); defer o.mu.Unlock(); return o.state }
func (o *quotaNotifier) close() error {
	close(o.stop)
	select {
	case <-o.done:
		return o.snapshot().err
	case <-time.After(2 * time.Second):
		return errors.New("notifier did not stop; retain owned scope")
	}
}
func receiveQuotaListener(ctx context.Context, socket int) (int, error) {
	for {
		if e := ctx.Err(); e != nil {
			return -1, e
		}
		poll := []unix.PollFd{{Fd: int32(socket), Events: unix.POLLIN}}
		if _, e := unix.Poll(poll, 100); e != nil && !errors.Is(e, unix.EINTR) {
			return -1, e
		}
		if poll[0].Revents&(unix.POLLHUP|unix.POLLERR) != 0 && poll[0].Revents&unix.POLLIN == 0 {
			return -1, errors.New("listener transfer child exited")
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			continue
		}
		data, control := make([]byte, 2), make([]byte, unix.CmsgSpace(4)*4)
		n, on, flags, _, e := unix.Recvmsg(socket, data, control, unix.MSG_CMSG_CLOEXEC)
		if e != nil {
			return -1, e
		}
		messages, e := unix.ParseSocketControlMessage(control[:on])
		if e != nil {
			return -1, e
		}
		fds := []int{}
		for _, m := range messages {
			rights, e := unix.ParseUnixRights(&m)
			if e != nil {
				for _, fd := range fds {
					unix.Close(fd)
				}
				return -1, e
			}
			fds = append(fds, rights...)
		}
		if n != 1 || data[0] != 1 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || len(fds) != 1 {
			for _, fd := range fds {
				unix.Close(fd)
			}
			return -1, errors.New("invalid bounded listener transfer")
		}
		return fds[0], nil
	}
}
func startQuotaNotified(ctx context.Context, name, runtimeRoot string) (*negativeDaemon, *quotaNotifier, error) {
	return startQuotaNotifiedOn(ctx, name, runtimeRoot, nil, nil)
}
func startQuotaNotifiedOn(ctx context.Context, name, runtimeRoot string, mapper *stateMapper, barrier *quotaBarrierPlan) (*negativeDaemon, *quotaNotifier, error) {
	if e := requireNode(); e != nil {
		return nil, nil, e
	}
	base, e := quotaSyscallBase(name)
	if e != nil {
		return nil, nil, e
	}
	want, e := quotaSyscallRuntime(name)
	if e != nil || runtimeRoot != want {
		return nil, nil, errors.New("fixed observed runtime required")
	}
	if (name == quotaBarrierCase) != (mapper != nil && barrier != nil) {
		return nil, nil, errors.New("fixed mapped barrier plan required")
	}
	if e = quotaNotifySizes(); e != nil {
		return nil, nil, e
	}
	sockets, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return nil, nil, e
	}
	parent, child := os.NewFile(uintptr(sockets[0]), "quota-listener-parent"), os.NewFile(uintptr(sockets[1]), "quota-listener-child")
	defer parent.Close()
	defer child.Close()
	log, e := os.OpenFile(base+"/first.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, nil, e
	}
	defer log.Close()
	c := exec.CommandContext(ctx, "/usr/bin/xandbox-host-fixture", "-mode", "quota-syscall-"+name)
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	c.Stdout, c.Stderr = log, log
	c.ExtraFiles = []*os.File{child}
	if e = c.Start(); e != nil {
		return nil, nil, e
	}
	child.Close()
	p := &negativeDaemon{cmd: c, done: make(chan struct{})}
	go func() { p.waitErr = c.Wait(); close(p.done) }()
	transfer, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	fd, e := receiveQuotaListener(transfer, int(parent.Fd()))
	if e != nil {
		c.Process.Kill()
		<-p.done
		return nil, nil, e
	}
	identity, e := processStart(c.Process.Pid)
	if e != nil {
		unix.Close(fd)
		c.Process.Kill()
		<-p.done
		return nil, nil, e
	}
	o := &quotaNotifier{mapper: mapper, barrier: barrier, state: quotaNotifyState{name: name}, fd: fd, pid: c.Process.Pid, identity: identity, base: base, runtimeRoot: runtimeRoot, stop: make(chan struct{}), done: make(chan struct{})}
	go o.serve()
	return p, o, nil
}
