//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: hold the exact ordinary daemon owner-directory fsync after a
// known victim unlink. This notification wait is NOT filesystem D-state.
import (
	"bytes"
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

	"github.com/123123213weqw/Xandbox/internal/client"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

func ownerNotifyProgram() ([]unix.SockFilter, error) {
	base, e := quotaNotifyProgram()
	if e != nil {
		return nil, e
	}
	p := append([]unix.SockFilter(nil), base[:6]...)
	return append(p, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_FSYNC), Jf: 1}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_USER_NOTIF}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW}), nil
}
func runOwnerDaemon() error {
	if e := requireQuotaChild(); e != nil {
		return e
	}
	if _, e := fixedCopyConfig(); e != nil {
		return e
	}
	var st unix.Stat_t
	if e := unix.Fstat(3, &st); e != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("fixed owner-fsync listener socket required")
	}
	if e := quotaNotifySizes(); e != nil {
		return e
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, unix.CAP_SYS_RESOURCE, 0); e != 0 {
		return e
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); e != 0 {
		return e
	}
	p, e := ownerNotifyProgram()
	if e != nil {
		return e
	}
	prog := unix.SockFprog{Len: uint16(len(p)), Filter: &p[0]}
	flags := unix.SECCOMP_FILTER_FLAG_NEW_LISTENER | unix.SECCOMP_FILTER_FLAG_TSYNC | unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH | unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, uintptr(flags), uintptr(unsafe.Pointer(&prog)))
	runtime.KeepAlive(p)
	runtime.KeepAlive(&prog)
	if errno != 0 {
		return errno
	}
	if e = unix.Sendmsg(3, []byte{1}, unix.UnixRights(int(fd)), nil, 0); e != nil {
		unix.Close(int(fd))
		return e
	}
	unix.Close(int(fd))
	unix.Close(3)
	return unix.Exec("/srv/assets/sandboxd", []string{"sandboxd", "-backend", "firecracker", "-state-dir", "/srv/state", "-auth-file", "/srv/config/auth.json", "-firecracker-config", "/srv/config/backend.json", "-max-instances", "2"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
}

func (n *node) startOwnerObserved(ctx context.Context) (*ownerObserver, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.quotaSnapshot || n.process == nil || n.quotaSwitch || n.mapper != nil {
		return nil, errors.New("idle fixed snapshot daemon required")
	}
	if _, e := fixedCopyConfig(); e != nil {
		return nil, e
	}
	if e := n.process.Process.Signal(os.Interrupt); e != nil {
		return nil, e
	}
	select {
	case e := <-n.exited:
		if e != nil {
			return nil, e
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	n.process = nil
	n.api.Close()
	n.api = client.NewWithToken("/srv/state/api.sock", n.token)
	pair, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	parent, child := os.NewFile(uintptr(pair[0]), "copy-parent"), os.NewFile(uintptr(pair[1]), "copy-child")
	defer parent.Close()
	defer child.Close()
	log, e := os.OpenFile("/srv/fixture/owner-controller.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, e
	}
	defer log.Close()
	cmd := exec.Command("/usr/bin/xandbox-host-fixture", "-mode", "quota-owner-daemon")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.ExtraFiles = []*os.File{child}
	cmd.Stdout, cmd.Stderr = log, log
	if e = cmd.Start(); e != nil {
		return nil, e
	}
	n.process = cmd
	n.exited = make(chan error, 1)
	go func() { n.exited <- cmd.Wait() }()
	child.Close()
	transfer, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	fd, e := receiveQuotaListener(transfer, int(parent.Fd()))
	if e != nil {
		cmd.Process.Kill()
		<-n.exited
		n.process = nil
		return nil, e
	}
	identity, e := processStart(cmd.Process.Pid)
	if e != nil {
		unix.Close(fd)
		cmd.Process.Kill()
		<-n.exited
		n.process = nil
		return nil, e
	}
	obs := &ownerObserver{fd: fd, pid: cmd.Process.Pid, identity: identity, held: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go obs.serve()
	if e = waitNode(ctx, func() (bool, error) {
		_, _, err := obs.snapshot()
		if err != nil {
			return false, err
		}
		var h struct {
			Backend    string `json:"backend"`
			Isolation  bool   `json:"isolation"`
			Production bool   `json:"production_ready"`
		}
		err = n.api.Do(ctx, "GET", "/healthz", nil, &h)
		return err == nil && h.Backend == "firecracker" && h.Isolation && !h.Production, nil
	}); e != nil {
		cmd.Process.Kill()
		<-n.exited
		n.process = nil
		obs.close()
		return nil, e
	}
	return obs, nil
}

type ownerObserver struct {
	mu         sync.Mutex
	once       sync.Once
	fd, pid    int
	identity   string
	victim     sandbox.Ref
	project    uint32
	armed      bool
	heldID     uint64
	continued  int
	err        error
	held       chan struct{}
	stop, done chan struct{}
}

func (o *ownerObserver) fail(e error) {
	o.mu.Lock()
	if o.err == nil {
		o.err = e
	}
	o.mu.Unlock()
}
func (o *ownerObserver) snapshot() (int, uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.continued, o.heldID, o.err
}
func (o *ownerObserver) arm(ref sandbox.Ref, project uint32) error {
	if !switchRefValid(ref) || project < driverProjectFirst || project >= driverProjectFirst+4 {
		return errors.New("fixed known owner target required")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.armed || o.heldID != 0 {
		return errors.New("owner target already armed")
	}
	o.victim = ref
	o.project = project
	o.armed = true
	return nil
}
func (o *ownerObserver) close() error {
	o.once.Do(func() { close(o.stop) })
	select {
	case <-o.done:
		_, _, e := o.snapshot()
		return e
	case <-time.After(2 * time.Second):
		return errors.New("owner observer did not stop")
	}
}
func (o *ownerObserver) checkHeld() error {
	if e := requireNode(); e != nil {
		return e
	}
	_, id, e := o.snapshot()
	if e != nil {
		return e
	}
	if id == 0 {
		return errors.New("owner fsync not held")
	}
	return quotaNotifyIO(o.fd, quotaNotifIDValid, unsafe.Pointer(&id))
}
func (o *ownerObserver) match(q quotaNotif) (bool, error) {
	if e := requireNode(); e != nil {
		return false, e
	}
	if q.ID == 0 || q.PID == 0 || q.Flags != 0 || q.Data.Arch != unix.AUDIT_ARCH_X86_64 || q.Data.NR != int32(unix.SYS_FSYNC) || q.Data.Args[0] > 4095 {
		return false, errors.New("unexpected fixed fsync notification")
	}
	if e := quotaNotifyIO(o.fd, quotaNotifIDValid, unsafe.Pointer(&q.ID)); e != nil {
		return false, e
	}
	identity, e := processStart(o.pid)
	if e != nil || identity != o.identity {
		return false, errors.New("owner daemon incarnation changed")
	}
	status, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", q.PID))
	if e != nil {
		return false, e
	}
	tgid := 0
	for _, line := range strings.Split(string(status), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "Tgid:" {
			tgid, e = strconv.Atoi(f[1])
			if e != nil {
				return false, e
			}
		}
	}
	if tgid != o.pid {
		return false, nil
	}
	exe, e := os.Stat(fmt.Sprintf("/proc/%d/exe", o.pid))
	if e != nil {
		return false, e
	}
	want, e := os.Stat("/srv/assets/sandboxd")
	if e != nil || !os.SameFile(exe, want) {
		return false, errors.New("owner fsync target ELF changed")
	}
	fdPath := fmt.Sprintf("/proc/%d/fd/%d", o.pid, q.Data.Args[0])
	target, e := os.Readlink(fdPath)
	if e != nil {
		return false, e
	}
	if target != "/srv/state/firecracker" {
		return false, nil
	}
	raw, e := os.Lstat(target)
	if e != nil {
		return false, e
	}
	via, e := os.Stat(fdPath)
	if e != nil || !raw.IsDir() || raw.Mode().Perm() != 0700 || raw.Mode()&os.ModeSymlink != 0 || !os.SameFile(raw, via) {
		return false, errors.New("owner directory descriptor identity changed")
	}
	st, ok := raw.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Gid != 0 {
		return false, errors.New("owner directory not private root")
	}
	// Earlier registry syncs are real CONTINUE, never mistaken for this window.
	if _, e = os.Lstat("/srv/state/firecracker/" + o.victim.ID + o.victim.Generation + ".json"); e == nil {
		return false, nil
	} else if !os.IsNotExist(e) {
		return false, e
	}
	if e = absentClearVictim(o.victim); e != nil {
		return false, e
	}
	qr, e := driverQuotaRead(o.project)
	if e != nil {
		return false, e
	}
	if !quotaEmpty(qr) {
		return false, errors.New("owner unlink occurred before full private quota clear")
	}
	if e = quotaNotifyIO(o.fd, quotaNotifIDValid, unsafe.Pointer(&q.ID)); e != nil {
		return false, e
	}
	return true, nil
}
func (o *ownerObserver) serve() {
	defer close(o.done)
	defer unix.Close(o.fd)
	var deadline time.Time
	for {
		select {
		case <-o.stop:
			return
		default:
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			o.fail(errors.New("owner cold cut missed fixed60s hold deadline"))
			return
		}
		p := []unix.PollFd{{Fd: int32(o.fd), Events: unix.POLLIN}}
		_, e := unix.Poll(p, 100)
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if e != nil {
			o.fail(e)
			return
		}
		if p[0].Revents&unix.POLLIN == 0 {
			if p[0].Revents&(unix.POLLHUP|unix.POLLERR) != 0 {
				return
			}
			continue
		}
		var q quotaNotif
		e = quotaNotifyIO(o.fd, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&q))
		if errors.Is(e, unix.EINTR) || errors.Is(e, unix.ENOENT) {
			continue
		}
		if e != nil {
			o.fail(e)
			return
		}
		o.mu.Lock()
		armed, total := o.armed, o.continued
		o.mu.Unlock()
		if total >= 8192 {
			o.fail(errors.New("owner notification bound exceeded"))
			return
		}
		if armed {
			matched, err := o.match(q)
			if errors.Is(err, unix.ENOENT) && errors.Is(quotaNotifyIO(o.fd, quotaNotifIDValid, unsafe.Pointer(&q.ID)), unix.ENOENT) {
				continue
			}
			if err != nil {
				o.fail(err)
				return
			}
			if matched {
				o.mu.Lock()
				o.heldID = q.ID
				o.armed = false
				o.mu.Unlock()
				deadline = time.Now().Add(60 * time.Second)
				o.held <- struct{}{}
				// Never reply to this target. Keep serving OTHER FSYNC notifications so
				// the fixture does not create a spurious global listener stall.
				continue
			}
		}
		reply := quotaNotifResponse{ID: q.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
		if e = quotaNotifyIO(o.fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&reply)); e != nil {
			if errors.Is(e, unix.ENOENT) {
				continue
			}
			o.fail(e)
			return
		}
		o.mu.Lock()
		o.continued++
		o.mu.Unlock()
	}
}

// Reads only; no catalog status, scanOwners or directory synchronization.
func ownerCutOwners(r copyCutReceipt) (bool, error) {
	if e := requireNode(); e != nil {
		return false, e
	}
	b, e := privatefile.Read("/srv/state/firecracker/catalog/index.json", 256<<10)
	if e != nil {
		return false, e
	}
	if e = validateCopyCutIndex(b, r); e != nil {
		return false, e
	}
	entries, e := os.ReadDir("/srv/state/firecracker")
	if e != nil {
		return false, e
	}
	keeper, victim := false, false
	for _, d := range entries {
		if d.Name() == "catalog" || d.Name() == "config.json" {
			continue
		}
		if !d.Type().IsRegular() || len(d.Name()) != 69 || !hashPattern.MatchString(strings.TrimSuffix(d.Name(), ".json")) {
			return false, errors.New("unknown owner-cut registry entry")
		}
		ref, want := r.Keeper, r.KeeperOwner
		if d.Name() == r.Victim.ID+r.Victim.Generation+".json" {
			ref, want = r.Victim, r.VictimOwner
			victim = true
		} else if d.Name() == r.Keeper.ID+r.Keeper.Generation+".json" {
			keeper = true
		} else {
			return false, errors.New("unknown extra owner-cut owner")
		}
		actual, e := clearOwnerBytes(ref)
		if e != nil || !bytes.Equal(actual, want) {
			return false, errors.New("exact owner-cut bytes changed")
		}
	}
	if !keeper {
		return false, errors.New("owner-cut keeper pin lost")
	}
	return victim, nil
}
