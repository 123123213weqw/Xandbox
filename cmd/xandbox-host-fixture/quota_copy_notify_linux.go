//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: one fixed partial workspace WRITE error in our owned L1. Never
// read tracee buffers, emulate successful writes, or expose a generic injector.
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

	"github.com/123123213weqw/Xandbox/internal/client"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const copyPrefix = 16 << 20
const copyChunk = 128 << 10

func copyNotifyProgram() ([]unix.SockFilter, error) {
	base, e := quotaNotifyProgram()
	if e != nil {
		return nil, e
	}
	// Preserve the exact architecture/x32 guards, not the quota syscall target.
	p := append([]unix.SockFilter(nil), base[:6]...)
	p = append(p,
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_WRITE), Jf: 5},
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 32},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: copyChunk, Jf: 3},
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 36},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 0, Jf: 1},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_USER_NOTIF},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	return p, nil
}
func fixedCopyConfig() (firecracker.Config, error) {
	var c firecracker.Config
	b, e := privatefile.Read("/srv/config/backend.json", 8192)
	if e != nil {
		return c, e
	}
	if e = strictjson.Decode(b, &c); e != nil {
		return c, e
	}
	if c.Version != 2 || c.RuntimeRoot != "/srv/r" || c.CgroupRoot != nodeGroup || c.UIDStart != 400000 || c.UIDCount != 4 || !c.ReservedUIDRange || c.Quota == nil || c.Quota.ProjectStart != driverProjectFirst || c.Quota.MaxBytes != 192<<20 || c.Quota.MaxInodes != 128 || c.Snapshot == nil || c.Snapshot.MemoryMiB != 512 || c.Snapshot.VCPUs != 2 || c.Snapshot.MaxEntries != 4 || c.Snapshot.MaxBytes != 2<<30 {
		return c, errors.New("fixed partial-copy snapshot policy required")
	}
	return c, nil
}
func runCopyDaemon() error {
	if e := requireQuotaChild(); e != nil {
		return e
	}
	if _, e := fixedCopyConfig(); e != nil {
		return e
	}
	var st unix.Stat_t
	if e := unix.Fstat(3, &st); e != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("fixed copy listener socket required")
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
	p, e := copyNotifyProgram()
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
	return unix.Exec("/srv/assets/sandboxd", []string{"sandboxd", "-backend", "firecracker", "-state-dir", "/srv/state", "-auth-file", "/srv/config/auth.json", "-firecracker-config", "/srv/config/backend.json", "-max-instances", "2", "-metrics"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
}

type copyBoundary struct {
	Ref                     sandbox.Ref
	Owner                   []byte
	Project                 uint32
	Space, Inodes           uint64
	NamedSpace, NamedInodes uint64
	Size                    int64
}
type copyObserver struct {
	mu                  sync.Mutex
	once                sync.Once
	armed               bool
	cut                 bool
	injected, continued int
	err                 error
	fd, pid             int
	identity            string
	held                chan copyBoundary
	release, stop, done chan struct{}
}

func copyWriteRef(target string) (sandbox.Ref, bool) {
	var ref sandbox.Ref
	const prefix = "/srv/r/j/firecracker/"
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, "/root/workspace.ext4") {
		return ref, false
	}
	key := strings.TrimSuffix(strings.TrimPrefix(target, prefix), "/root/workspace.ext4")
	if len(key) != 64 || strings.Trim(key, "0123456789abcdef") != "" {
		return ref, false
	}
	ref = sandbox.Ref{ID: key[:32], Generation: key[32:]}
	return ref, true
}
func (o *copyObserver) fail(e error) {
	o.mu.Lock()
	if o.err == nil {
		o.err = e
	}
	o.mu.Unlock()
}
func (o *copyObserver) snapshot() (int, int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.injected, o.continued, o.err
}
func (o *copyObserver) arm() { o.mu.Lock(); o.armed = true; o.mu.Unlock() }
func (o *copyObserver) close() error {
	o.once.Do(func() { close(o.stop) })
	select {
	case <-o.done:
		_, _, e := o.snapshot()
		return e
	case <-time.After(2 * time.Second):
		return errors.New("copy observer did not stop")
	}
}
func (o *copyObserver) match(q quotaNotif) (copyBoundary, bool, error) {
	return o.matchScope(q, false)
}
func (o *copyObserver) matchNode(q quotaNotif) (copyBoundary, bool, error) {
	if e := requireNode(); e != nil {
		return copyBoundary{}, false, e
	}
	if _, e := fixedNodeSnapshotConfig(); e != nil {
		return copyBoundary{}, false, e
	}
	return o.matchScope(q, true)
}
func (o *copyObserver) matchScope(q quotaNotif, nodeScope bool) (copyBoundary, bool, error) {
	var b copyBoundary
	if e := requireNode(); e != nil {
		return b, false, e
	}
	if q.ID == 0 || q.PID == 0 || q.Flags != 0 || q.Data.Arch != unix.AUDIT_ARCH_X86_64 || q.Data.NR != int32(unix.SYS_WRITE) || q.Data.Args[0] > 4095 || q.Data.Args[2] != copyChunk {
		return b, false, errors.New("unexpected bounded copy notification")
	}
	if e := quotaNotifyIO(o.fd, quotaNotifIDValid, unsafe.Pointer(&q.ID)); e != nil {
		return b, false, e
	}
	identity, e := processStart(o.pid)
	if e != nil || identity != o.identity {
		return b, false, errors.New("copy daemon incarnation changed")
	}
	status, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", q.PID))
	if e != nil {
		return b, false, e
	}
	// The filter is inherited; other descendants are never copy targets.
	if !strings.Contains("\n"+string(status), "\nTgid:\t"+strconv.Itoa(o.pid)+"\n") {
		return b, false, nil
	}
	target, e := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", o.pid, q.Data.Args[0]))
	if e != nil {
		return b, false, e
	}
	ref, ok := copyWriteRef(target)
	if !ok {
		return b, false, nil
	}
	fdinfo, e := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", o.pid, q.Data.Args[0]))
	if e != nil {
		return b, false, e
	}
	pos, flags, gotPos, gotFlags := int64(0), uint64(0), false, false
	for _, line := range strings.Split(string(fdinfo), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		if f[0] == "pos:" {
			pos, e = strconv.ParseInt(f[1], 10, 64)
			gotPos = e == nil
		}
		if f[0] == "flags:" {
			flags, e = strconv.ParseUint(f[1], 8, 64)
			gotFlags = e == nil
		}
	}
	if !gotPos || !gotFlags || flags&unix.O_ACCMODE != unix.O_WRONLY {
		return b, false, errors.New("fixed workspace write offset/access unavailable")
	}
	if pos < copyPrefix {
		return b, false, nil
	}
	if pos != copyPrefix {
		return b, false, errors.New("fixed partial-copy write boundary missed")
	}
	owner, e := clearOwnerBytes(ref)
	if e != nil {
		return b, false, e
	}
	var own clearWindowOwner
	if e = strictjson.Decode(owner, &own); e != nil {
		return b, false, e
	}
	if own.Ref != ref || own.Version != 4 || !own.QuotaAttempted || own.InitializationAttempted || own.UID < 400000 || own.UID >= 400004 || own.ProjectID != driverProjectFirst+uint32(own.UID-400000) || !hashPattern.MatchString(own.TemplateID) {
		return b, false, errors.New("partial-copy attempted owner invalid")
	}
	root := "/srv/r/j/firecracker/" + ref.ID + ref.Generation
	var raw unix.Stat_t
	if e = unix.Lstat(target, &raw); e != nil || raw.Mode != unix.S_IFREG|0600 || raw.Nlink != 1 || raw.Uid != 0 || raw.Gid != 0 {
		return b, false, errors.New("partial workspace raw inode identity invalid")
	}
	exe, e := os.Stat(fmt.Sprintf("/proc/%d/exe", o.pid))
	if e != nil {
		return b, false, e
	}
	wantExe, e := os.Stat("/srv/assets/sandboxd")
	if e != nil || !os.SameFile(exe, wantExe) {
		return b, false, errors.New("copy target is not unchanged sandboxd ELF")
	}
	st, e := os.Stat(target)
	if e != nil || !st.Mode().IsRegular() || st.Size() != copyPrefix || st.Mode().Perm() != 0600 {
		return b, false, errors.New("actual partial workspace size/mode mismatch")
	}
	via, e := os.Stat(fmt.Sprintf("/proc/%d/fd/%d", o.pid, q.Data.Args[0]))
	if e != nil || !os.SameFile(st, via) {
		return b, false, errors.New("partial workspace descriptor identity mismatch")
	}
	for _, p := range []string{root, root + "/root", target} {
		a, e := quotaAttributes(p, nil)
		if e != nil || a.Project != own.ProjectID {
			return b, false, errors.New("partial-copy project inheritance mismatch")
		}
		if p != target && a.XFlags&quotaInherit == 0 {
			return b, false, errors.New("partial-copy inheritance absent")
		}
	}
	for _, name := range []string{"template.mem", "template.state", "firecracker.pid", "firecracker"} {
		if _, e = os.Lstat(root + "/root/" + name); !os.IsNotExist(e) {
			return b, false, errors.New("copy boundary already reached link or execution stage")
		}
	}
	groupRoot := nodeGroup
	var empty bool
	if nodeScope {
		groupRoot = nodeBudgetInstances
		empty, e = nodePrepareGroupEmpty(ref)
	} else {
		empty, e = switchDomainEmpty(ref)
	}
	if e != nil || !empty {
		return b, false, errors.New("partial-copy boundary has running execution")
	}
	procs, e := os.ReadFile(groupRoot + "/" + ref.ID + ref.Generation + "/cgroup.procs")
	if e != nil || strings.TrimSpace(string(procs)) != "" {
		return b, false, errors.New("partial-copy cgroup not present and empty")
	}
	qfs, e := openQuotaFS(false)
	if e != nil {
		return b, false, e
	}
	defer qfs.file.Close()
	// Healthy TEST checkpoint only: make this actual prefix/accounting stable
	// before injecting the next write. This is not a commit latency measurement.
	if !o.cut {
		if e = qfs.sync(); e != nil {
			return b, false, e
		}
		if e = unix.Syncfs(int(qfs.file.Fd())); e != nil {
			return b, false, e
		}
	}
	qr, e := driverQuotaRead(own.ProjectID)
	if e != nil {
		return b, false, e
	}
	blocks, inodes, entries, e := driverQuotaTree(root, true)
	if e != nil {
		return b, false, e
	}
	if !o.cut {
		if e = copyPartialAccounting(qr, blocks, inodes, entries); e != nil {
			return b, false, e
		}
	} else {
		if qr.BHard != 192<<10 || qr.IHard != 128 || qr.BSoft|qr.ISoft|qr.BTime|qr.ITime != 0 || qr.Space > 192<<20 || qr.Inodes != 3 || len(entries) != 3 || entries["root/workspace.ext4"].Size != copyPrefix {
			return b, false, errors.New("live unsynced partial policy/namespace mismatch")
		}
	}
	identity, e = processStart(o.pid)
	if e != nil || identity != o.identity {
		return b, false, errors.New("copy daemon changed at boundary")
	}
	if e = quotaNotifyIO(o.fd, quotaNotifIDValid, unsafe.Pointer(&q.ID)); e != nil {
		return b, false, e
	}
	return copyBoundary{Ref: ref, Owner: owner, Project: own.ProjectID, Space: qr.Space, Inodes: qr.Inodes, Size: st.Size(), NamedSpace: blocks, NamedInodes: inodes}, true, nil
}
func (o *copyObserver) serve() {
	defer close(o.done)
	defer unix.Close(o.fd)
	for {
		select {
		case <-o.stop:
			return
		default:
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
		armed := o.armed
		total := o.continued + o.injected
		o.mu.Unlock()
		if total >= 8192 {
			o.fail(errors.New("fixed copy notification bound exceeded"))
			return
		}
		r := quotaNotifResponse{ID: q.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
		if armed {
			b, match, err := o.match(q)
			if errors.Is(err, unix.ENOENT) && errors.Is(quotaNotifyIO(o.fd, quotaNotifIDValid, unsafe.Pointer(&q.ID)), unix.ENOENT) {
				continue
			}
			if err != nil {
				o.fail(err)
				return
			}
			if match {
				o.mu.Lock()
				o.armed = false
				o.mu.Unlock()
				o.held <- b
				if o.cut {
					timer := time.NewTimer(60 * time.Second)
					select {
					case <-o.stop:
						timer.Stop()
						return
					case <-timer.C:
						o.fail(errors.New("copy cut did not arrive before fixed hold deadline"))
						return
					}
				}
				timer := time.NewTimer(30 * time.Second)
				select {
				case <-o.release:
					timer.Stop()
				case <-o.stop:
					timer.Stop()
					return
				case <-timer.C:
					o.fail(errors.New("fixed partial-copy observation deadline"))
					return
				}
				if err = quotaNotifyIO(o.fd, quotaNotifIDValid, unsafe.Pointer(&q.ID)); err != nil {
					o.fail(err)
					return
				}
				r.Flags = 0
				r.Error = -int32(unix.EIO)
			}
		}
		if e = quotaNotifyIO(o.fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&r)); e != nil {
			if errors.Is(e, unix.ENOENT) {
				continue
			}
			o.fail(e)
			return
		}
		o.mu.Lock()
		if r.Error != 0 {
			o.injected++
		} else {
			o.continued++
		}
		o.mu.Unlock()
	}
}
func (n *node) startCopyObserved(ctx context.Context) (*copyObserver, error) {
	return n.startCopyObservedOn(ctx, false)
}
func (n *node) startCopyObservedOn(ctx context.Context, cut bool) (*copyObserver, error) {
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
	log, e := os.OpenFile("/srv/fixture/copy-controller.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, e
	}
	defer log.Close()
	cmd := exec.Command("/usr/bin/xandbox-host-fixture", "-mode", "quota-copy-daemon")
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
	obs := &copyObserver{cut: cut, fd: fd, pid: cmd.Process.Pid, identity: identity, held: make(chan copyBoundary, 1), release: make(chan struct{}), stop: make(chan struct{}), done: make(chan struct{})}
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

func copyPartialAccounting(q quotaRecord, blocks, inodes uint64, entries map[string]driverQuotaEntry) error {
	if len(entries) != 3 || q.BHard != 192<<10 || q.IHard != 128 || q.BSoft|q.ISoft|q.BTime|q.ITime != 0 || q.Space != blocks || q.Inodes != inodes || q.Space < copyPrefix || q.Space >= 128<<20 || inodes != 3 {
		return errors.New("actual partial prefix and independent quota disagree")
	}
	for _, name := range []string{".", "root", "root/workspace.ext4"} {
		a, ok := entries[name]
		if !ok || a.Shared || a.UID != 0 || a.GID != 0 {
			return errors.New("partial copy namespace invalid")
		}
		if name == "root/workspace.ext4" {
			if a.Mode != unix.S_IFREG|0600 || a.Size != copyPrefix || a.Links != 1 {
				return errors.New("partial workspace inode invalid")
			}
		} else if a.Mode != unix.S_IFDIR|0700 {
			return errors.New("partial copy directory invalid")
		}
	}
	return nil
}
