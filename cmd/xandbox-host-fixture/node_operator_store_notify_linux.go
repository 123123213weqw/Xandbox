//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: one exact ordinary FileStore FSYNC gets EIO. Other FSYNCs are
// continued while it waits. A notification wait is NOT filesystem D or media EIO.
import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/123123213weqw/Xandbox/internal/client"
	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

type operatorStoreMode string

const operatorStorePre operatorStoreMode = "pre-file"
const operatorStorePost operatorStoreMode = "post-root"

func (m operatorStoreMode) valid() bool { return m == operatorStorePre || m == operatorStorePost }

const operatorStoreHoldMax = 20 * time.Second

var operatorTempPattern = regexp.MustCompile(`^\.state-[0-9]+$`)

func runOperatorStoreDaemon() error {
	if e := requireQuotaChild(); e != nil {
		return e
	}
	if _, e := fixedBudgetConfig(); e != nil {
		return e
	}
	hash, e := fileHash("/srv/assets/sandboxd")
	if e != nil || hash != prepareTraceELFSHA {
		return errors.New("exact ordinary operator ELF required")
	}
	var st unix.Stat_t
	if e = unix.Fstat(3, &st); e != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("fixed operator listener transfer socket required")
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
	return unix.Exec("/srv/assets/sandboxd", []string{"sandboxd", "-backend", "firecracker", "-state-dir", "/srv/state", "-auth-file", "/srv/config/auth.json", "-firecracker-config", "/srv/config/backend.json", "-max-instances", "4", "-max-records", "1024", "-max-sessions", "32", "-metrics"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
}

type operatorStoreSnapshot struct {
	HeldID                                        uint64
	FileEntries, AdmissionDirEntries, RootEntries int
	Continued, OtherWhileHeld, Injected           int
	Err                                           error
}
type operatorStoreObserver struct {
	mu                          sync.Mutex
	once                        sync.Once
	fd, pid                     int
	identity                    string
	mode                        operatorStoreMode
	before, next                nodecontrol.State
	armed                       bool
	tempPath                    string
	tempInfo, rootInfo, dirInfo os.FileInfo
	snapshotValue               operatorStoreSnapshot
	held                        chan struct{}
	inject                      chan struct{}
	stop, done                  chan struct{}
}

func (o *operatorStoreObserver) snapshot() operatorStoreSnapshot {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.snapshotValue
}
func (o *operatorStoreObserver) fail(e error) {
	o.mu.Lock()
	if o.snapshotValue.Err == nil {
		o.snapshotValue.Err = e
	}
	o.mu.Unlock()
}
func (o *operatorStoreObserver) close() error {
	o.once.Do(func() { close(o.stop) })
	select {
	case <-o.done:
		return o.snapshot().Err
	case <-time.After(2 * time.Second):
		return errors.New("operator fsync observer did not stop")
	}
}
func (o *operatorStoreObserver) arm(mode operatorStoreMode, before, next nodecontrol.State) error {
	if e := requireNode(); e != nil {
		return e
	}
	if !mode.valid() || before.Mode != nodecontrol.ModeOpen || before.Revision != 1 || next.Mode != nodecontrol.ModeDrained || next.Revision != 2 || next.Epoch != before.Epoch || !hex32Pattern(next.LastRequestID) || next.LastExpectedRevision != 1 {
		return errors.New("fixed operator transition required")
	}
	root, e := os.Lstat("/srv/state")
	if e != nil {
		return e
	}
	dir, e := os.Lstat("/srv/state/admission")
	if e != nil {
		return e
	}
	for _, info := range []os.FileInfo{root, dir} {
		s, ok := info.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != 0 || s.Gid != 0 || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("private bound operator directory required")
		}
	}
	stored, e := operatorState()
	if e != nil || stored != before {
		return errors.New("operator baseline disk state mismatch")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.armed || o.mode != "" || o.snapshotValue.HeldID != 0 {
		return errors.New("operator observer already armed")
	}
	o.mode, o.before, o.next, o.rootInfo, o.dirInfo, o.armed = mode, before, next, root, dir, true
	return nil
}
func (o *operatorStoreObserver) heldValid() error {
	if e := requireNode(); e != nil {
		return e
	}
	s := o.snapshot()
	if s.Err != nil {
		return s.Err
	}
	if s.HeldID == 0 || s.Injected != 0 {
		return errors.New("operator fsync not pending")
	}
	id := s.HeldID
	return quotaNotifyIO(o.fd, quotaNotifIDValid, unsafe.Pointer(&id))
}
func (o *operatorStoreObserver) descriptor(q quotaNotif) (string, os.FileInfo, bool, error) {
	if e := requireNode(); e != nil {
		return "", nil, false, e
	}
	if q.ID == 0 || q.PID == 0 || q.Flags != 0 || q.Data.Arch != unix.AUDIT_ARCH_X86_64 || q.Data.NR != int32(unix.SYS_FSYNC) || q.Data.Args[0] > 4095 {
		return "", nil, false, errors.New("unexpected fixed operator fsync notification")
	}
	if e := quotaNotifyIO(o.fd, quotaNotifIDValid, unsafe.Pointer(&q.ID)); e != nil {
		return "", nil, false, e
	}
	start, e := processStart(o.pid)
	if e != nil || start != o.identity {
		return "", nil, false, errors.New("operator daemon incarnation changed")
	}
	status, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", q.PID))
	if e != nil {
		return "", nil, false, e
	}
	tgid := 0
	for _, line := range strings.Split(string(status), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "Tgid:" {
			tgid, e = strconv.Atoi(f[1])
			if e != nil {
				return "", nil, false, e
			}
		}
	}
	if tgid != o.pid {
		return "", nil, false, nil
	}
	exe, e := os.Stat(fmt.Sprintf("/proc/%d/exe", o.pid))
	if e != nil {
		return "", nil, false, e
	}
	want, e := os.Stat("/srv/assets/sandboxd")
	if e != nil || !os.SameFile(exe, want) {
		return "", nil, false, errors.New("operator fsync target ELF changed")
	}
	group, e := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", o.pid))
	if e != nil || !operatorStoreControlMember(string(group)) {
		return "", nil, false, errors.New("operator daemon left fixed control cgroup")
	}
	path := fmt.Sprintf("/proc/%d/fd/%d", o.pid, q.Data.Args[0])
	target, e := os.Readlink(path)
	if e != nil {
		return "", nil, false, e
	}
	if target != "/srv/state" && target != "/srv/state/admission" && !(filepath.Dir(target) == "/srv/state/admission" && operatorTempPattern.MatchString(filepath.Base(target))) {
		return "", nil, false, nil
	}
	direct, e := os.Lstat(target)
	if e != nil {
		return "", nil, false, e
	}
	via, e := os.Stat(path)
	if e != nil || !os.SameFile(direct, via) || direct.Mode()&os.ModeSymlink != 0 {
		return "", nil, false, errors.New("operator fsync descriptor identity changed")
	}
	st, ok := direct.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Gid != 0 {
		return "", nil, false, errors.New("operator fsync descriptor owner changed")
	}
	return target, direct, true, nil
}

func operatorStoreControlMember(value string) bool {
	// /proc/PID/cgroup contains a hierarchy-relative path, not its mount path.
	return strings.TrimSpace(value) == "0::"+strings.TrimPrefix(nodeGroup, "/sys/fs/cgroup")+"/control"
}

// Only the serving goroutine touches the sequence fields. FileSync CONTINUE
// alone is not completion; the NEXT ordinary directory FSYNC proves progress
// through the frozen code's checked return/rename, with the same temp inode.
func (o *operatorStoreObserver) match(q quotaNotif) (bool, error) {
	target, info, owned, e := o.descriptor(q)
	if e != nil || !owned {
		return false, e
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	s := &o.snapshotValue
	disk, e := operatorState()
	if e != nil {
		return false, e
	}
	switch {
	case operatorTempPattern.MatchString(filepath.Base(target)):
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Nlink != 1 || info.Size() <= 0 || info.Size() > nodecontrol.StateLimit || disk != o.before || s.FileEntries != 0 {
			return false, errors.New("operator temp fsync boundary mismatch")
		}
		data, e := privatefile.Read(target, nodecontrol.StateLimit)
		if e != nil {
			return false, e
		}
		var next nodecontrol.State
		if strictjson.Decode(data, &next) != nil || next != o.next {
			return false, errors.New("ordinary temporary transition differs from exact command")
		}
		o.tempPath, o.tempInfo = target, info
		s.FileEntries++
		return o.mode == operatorStorePre, nil
	case target == "/srv/state/admission":
		if !os.SameFile(info, o.dirInfo) || info.Mode().Perm() != 0700 || o.mode != operatorStorePost || s.FileEntries != 1 || s.AdmissionDirEntries != 0 || disk != o.next {
			return false, errors.New("operator admission-directory sequence mismatch")
		}
		if e = o.renamed(); e != nil {
			return false, e
		}
		s.AdmissionDirEntries++
		return false, nil
	case target == "/srv/state":
		if !os.SameFile(info, o.rootInfo) || info.Mode().Perm() != 0700 || o.mode != operatorStorePost || s.FileEntries != 1 || s.AdmissionDirEntries != 1 || s.RootEntries != 0 || disk != o.next {
			return false, errors.New("operator post-commit root-directory sequence mismatch")
		}
		if e = o.renamed(); e != nil {
			return false, e
		}
		s.RootEntries++
		return true, nil
	}
	return false, errors.New("unknown fixed operator descriptor")
}
func (o *operatorStoreObserver) renamed() error {
	if _, e := os.Lstat(o.tempPath); !os.IsNotExist(e) {
		return errors.New("operator temp name still exists after rename")
	}
	info, e := os.Lstat("/srv/state/admission/state.json")
	if e != nil || o.tempInfo == nil || !os.SameFile(info, o.tempInfo) {
		return errors.New("operator rename did not preserve exact temporary inode")
	}
	return nil
}
func operatorStoreEIO(id uint64) quotaNotifResponse {
	return quotaNotifResponse{ID: id, Error: -int32(unix.EIO)}
}
func (o *operatorStoreObserver) serve() {
	defer close(o.done)
	defer unix.Close(o.fd)
	var target quotaNotif
	var deadline time.Time
	for {
		select {
		case <-o.stop:
			return
		case <-o.inject:
			if target.ID == 0 || time.Now().After(deadline) {
				o.fail(errors.New("operator target missing/expired before EIO"))
				return
			}
			if e := o.heldValid(); e != nil {
				o.fail(e)
				return
			}
			path, info, owned, e := o.descriptor(target)
			if e != nil || !owned || path == "" || info == nil {
				o.fail(errors.New("operator target invalid at EIO reply"))
				return
			}
			wantPath, wantInfo := o.tempPath, o.tempInfo
			if o.mode == operatorStorePost {
				wantPath, wantInfo = "/srv/state", o.rootInfo
			}
			if wantInfo == nil || path != wantPath || !os.SameFile(info, wantInfo) {
				o.fail(errors.New("operator held inode changed before EIO"))
				return
			}
			if e = quotaNotifyIO(o.fd, quotaNotifIDValid, unsafe.Pointer(&target.ID)); e != nil {
				o.fail(e)
				return
			}
			response := operatorStoreEIO(target.ID)
			if e = quotaNotifyIO(o.fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&response)); e != nil {
				o.fail(e)
				return
			}
			o.mu.Lock()
			o.snapshotValue.Injected++
			o.mu.Unlock()
			deadline = time.Time{}
		default:
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			o.fail(errors.New("operator fsync hold exceeded fixed20s bound"))
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
		snapshot := o.snapshot()
		if snapshot.Continued >= 8192 {
			o.fail(errors.New("operator fsync notification bound exceeded"))
			return
		}
		o.mu.Lock()
		armed := o.armed
		o.mu.Unlock()
		if armed {
			selected, err := o.match(q)
			if errors.Is(err, unix.ENOENT) && errors.Is(quotaNotifyIO(o.fd, quotaNotifIDValid, unsafe.Pointer(&q.ID)), unix.ENOENT) {
				continue
			}
			if err != nil {
				o.fail(err)
				return
			}
			if selected {
				o.mu.Lock()
				o.armed = false
				o.snapshotValue.HeldID = q.ID
				o.mu.Unlock()
				target = q
				deadline = time.Now().Add(operatorStoreHoldMax)
				o.held <- struct{}{}
				continue
			}
		}
		// Never synthesize successful FSYNC returns. Only the one target gets EIO.
		response := quotaNotifResponse{ID: q.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
		e = quotaNotifyIO(o.fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&response))
		if errors.Is(e, unix.ENOENT) {
			continue
		}
		if e != nil {
			o.fail(e)
			return
		}
		o.mu.Lock()
		o.snapshotValue.Continued++
		if o.snapshotValue.HeldID != 0 && o.snapshotValue.Injected == 0 {
			o.snapshotValue.OtherWhileHeld++
		}
		o.mu.Unlock()
	}
}
func (n *node) stopOperatorDaemon(ctx context.Context) error {
	if e := requireNode(); e != nil {
		return e
	}
	if n.process == nil {
		return errors.New("known operator daemon required")
	}
	if e := n.process.Process.Signal(os.Interrupt); e != nil {
		return e
	}
	select {
	case e := <-n.exited:
		if e == nil {
			n.process = nil
			n.api.Close()
			n.api = client.NewWithToken("/srv/state/api.sock", n.token)
		}
		return e
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (n *node) startOperatorStoreObserved(ctx context.Context) (*operatorStoreObserver, error) {
	if e := n.operatorProfile(); e != nil {
		return nil, e
	}
	hash, e := fileHash("/srv/assets/sandboxd")
	if e != nil || hash != prepareTraceELFSHA {
		return nil, errors.New("fixed ordinary FileStore executable required")
	}
	pair, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	parent, child := os.NewFile(uintptr(pair[0]), "operator-store-parent"), os.NewFile(uintptr(pair[1]), "operator-store-child")
	defer parent.Close()
	defer child.Close()
	log, e := os.OpenFile("/srv/fixture/operator-store-controller.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	defer log.Close()
	cg, e := os.Open(nodeGroup + "/control")
	if e != nil {
		return nil, e
	}
	defer cg.Close()
	cmd := exec.Command("/usr/bin/xandbox-host-fixture", "-mode", "node-operator-store-daemon")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.ExtraFiles = []*os.File{child}
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
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
	o := &operatorStoreObserver{fd: fd, pid: cmd.Process.Pid, identity: identity, held: make(chan struct{}, 1), inject: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go o.serve()
	e = waitNode(ctx, func() (bool, error) {
		if e := o.snapshot().Err; e != nil {
			return false, e
		}
		var h struct {
			Backend    string `json:"backend"`
			Isolation  bool   `json:"isolation"`
			Production bool   `json:"production_ready"`
		}
		e := n.api.Do(ctx, "GET", "/healthz", nil, &h)
		return e == nil && h.Backend == "firecracker" && h.Isolation && !h.Production, nil
	})
	if e != nil {
		cmd.Process.Kill()
		<-n.exited
		n.process = nil
		o.close()
		return nil, e
	}
	return o, nil
}
