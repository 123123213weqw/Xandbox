//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: fixed schema3 copy hold. A held seccomp notification is NOT a
// filesystem-D state. CONTINUE is permission to execute, not write completion.
import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/123123213weqw/Xandbox/internal/client"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

const nodePrepareNotificationMax = 32768
const nodePrepareHoldMax = 20 * time.Second

// Also observe small metadata/HTTP writes so the experiment can demonstrate
// that the listener keeps processing OTHER writes while one copy is held.
// No buffer is fetched and no successful return value is emulated.
func nodePrepareCopyProgram() ([]unix.SockFilter, error) {
	base, e := quotaNotifyProgram()
	if e != nil {
		return nil, e
	}
	p := append([]unix.SockFilter(nil), base[:6]...)
	return append(p,
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_WRITE), Jf: 6},
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 32},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JGT | unix.BPF_K, K: copyChunk, Jt: 4},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 0, Jt: 3},
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 36},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 0, Jf: 1},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_USER_NOTIF},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW}), nil
}
func runNodePrepareCopyDaemon() error {
	if e := requireQuotaChild(); e != nil {
		return e
	}
	if _, e := fixedNodeSnapshotConfig(); e != nil {
		return e
	}
	var st unix.Stat_t
	if e := unix.Fstat(3, &st); e != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("fixed node copy listener socket required")
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
	p, e := nodePrepareCopyProgram()
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

func nodePrepareGroupEmpty(ref sandbox.Ref) (bool, error) {
	if e := requireNode(); e != nil {
		return false, e
	}
	if !switchRefValid(ref) {
		return false, errors.New("fixed node ref required")
	}
	b, e := os.ReadFile(nodeBudgetInstances + "/" + ref.ID + ref.Generation + "/cgroup.events")
	if e != nil {
		return false, e
	}
	return strings.Contains("\n"+string(b), "\npopulated 0\n") && !strings.Contains(string(b), "populated 1"), nil
}

type nodePrepareCopyObserver struct {
	*copyObserver
	holdMu                       sync.Mutex
	heldNotif                    quotaNotif
	heldAt                       time.Time
	otherReplies, releaseReplies int
	received                     int
	releasedAt                   time.Time
}

func (o *nodePrepareCopyObserver) heldValid() error {
	if e := requireNode(); e != nil {
		return e
	}
	o.holdMu.Lock()
	defer o.holdMu.Unlock()
	if o.heldNotif.ID == 0 || time.Since(o.heldAt) >= nodePrepareHoldMax {
		return errors.New("fixed copy no longer held within20s budget")
	}
	_, matched, e := o.matchNode(o.heldNotif)
	if e != nil {
		return e
	}
	if !matched {
		return errors.New("held node workspace boundary changed")
	}
	return nil
}
func (o *nodePrepareCopyObserver) counts() (int, int) {
	o.holdMu.Lock()
	defer o.holdMu.Unlock()
	return o.otherReplies, o.releaseReplies
}
func (o *nodePrepareCopyObserver) serveNode() {
	defer close(o.done)
	defer unix.Close(o.fd)
	for {
		select {
		case <-o.stop:
			return
		default:
		}
		o.holdMu.Lock()
		held := o.heldNotif
		at := o.heldAt
		o.holdMu.Unlock()
		if held.ID != 0 {
			if time.Since(at) >= nodePrepareHoldMax {
				o.fail(errors.New("fixed node copy hold deadline20s"))
				return
			}
			select {
			case <-o.release:
				if e := o.heldValid(); e != nil {
					o.fail(e)
					return
				}
				r := quotaNotifResponse{ID: held.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
				if e := quotaNotifyIO(o.fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&r)); e != nil {
					o.fail(e)
					return
				}
				o.holdMu.Lock()
				o.heldNotif = quotaNotif{}
				o.releaseReplies++
				o.releasedAt = time.Now()
				o.holdMu.Unlock()
			default:
			}
		}
		p := []unix.PollFd{{Fd: int32(o.fd), Events: unix.POLLIN}}
		_, e := unix.Poll(p, 10)
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if e != nil {
			o.fail(e)
			return
		}
		if p[0].Revents&unix.POLLIN == 0 {
			if p[0].Revents&(unix.POLLERR|unix.POLLHUP) != 0 {
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
		if q.ID == 0 || q.PID == 0 || q.Flags != 0 || q.Data.Arch != unix.AUDIT_ARCH_X86_64 || q.Data.NR != int32(unix.SYS_WRITE) || q.Data.Args[2] == 0 || q.Data.Args[2] > copyChunk {
			o.fail(errors.New("unexpected fixed node write notification"))
			return
		}
		o.mu.Lock()
		armed, total := o.armed, o.continued
		o.mu.Unlock()
		o.holdMu.Lock()
		o.received++
		received := o.received
		o.holdMu.Unlock()
		if received > nodePrepareNotificationMax || total >= nodePrepareNotificationMax {
			o.fail(errors.New("node write notification bound"))
			return
		}
		if armed && q.Data.Args[2] == copyChunk {
			b, match, err := o.matchNode(q)
			if err != nil {
				o.fail(err)
				return
			}
			if match {
				o.mu.Lock()
				o.armed = false
				o.mu.Unlock()
				o.holdMu.Lock()
				o.heldNotif = q
				o.heldAt = time.Now()
				o.holdMu.Unlock()
				o.held <- b
				continue // KEEP receiving other notifications; never block here.
			}
		}
		r := quotaNotifResponse{ID: q.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
		if e = quotaNotifyIO(o.fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&r)); e != nil {
			if errors.Is(e, unix.ENOENT) {
				continue
			}
			o.fail(e)
			return
		}
		o.mu.Lock()
		o.continued++
		o.mu.Unlock()
		o.holdMu.Lock()
		if o.heldNotif.ID != 0 {
			o.otherReplies++
		}
		o.holdMu.Unlock()
	}
}

func (n *node) startNodePrepareObserved(ctx context.Context) (*nodePrepareCopyObserver, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.nodeSnapshot || n.process == nil || n.mapper != nil {
		return nil, errors.New("fixed idle snapshot node required")
	}
	if _, e := fixedNodeSnapshotConfig(); e != nil {
		return nil, e
	}
	g, e := switchGauges(ctx)
	if e != nil {
		return nil, e
	}
	if g["allocated"] != 0 || g["stop_queued"] != 0 || g["stop_running"] != 0 || g["cleanup_queued"] != 0 || g["cleanup_running"] != 0 {
		return nil, errors.New("observed daemon restart requires zero allocated guests")
	}
	if e = nodeSnapshotPins(ctx, n.switchTemplate, 0); e != nil {
		return nil, e
	}
	if e = n.process.Process.Signal(os.Interrupt); e != nil {
		return nil, e
	}
	select {
	case e = <-n.exited:
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
	parent, child := os.NewFile(uintptr(pair[0]), "node-copy-parent"), os.NewFile(uintptr(pair[1]), "node-copy-child")
	defer parent.Close()
	defer child.Close()
	log, e := os.OpenFile("/srv/fixture/node-prepare-observer.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	defer log.Close()
	cg, e := os.Open(nodeGroup + "/control")
	if e != nil {
		return nil, e
	}
	defer cg.Close()
	cmd := exec.Command("/usr/bin/xandbox-host-fixture", "-mode", "node-prepare-copy-daemon")
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
	id, e := processStart(cmd.Process.Pid)
	if e != nil {
		unix.Close(fd)
		cmd.Process.Kill()
		<-n.exited
		n.process = nil
		return nil, e
	}
	o := &nodePrepareCopyObserver{copyObserver: &copyObserver{cut: true, fd: fd, pid: cmd.Process.Pid, identity: id, held: make(chan copyBoundary, 1), release: make(chan struct{}), stop: make(chan struct{}), done: make(chan struct{})}}
	go o.serveNode()
	e = waitNode(ctx, func() (bool, error) {
		_, _, e := o.snapshot()
		if e != nil {
			return false, e
		}
		var h struct {
			Backend    string `json:"backend"`
			Isolation  bool   `json:"isolation"`
			Production bool   `json:"production_ready"`
		}
		e = n.api.Do(ctx, "GET", "/healthz", nil, &h)
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

func (n *node) stopNodePrepareObserved(ctx context.Context, o *nodePrepareCopyObserver, force bool) error {
	if e := requireNode(); e != nil {
		return e
	}
	if n.process == nil {
		return errors.New("owned observed controller absent")
	}
	if force {
		n.process.Process.Kill()
	} else {
		n.process.Process.Signal(os.Interrupt)
	}
	var e error
	select {
	case e = <-n.exited:
	case <-ctx.Done():
		n.process.Process.Kill()
		e = <-n.exited
	}
	n.process = nil
	closeErr := o.close()
	if force {
		return closeErr
	}
	if e != nil {
		return fmt.Errorf("observed daemon exit: %w", e)
	}
	if closeErr != nil {
		return closeErr
	}
	n.api.Close()
	n.api = client.NewWithToken("/srv/state/api.sock", n.token)
	return n.start(ctx)
}
