//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: exact ordinary daemon ring FSYNC entry and EXIT_GROUP(1) holds.
// A notification wait is not filesystem D, media failure or a durable audit ACK.
import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/123123213weqw/Xandbox/internal/diagnostics"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"golang.org/x/sys/unix"
)

type diagnosticHoldMode string

const diagnosticData diagnosticHoldMode = "record-data"
const diagnosticHeader diagnosticHoldMode = "header-publish"
const diagnosticHoldMax = 20 * time.Second
const diagnosticRingPath = "/srv/state/diagnostics/events.ring"
const diagnosticControllerLog = "/srv/fixture/diagnostic-controller.log"

func (m diagnosticHoldMode) valid() bool { return m == diagnosticData || m == diagnosticHeader }
func (m diagnosticHoldMode) observed() uint64 {
	if m == diagnosticHeader {
		return 5
	}
	return 4
}

type diagnosticObservation struct {
	TargetID, ExitID                                                          uint64
	RingEntries, DataContinued, OtherContinued, OtherWhileHeld, ExitContinued int
	HeldAt, SignalAt, ExitAt                                                  time.Time
	Err                                                                       error
}
type diagnosticObserver struct {
	mu                           sync.Mutex
	once                         sync.Once
	base                         *operatorStoreObserver // Reuse ONLY fixed incarnation/TGID/ELF/control checks.
	mode                         diagnosticHoldMode
	armed                        bool
	ringInfo                     os.FileInfo
	v                            diagnosticObservation
	held, exitHeld, continueExit chan struct{}
	stop, done                   chan struct{}
}

func (o *diagnosticObserver) snapshot() diagnosticObservation {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.v
}
func (o *diagnosticObserver) fail(e error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.v.Err == nil {
		o.v.Err = e
	}
}
func (o *diagnosticObserver) close() error {
	o.once.Do(func() { close(o.stop) })
	select {
	case <-o.done:
		return o.snapshot().Err
	case <-time.After(2 * time.Second):
		return errors.New("diagnostic observer did not stop")
	}
}
func (o *diagnosticObserver) target(q quotaNotif) (bool, error) {
	return (&operatorShutdownObserver{store: o.base}).targetTGID(q)
}
func (o *diagnosticObserver) heldValid() error {
	if e := requireNode(); e != nil {
		return e
	}
	v := o.snapshot()
	if v.Err != nil {
		return v.Err
	}
	if v.TargetID == 0 || v.ExitContinued != 0 {
		return errors.New("diagnostic FSYNC not held")
	}
	return quotaNotifyIO(o.base.fd, quotaNotifIDValid, unsafe.Pointer(&v.TargetID))
}
func (o *diagnosticObserver) bothValid() error {
	if e := o.heldValid(); e != nil {
		return e
	}
	v := o.snapshot()
	if v.ExitID == 0 || v.SignalAt.IsZero() {
		return errors.New("diagnostic exit not held")
	}
	return quotaNotifyIO(o.base.fd, quotaNotifIDValid, unsafe.Pointer(&v.ExitID))
}
func diagnosticStage(data []byte) error {
	if len(data) != diagnostics.RingBytes {
		return errors.New("fixed diagnostic ring size required")
	}
	offset := 2*diagnostics.HeaderBytes + 5%(diagnostics.RetainedRecords+1)*diagnostics.FrameBytes
	b := data[offset : offset+diagnostics.FrameBytes]
	if string(b[:8]) != "XBDEVEN\x01" || b[8] != 1 || b[9] != byte(diagnostics.PrepareFailed) || b[10] != byte(diagnostics.Other) || binary.LittleEndian.Uint64(b[16:24]) != 5 || int64(binary.LittleEndian.Uint64(b[24:32])) <= 0 || binary.LittleEndian.Uint64(b[32:40]) != 0 || binary.LittleEndian.Uint32(b[124:]) != crc32.Checksum(b[:124], crc32.MakeTable(crc32.Castagnoli)) {
		return errors.New("exact closed first failed-prepare stage required")
	}
	for i, c := range b[:124] {
		if (i >= 11 && i < 16 || i >= 40) && c != 0 {
			return errors.New("diagnostic stage reserved bytes")
		}
	}
	return nil
}
func diagnosticPrefix(v diagnostics.Snapshot, last uint64) error {
	if last < 4 || last > 5 || v.Version != 1 || v.ObservedSequence != last || v.Overwritten != 0 || v.RetainedCapacity != 128 || len(v.Records) != int(last) {
		return errors.New("fixed observed diagnostic prefix required")
	}
	kinds := []diagnostics.Kind{diagnostics.ServiceKVM, diagnostics.ProcessStopped, diagnostics.CollectorClosed, diagnostics.ServiceKVM, diagnostics.PrepareFailed}
	for i, r := range v.Records {
		if r.Sequence != uint64(i+1) || r.Event.Kind != kinds[i] || r.Event.Reason != diagnostics.Other || r.Event.DroppedBefore != 0 || r.Event.TimeNS <= 0 {
			return errors.New("unexpected diagnostic prefix event")
		}
	}
	return nil
}
func (o *diagnosticObserver) arm(mode diagnosticHoldMode) error {
	if e := requireNode(); e != nil {
		return e
	}
	if !mode.valid() {
		return errors.New("fixed diagnostic phase required")
	}
	info, e := os.Lstat(diagnosticRingPath)
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != 0 || st.Nlink != 1 || info.Size() != diagnostics.RingBytes {
		return errors.New("private original ring required")
	}
	v, e := diagnostics.Read(filepath.Dir(diagnosticRingPath))
	if e != nil {
		return e
	}
	if e = diagnosticPrefix(v, 4); e != nil {
		return e
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.armed || o.mode != "" || o.v.TargetID != 0 {
		return errors.New("diagnostic observer already armed")
	}
	o.mode, o.ringInfo, o.armed = mode, info, true
	return nil
}
func (o *diagnosticObserver) match(q quotaNotif) (bool, error) {
	if q.Data.NR != int32(unix.SYS_FSYNC) || q.Data.Args[0] > 4095 {
		return false, errors.New("fixed ring FSYNC required")
	}
	owned, e := o.target(q)
	if e != nil || !owned {
		return false, e
	}
	path := fmt.Sprintf("/proc/%d/fd/%d", o.base.pid, q.Data.Args[0])
	target, e := os.Readlink(path)
	if e != nil {
		return false, e
	}
	if target != diagnosticRingPath {
		return false, nil
	}
	info, e := os.Stat(path)
	if e != nil || !os.SameFile(info, o.ringInfo) {
		return false, errors.New("ring descriptor inode changed")
	}
	if e = quotaNotifyIO(o.base.fd, quotaNotifIDValid, unsafe.Pointer(&q.ID)); e != nil {
		return false, e
	}
	data, e := privatefile.Read(diagnosticRingPath, diagnostics.RingBytes)
	if e != nil {
		return false, e
	}
	if e = diagnosticStage(data); e != nil {
		return false, e
	}
	view, e := diagnostics.Read(filepath.Dir(diagnosticRingPath))
	if e != nil {
		return false, e
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.v.RingEntries++
	want := uint64(4)
	if o.v.RingEntries == 2 {
		want = 5
	}
	if o.v.RingEntries > 2 || diagnosticPrefix(view, want) != nil {
		return false, errors.New("ring data/header fsync order changed")
	}
	if o.mode == diagnosticHeader && o.v.RingEntries == 1 {
		o.v.DataContinued++
		return false, nil
	}
	if o.mode == diagnosticData && o.v.RingEntries != 1 || o.mode == diagnosticHeader && o.v.RingEntries != 2 {
		return false, errors.New("wrong diagnostic target phase")
	}
	o.armed = false
	o.v.TargetID = q.ID
	o.v.HeldAt = time.Now()
	return true, nil
}
func (o *diagnosticObserver) selectExit(q quotaNotif) (bool, error) {
	owned, e := o.target(q)
	if e != nil || !owned {
		return false, e
	}
	v := o.snapshot()
	if q.Data.Args[0] != 1 || v.ExitID != 0 || v.SignalAt.IsZero() || time.Since(v.SignalAt) < 250*time.Millisecond {
		return false, errors.New("ordinary exit must follow diagnostic Close budget")
	}
	if e = o.heldValid(); e != nil {
		return false, e
	}
	view, e := diagnostics.Read(filepath.Dir(diagnosticRingPath))
	if e != nil {
		return false, e
	}
	if e = diagnosticPrefix(view, o.mode.observed()); e != nil {
		return false, e
	}
	o.mu.Lock()
	o.v.ExitID = q.ID
	o.v.ExitAt = time.Now()
	o.mu.Unlock()
	return true, nil
}
func (o *diagnosticObserver) signal() error {
	if e := o.heldValid(); e != nil {
		return e
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.v.SignalAt.IsZero() {
		return errors.New("diagnostic signal already sent")
	}
	o.v.SignalAt = time.Now()
	return nil
}
func (o *diagnosticObserver) invalidAfterReap() error {
	if e := requireNode(); e != nil {
		return e
	}
	v := o.snapshot()
	if v.TargetID == 0 || v.ExitID == 0 || v.ExitContinued != 1 {
		return errors.New("diagnostic actual exit required")
	}
	if _, e := unix.FcntlInt(uintptr(o.base.fd), unix.F_GETFD, 0); e != nil {
		return e
	}
	for _, id := range []uint64{v.TargetID, v.ExitID} {
		if e := quotaNotifyIO(o.base.fd, quotaNotifIDValid, unsafe.Pointer(&id)); !errors.Is(e, unix.ENOENT) {
			return errors.New("held diagnostic ID must be ENOENT after reap with listener open")
		}
	}
	return nil
}
func (o *diagnosticObserver) serve() {
	defer close(o.done)
	defer unix.Close(o.base.fd)
	for {
		select {
		case <-o.stop:
			return
		case <-o.continueExit:
			if e := o.bothValid(); e != nil {
				o.fail(e)
				return
			}
			v := o.snapshot()
			r := quotaNotifResponse{ID: v.ExitID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
			if e := quotaNotifyIO(o.base.fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&r)); e != nil {
				o.fail(e)
				return
			}
			o.mu.Lock()
			o.v.ExitContinued++
			o.mu.Unlock()
		default:
		}
		v := o.snapshot()
		if !v.HeldAt.IsZero() && time.Since(v.HeldAt) > diagnosticHoldMax {
			o.fail(errors.New("diagnostic fixed20s hold expired"))
			return
		}
		p := []unix.PollFd{{Fd: int32(o.base.fd), Events: unix.POLLIN}}
		_, e := unix.Poll(p, 50)
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if e != nil {
			o.fail(e)
			return
		}
		if p[0].Revents&unix.POLLIN == 0 {
			if p[0].Revents&(unix.POLLHUP|unix.POLLERR) != 0 {
				select {
				case <-o.stop:
					return
				case <-time.After(20 * time.Millisecond):
				}
			}
			continue
		}
		var q quotaNotif
		e = quotaNotifyIO(o.base.fd, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&q))
		if errors.Is(e, unix.EINTR) || errors.Is(e, unix.ENOENT) {
			continue
		}
		if e != nil {
			o.fail(e)
			return
		}
		if q.ID == 0 || q.PID == 0 || q.Flags != 0 || q.Data.Arch != unix.AUDIT_ARCH_X86_64 || (q.Data.NR != int32(unix.SYS_FSYNC) && q.Data.NR != int32(unix.SYS_EXIT_GROUP)) {
			o.fail(errors.New("unexpected diagnostic notification"))
			return
		}
		if o.snapshot().OtherContinued >= 16384 {
			o.fail(errors.New("bounded diagnostic notification count exceeded"))
			return
		}
		selected := false
		if q.Data.NR == int32(unix.SYS_EXIT_GROUP) {
			selected, e = o.selectExit(q)
			if selected {
				o.exitHeld <- struct{}{}
				continue
			}
		} else {
			o.mu.Lock()
			armed := o.armed
			o.mu.Unlock()
			if armed {
				selected, e = o.match(q)
			}
			if selected {
				o.held <- struct{}{}
				continue
			}
		}
		if e != nil {
			o.fail(e)
			return
		}
		r := quotaNotifResponse{ID: q.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
		if e = quotaNotifyIO(o.base.fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&r)); e != nil {
			o.fail(e)
			return
		}
		o.mu.Lock()
		o.v.OtherContinued++
		if o.v.TargetID != 0 {
			o.v.OtherWhileHeld++
		}
		o.mu.Unlock()
	}
}
func (n *node) startDiagnosticObserved(ctx context.Context) (*diagnosticObserver, error) {
	if e := n.operatorProfile(); e != nil {
		return nil, e
	}
	h, e := fileHash("/srv/assets/sandboxd")
	if e != nil || h != prepareTraceELFSHA {
		return nil, errors.New("exact ordinary diagnostic ELF required")
	}
	pair, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	parent, child := os.NewFile(uintptr(pair[0]), "diagnostic-parent"), os.NewFile(uintptr(pair[1]), "diagnostic-child")
	defer parent.Close()
	defer child.Close()
	log, e := os.OpenFile(diagnosticControllerLog, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, e
	}
	defer log.Close()
	cg, e := os.Open(nodeGroup + "/control")
	if e != nil {
		return nil, e
	}
	defer cg.Close()
	// Same fixed FSYNC+EXIT_GROUP launcher. Only the TEST observer selector differs.
	cmd := exec.Command("/usr/bin/xandbox-host-fixture", "-mode", "node-operator-shutdown-daemon")
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
	success := false
	var o *diagnosticObserver
	defer func() {
		if !success {
			cmd.Process.Kill()
			<-n.exited
			n.process = nil
			if o != nil {
				o.close()
			}
		}
	}()
	transfer, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	fd, e := receiveQuotaListener(transfer, int(parent.Fd()))
	if e != nil {
		return nil, e
	}
	identity, e := processStart(cmd.Process.Pid)
	if e != nil {
		unix.Close(fd)
		return nil, e
	}
	o = &diagnosticObserver{base: &operatorStoreObserver{fd: fd, pid: cmd.Process.Pid, identity: identity}, held: make(chan struct{}, 1), exitHeld: make(chan struct{}, 1), continueExit: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go o.serve()
	if e = waitNode(ctx, func() (bool, error) {
		if e := o.snapshot().Err; e != nil {
			return false, e
		}
		return diagnosticWriterReady(ctx)
	}); e != nil {
		return nil, e
	}
	success = true
	return o, nil
}
