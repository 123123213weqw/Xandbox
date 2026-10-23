//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: hold one exact pre-rename control FSYNC, then the ordinary
// daemon's actual EXIT_GROUP(1). Never reply to the held FSYNC, even on exit.
import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/123123213weqw/Xandbox/internal/diagnostics"
	"golang.org/x/sys/unix"
)

const operatorShutdownLog = "/srv/fixture/operator-shutdown-controller.log"
const operatorShutdownReceipt = "/srv/fixture/operator-shutdown-receipt.json"

func operatorShutdownProgram() ([]unix.SockFilter, error) {
	base, e := ownerNotifyProgram()
	if e != nil {
		return nil, e
	}
	p := append([]unix.SockFilter(nil), base[:6]...)
	return append(p,
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_FSYNC), Jt: 1},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_EXIT_GROUP), Jf: 1},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_USER_NOTIF},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW}), nil
}

type operatorShutdownSnapshot struct {
	ExitID                    uint64
	ExitContinued, OtherExits int
	SignalAt                  time.Time
}
type operatorShutdownObserver struct {
	store                  *operatorStoreObserver
	value                  operatorShutdownSnapshot // protected by store.mu
	exitHeld, continueExit chan struct{}
}

func newOperatorShutdownObserver(o *operatorStoreObserver) *operatorShutdownObserver {
	return &operatorShutdownObserver{store: o, exitHeld: make(chan struct{}, 1), continueExit: make(chan struct{}, 1)}
}
func (s *operatorShutdownObserver) snapshot() operatorShutdownSnapshot {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	return s.value
}
func (s *operatorShutdownObserver) signal() error {
	if e := s.store.heldValid(); e != nil {
		return e
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if !s.value.SignalAt.IsZero() {
		return errors.New("shutdown signal already selected")
	}
	s.value.SignalAt = time.Now()
	return nil
}
func (s *operatorShutdownObserver) bothValid() error {
	if e := s.store.heldValid(); e != nil {
		return e
	}
	v := s.snapshot()
	if v.ExitID == 0 || v.ExitContinued != 0 || v.SignalAt.IsZero() {
		return errors.New("both shutdown notifications not held")
	}
	if e := quotaNotifyIO(s.store.fd, quotaNotifIDValid, unsafe.Pointer(&v.ExitID)); e != nil {
		return e
	}
	_, e := s.targetTGID(quotaNotif{PID: uint32(s.store.pid)})
	return e
}

// A thread ID need not equal its process TGID. No PID from RPC is accepted.
func (s *operatorShutdownObserver) targetTGID(q quotaNotif) (bool, error) {
	if e := requireNode(); e != nil {
		return false, e
	}
	if q.PID == 0 {
		return false, errors.New("zero shutdown notification PID")
	}
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", q.PID))
	if e != nil {
		return false, e
	}
	tgid := 0
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "Tgid:" {
			tgid, e = strconv.Atoi(f[1])
			if e != nil {
				return false, e
			}
		}
	}
	if tgid == 0 {
		return false, errors.New("missing shutdown TGID")
	}
	if tgid != s.store.pid {
		return false, nil
	}
	start, e := processStart(tgid)
	if e != nil || start != s.store.identity {
		return false, errors.New("shutdown incarnation changed")
	}
	exe, e := os.Stat(fmt.Sprintf("/proc/%d/exe", tgid))
	if e != nil {
		return false, e
	}
	want, e := os.Stat("/srv/assets/sandboxd")
	if e != nil || !os.SameFile(exe, want) {
		return false, errors.New("shutdown ordinary ELF inode changed")
	}
	b, e = os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", tgid))
	if e != nil || !operatorStoreControlMember(string(b)) {
		return false, errors.New("shutdown daemon left control")
	}
	return true, nil
}

// The ordinary daemon no longer serializes raw errors to inherited stderr.
// This test requires a completed bounded diagnostic drain after control.Close's
// real deadline, and rejects unrelated lifecycle/listener/operator failures.
// It is not durable tenant-operation audit coverage.
func shutdownDiagnostics(v diagnostics.Snapshot) error {
	if v.Version != 1 || v.RetainedCapacity != diagnostics.RetainedRecords || v.Overwritten != 0 || v.ObservedSequence == 0 || len(v.Records) < 4 || len(v.Records) > diagnostics.RetainedRecords || uint64(len(v.Records)) != v.ObservedSequence {
		return errors.New("bounded complete shutdown diagnostic view required")
	}
	control, failed := 0, 0
	for i, r := range v.Records {
		if r.Sequence != uint64(i+1) || r.Event.DroppedBefore != 0 || r.Event.TimeNS <= 0 {
			return errors.New("shutdown diagnostic gap/loss")
		}
		switch r.Event.Kind {
		case diagnostics.ServiceKVM:
			if i != 0 || r.Event.Reason != diagnostics.Other {
				return errors.New("unexpected startup diagnostic")
			}
		case diagnostics.ControlUnfinished:
			control++
			if r.Event.Reason != diagnostics.Deadline || i != len(v.Records)-3 {
				return errors.New("control Close deadline diagnostic required")
			}
		case diagnostics.ProcessFailed:
			failed++
			if r.Event.Reason != diagnostics.Deadline || i != len(v.Records)-2 {
				return errors.New("exact failed shutdown diagnostic required")
			}
		case diagnostics.CollectorClosed:
			if i != len(v.Records)-1 || r.Event.Reason != diagnostics.Other {
				return errors.New("completed writer drain required")
			}
		default:
			return errors.New("unrelated shutdown failure diagnostic")
		}
	}
	if control != 1 || failed != 1 || v.Records[len(v.Records)-1].Event.Kind != diagnostics.CollectorClosed {
		return errors.New("missing control shutdown diagnostic")
	}
	return nil
}
func (s *operatorShutdownObserver) selectExit(q quotaNotif) (bool, error) {
	owned, e := s.targetTGID(q)
	if e != nil || !owned {
		return false, e
	}
	v := s.snapshot()
	if q.Data.Args[0] != 1 || v.ExitID != 0 || v.SignalAt.IsZero() || time.Since(v.SignalAt) < 5*time.Second {
		return false, errors.New("unexpected ordinary exit before control Close timeout")
	}
	if e = s.store.heldValid(); e != nil {
		return false, e
	}
	if e = operatorStoreSequence(operatorStorePre, s.store.snapshot()); e != nil {
		return false, e
	}
	view, e := diagnostics.Read("/srv/state/diagnostics")
	if e != nil {
		return false, e
	}
	if e = shutdownDiagnostics(view); e != nil {
		return false, e
	}
	s.store.mu.Lock()
	s.value.ExitID = q.ID
	s.store.mu.Unlock()
	return true, nil
}
func (s *operatorShutdownObserver) invalidAfterReap() error {
	if e := requireNode(); e != nil {
		return e
	}
	v := s.snapshot()
	o := s.store
	id := o.snapshot().HeldID
	if v.ExitID == 0 || v.ExitContinued != 1 || id == 0 {
		return errors.New("real exit CONTINUE required before death check")
	}
	// The listener remains OPEN after POLLHUP. EBADF is never proof of death.
	if _, e := unix.FcntlInt(uintptr(o.fd), unix.F_GETFD, 0); e != nil {
		return e
	}
	for _, n := range []uint64{id, v.ExitID} {
		if e := quotaNotifyIO(o.fd, quotaNotifIDValid, unsafe.Pointer(&n)); !errors.Is(e, unix.ENOENT) {
			return errors.New("notification not invalidated by actual process death")
		}
	}
	return nil
}
func (s *operatorShutdownObserver) serve() {
	o := s.store
	defer close(o.done)
	defer unix.Close(o.fd)
	var deadline time.Time
	for {
		select {
		case <-o.stop:
			return
		case <-s.continueExit:
			if e := s.bothValid(); e != nil {
				o.fail(e)
				return
			}
			id := s.snapshot().ExitID
			r := quotaNotifResponse{ID: id, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
			if e := quotaNotifyIO(o.fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&r)); e != nil {
				o.fail(e)
				return
			}
			o.mu.Lock()
			s.value.ExitContinued++
			o.mu.Unlock()
		default:
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			o.fail(errors.New("shutdown hold exceeded original fixed20s"))
			return
		}
		p := []unix.PollFd{{Fd: int32(o.fd), Events: unix.POLLIN}}
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
				// No busy spin or early fd close: caller must reap/check IDs first.
				select {
				case <-o.stop:
					return
				case <-time.After(20 * time.Millisecond):
				}
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
		if q.ID == 0 || q.PID == 0 || q.Flags != 0 || q.Data.Arch != unix.AUDIT_ARCH_X86_64 || (q.Data.NR != int32(unix.SYS_FSYNC) && q.Data.NR != int32(unix.SYS_EXIT_GROUP)) {
			o.fail(errors.New("unexpected fixed shutdown notification"))
			return
		}
		if o.snapshot().Continued+s.snapshot().OtherExits >= 8192 {
			o.fail(errors.New("shutdown notification bound exceeded"))
			return
		}
		selected := false
		if q.Data.NR == int32(unix.SYS_EXIT_GROUP) {
			selected, e = s.selectExit(q)
			if selected {
				s.exitHeld <- struct{}{}
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
				o.mu.Lock()
				o.armed = false
				o.snapshotValue.HeldID = q.ID
				o.mu.Unlock()
				deadline = time.Now().Add(operatorStoreHoldMax)
				o.held <- struct{}{}
				continue
			}
		}
		if errors.Is(e, unix.ENOENT) && errors.Is(quotaNotifyIO(o.fd, quotaNotifIDValid, unsafe.Pointer(&q.ID)), unix.ENOENT) {
			continue
		}
		if e != nil {
			o.fail(e)
			return
		}
		r := quotaNotifResponse{ID: q.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
		e = quotaNotifyIO(o.fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&r))
		if errors.Is(e, unix.ENOENT) {
			continue
		}
		if e != nil {
			o.fail(e)
			return
		}
		o.mu.Lock()
		if q.Data.NR == int32(unix.SYS_EXIT_GROUP) {
			s.value.OtherExits++
		} else {
			o.snapshotValue.Continued++
			if o.snapshotValue.HeldID != 0 {
				o.snapshotValue.OtherWhileHeld++
			}
		}
		o.mu.Unlock()
	}
}
