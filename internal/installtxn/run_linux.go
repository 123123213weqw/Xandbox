//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/123123213weqw/Xandbox/internal/launch"
	"golang.org/x/sys/unix"
)

func systemFS() (*filesystem, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || launch.SystemdService() != nil {
		return nil, ErrPlatform
	}
	if e := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); e != nil {
		return nil, e
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	return &filesystem{root: os.NewFile(uintptr(fd), "install-system-root")}, nil
}
func Apply(ctx context.Context, path string, expected uint64, request string) (Result, error) {
	var zero Result
	if expected != 0 || !requestPattern.MatchString(request) {
		return zero, ErrPolicy
	}
	f, e := systemFS()
	if e != nil {
		return zero, e
	}
	defer f.root.Close()
	raw, e := f.read(path, MaxPlan, 0600)
	if e != nil {
		return zero, e
	}
	plan, e := Decode(raw)
	if e != nil {
		return zero, e
	}
	if e = f.self(ctx, plan); e != nil {
		return zero, e
	}
	if e = f.mkdir(Root, 0700); e != nil {
		return zero, e
	}
	unlock, e := f.initialLock(ctx)
	if e != nil {
		return zero, e
	}
	manager := systemManager{f, f.managerCommand}
	load := func(ctx context.Context, p Plan, pending bool) (*prepared, func(), error) {
		self, e := launch.StaticServiceELF(p.Self)
		if e != nil {
			return nil, nil, e
		}
		self.Close()
		r, e := f.release(ctx, p, pending)
		if e != nil {
			return nil, nil, e
		}
		prepared, e := f.prepare(ctx, p, r)
		if e != nil {
			r.close()
			return nil, nil, e
		}
		return prepared, func() { prepared.close(); r.close() }, nil
	}
	t, e := f.installLocked(ctx, plan, request, manager, load)
	unlock()
	if e != nil {
		return zero, e
	}
	// Reconcile reacquires a read proof, then releases it BEFORE asking systemd
	// to run the commit gate. No exclusive lock/ExecStartPre self-deadlock.
	return reconcile(ctx, f, t.RequestID, manager)
}
func reconcile(ctx context.Context, f *filesystem, request string, manager serviceManager) (Result, error) {
	var zero Result
	if !requestPattern.MatchString(request) {
		return zero, ErrPolicy
	}
	unlock, e := f.existingLock(ctx, true)
	if e != nil {
		return zero, e
	}
	t, e := f.readTransaction("commit")
	if e == nil && t.RequestID != request {
		e = ErrConflict
	}
	if e == nil {
		e = f.self(ctx, t.Plan)
	}
	if e == nil {
		e = f.verifyTransaction(ctx, t)
	}
	if e == nil && t.Plan.Version == 2 {
		_, p, err := f.effectivePolicy(t, true)
		if err != nil {
			e = err
		} else if p.Revision != 1 {
			e = ErrConflict
		}
	}
	if e == nil {
		e = f.removeIntent(t)
	}
	unlock()
	if e != nil {
		return zero, e
	}
	if t.Plan.Version == 2 {
		managed, ok := manager.(managedServiceManager)
		if !ok {
			return zero, ErrPlatform
		}
		e = managed.reconcileManaged(ctx)
	} else {
		e = manager.reconcile(ctx)
	}
	if e != nil {
		return zero, e
	}
	if t.Plan.Version == 2 {
		yes, e := f.policyReceipt(ctx, t, manager, true)
		if e != nil {
			return zero, e
		}
		if !yes {
			return zero, ErrPlatform
		}
	}
	// A manager success without a fresh on-disk proof is not a durable receipt.
	unlock, e = f.existingLock(ctx, false)
	if e != nil {
		return zero, e
	}
	defer unlock()
	current, e := f.readTransaction("commit")
	if e != nil {
		return zero, e
	}
	if !bytes.Equal(encode(current), encode(t)) {
		return zero, ErrConflict
	}
	if e = f.verifyTransaction(ctx, t); e != nil {
		return zero, e
	}
	result, e := f.committedResult(t)
	if e != nil {
		return zero, e
	}
	if t.Plan.Version == 2 {
		yes, e := f.policyReceipt(ctx, t, manager, false)
		if e != nil {
			return zero, e
		}
		if !yes {
			return zero, ErrPlatform
		}
	}
	result.ManagerReconciled = true
	return result, nil
}
func Reconcile(ctx context.Context, request string) (Result, error) {
	if !requestPattern.MatchString(request) {
		return Result{}, ErrPolicy
	}
	f, e := systemFS()
	if e != nil {
		return Result{}, e
	}
	defer f.root.Close()
	manager := systemManager{f, f.managerCommand}
	unlock, e := f.existingLock(ctx, false)
	if e != nil {
		return Result{}, e
	}
	t, e := f.readTransaction("commit")
	unlock()
	if e != nil {
		return Result{}, e
	}
	if t.Plan.Version == 2 && request != t.RequestID {
		return reconcileRotation(ctx, f, request, manager)
	}
	return reconcile(ctx, f, request, manager)
}
func Status(ctx context.Context) (Result, error) {
	var zero Result
	f, e := systemFS()
	if e != nil {
		return zero, e
	}
	defer f.root.Close()
	return f.status(ctx, systemManager{f, f.managerCommand})
}
func (f *filesystem) status(ctx context.Context, manager serviceManager) (Result, error) {
	var zero Result
	// Observation never manufactures a missing transaction lock inode.
	unlock, e := f.existingLock(ctx, false)
	if e != nil {
		return zero, e
	}
	defer unlock()
	t, e := f.readTransaction("commit")
	if errors.Is(e, unix.ENOENT) {
		var pending transaction
		if pending, e = f.readTransaction("intent"); e != nil {
			return zero, e
		}
		if e = f.rootInventory(pending.Plan.Version, true); e != nil {
			return zero, e
		}
		return Result{Version: 1}, nil
	}
	if e != nil {
		return zero, e
	}
	if e = f.verifyTransaction(ctx, t); e != nil {
		return zero, e
	}
	result, e := f.committedResult(t)
	if e != nil {
		return zero, e
	}
	result.ManagerReconciled, e = manager.current(ctx)
	if e == nil && result.ManagerReconciled && t.Plan.Version == 2 {
		result.ManagerReconciled, e = f.policyReceipt(ctx, t, manager, false)
	}
	return result, e
}
func restrictGate() error {
	b, e := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if e != nil || len(b) > 64 {
		return ErrPlatform
	}
	last, e := strconv.Atoi(strings.TrimSpace(string(b)))
	if e != nil || last < 0 || last > 63 {
		return ErrPlatform
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); e != 0 {
		return e
	}
	if _, _, e := syscall.AllThreadsSyscall6(unix.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0, 0); e != 0 {
		return e
	}
	for cap := 0; cap <= last; cap++ {
		if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, uintptr(cap), 0); e != 0 {
			return e
		}
	}
	h := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return e
	}
	return launch.ServiceCapabilities(0)
}
func Verify(ctx context.Context) error {
	f, e := systemFS()
	if e != nil {
		return e
	}
	defer f.root.Close()
	if e = restrictGate(); e != nil {
		return e
	}
	if e = launch.ServicePlacement(unitRoot + "/.control"); e != nil {
		return e
	}
	raw, e := os.ReadFile(unitRoot + "/.control/cgroup.procs")
	if e != nil || len(raw) > 4096 || strings.TrimSpace(string(raw)) != strconv.Itoa(os.Getpid()) {
		return ErrPlatform
	}
	if e = launch.RejectServiceDescriptors(); e != nil {
		return e
	}
	// The read-only gate never creates a lock on an uncommitted/absent install.
	lock, e := f.open(Root+"/.lock", unix.O_RDONLY, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		e = unix.Flock(int(lock.Fd()), unix.LOCK_SH|unix.LOCK_NB)
		if e == nil {
			break
		}
		if !errors.Is(e, unix.EAGAIN) && !errors.Is(e, unix.EWOULDBLOCK) {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	t, e := f.readTransaction("commit")
	if e != nil {
		return e
	}
	if e = f.self(ctx, t.Plan); e != nil {
		return e
	}
	return f.verifyTransaction(ctx, t)
}
