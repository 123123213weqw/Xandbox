//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"golang.org/x/sys/unix"
	"os"
	"strconv"
	"strings"
)

// Explicit SAME-SOURCE cold bootstrap. No default opt-in, existing-state
// migration, service choice, task argv, host fallback or automatic rollback.
func ApplyResults(ctx context.Context, path string, expected uint64, request string) (Result, error) {
	var zero Result
	if !resultBounded(ctx) || expected != 0 || !requestPattern.MatchString(request) {
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
	if e != nil || plan.Version != 2 {
		return zero, ErrPolicy
	}
	if e = f.self(ctx, plan); e != nil {
		return zero, e
	}
	if e = f.initialInstallRoot(ctx); e != nil {
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
		prepared, e := f.prepareResults(ctx, p, r)
		if e != nil {
			r.close()
			return nil, nil, e
		}
		if e = resultSourceBuilds(ctx, prepared, r); e != nil {
			prepared.close()
			r.close()
			return nil, nil, e
		}
		return prepared, func() { prepared.close(); r.close() }, nil
	}
	return newResultBootstrap(f).installOperation(ctx, plan, request, manager, load)
}

func (b resultBootstrap) installOperation(ctx context.Context, plan Plan, request string, manager serviceManager, load func(context.Context, Plan, bool) (*prepared, func(), error)) (Result, error) {
	f := b.fs
	var zero Result
	operationDone, e := f.ordinaryInitialOperationLock(ctx)
	if e != nil {
		return zero, e
	}
	defer operationDone()
	unlock, e := f.existingLock(ctx, true)
	if e != nil {
		return zero, e
	}
	if e = f.noPolicyRecovery(); e != nil {
		unlock()
		return zero, e
	}
	t, e := b.installLocked(ctx, plan, request, manager, load)
	unlock()
	if e != nil {
		return zero, e
	}
	// Reconcile reacquires a read proof, then releases it BEFORE asking systemd
	// to run the commit gate. No exclusive lock/ExecStartPre self-deadlock.
	return b.reconcile(ctx, t.RequestID, manager)
}
func (b resultBootstrap) reconcile(ctx context.Context, request string, manager serviceManager) (Result, error) {
	f := b.fs
	var zero Result
	if !requestPattern.MatchString(request) {
		return zero, ErrPolicy
	}
	unlock, e := f.existingLock(ctx, true)
	if e != nil {
		return zero, e
	}
	t, e := f.readResultTransaction("commit")
	if e == nil && t.RequestID != request {
		e = ErrConflict
	}
	if e == nil {
		e = f.self(ctx, t.Plan)
	}
	if e == nil {
		e = b.verifyTargets(ctx, t, true)
	}
	if e == nil && t.Plan.Version == 2 {
		_, p, err := b.effectivePolicy(t, true)
		if err != nil {
			e = err
		} else if p.Revision != 1 {
			e = ErrConflict
		}
	}
	if e == nil {
		e = f.removeResultIntent(t)
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
		yes, e := b.policyReceipt(ctx, t, manager, true)
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
	current, e := f.readResultTransaction("commit")
	if e != nil {
		return zero, e
	}
	if !bytes.Equal(encode(current), encode(t)) {
		return zero, ErrConflict
	}
	if e = b.verifyTargets(ctx, t, true); e != nil {
		return zero, e
	}
	result, e := b.committedResult(t)
	if e != nil {
		return zero, e
	}
	if t.Plan.Version == 2 {
		yes, e := b.policyReceipt(ctx, t, manager, false)
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
func ReconcileResults(ctx context.Context, request string) (Result, error) {
	if !resultBounded(ctx) || !requestPattern.MatchString(request) {
		return Result{}, ErrPolicy
	}
	f, e := systemFS()
	if e != nil {
		return Result{}, e
	}
	defer f.root.Close()
	done, e := f.ordinaryOperationLock(ctx, false)
	if e != nil {
		return Result{}, e
	}
	defer done()
	if e = f.noPolicyRecovery(); e != nil {
		return Result{}, e
	}
	return newResultBootstrap(f).reconcile(ctx, request, systemManager{f, f.managerCommand})
}

func StatusResults(ctx context.Context) (Result, error) {
	if !resultBounded(ctx) {
		return Result{}, ErrPolicy
	}
	var zero Result
	f, e := systemFS()
	if e != nil {
		return zero, e
	}
	defer f.root.Close()
	return newResultBootstrap(f).status(ctx, systemManager{f, f.managerCommand})
}
func (b resultBootstrap) status(ctx context.Context, manager serviceManager) (Result, error) {
	f := b.fs
	var zero Result
	// Observation never manufactures a missing transaction lock inode.
	unlock, e := f.existingLock(ctx, false)
	if e != nil {
		return zero, e
	}
	defer unlock()
	if e = f.runtimeNamespaceVeto(ctx); e != nil {
		return zero, e
	}
	t, e := f.readResultTransaction("commit")
	if errors.Is(e, unix.ENOENT) {
		var pending resultTransaction
		if pending, e = f.readResultTransaction("intent"); e != nil {
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
	if e = b.verifyTargets(ctx, t, true); e != nil {
		return zero, e
	}
	result, e := b.committedResult(t)
	if e != nil {
		return zero, e
	}
	result.ManagerReconciled, e = manager.current(ctx)
	if e == nil && result.ManagerReconciled && t.Plan.Version == 2 {
		result.ManagerReconciled, e = b.policyReceipt(ctx, t, manager, false)
	}
	return result, e
}
func VerifyResults(ctx context.Context) error {
	if !resultBounded(ctx) {
		return ErrPolicy
	}
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
	// The gate uses the original read-only SH lock, never a new inode.
	unlock, e := f.startupReadLock(ctx)
	if e != nil {
		return e
	}
	defer unlock()
	t, e := newResultBootstrap(f).startupFilesLocked(ctx)
	if e != nil {
		return e
	}
	return f.self(ctx, t.Plan)
}

func (b resultBootstrap) startupFilesLocked(ctx context.Context) (resultTransaction, error) {
	f := b.fs
	var zero resultTransaction
	if e := f.runtimeNamespaceVeto(ctx); e != nil {
		return zero, e
	}
	if e := ctx.Err(); e != nil {
		return zero, e
	}
	for _, root := range []string{runtimeFilesRoot, runtimeDrainRoot, runtimeStopRoot, runtimeWorkStopRoot, runtimeWorkStopAnchor, runtimeWorkStopAnchorScratch, runtimeCloseRoot, runtimeCloseAnchor, runtimeCloseAnchorScratch, runtimeResultsCloseRoot, runtimeResultsCloseAnchor, runtimeResultsCloseAnchorScratch, runtimeResultsStopRoot} {
		if yes, e := f.exists(root); e != nil {
			return zero, e
		} else if yes {
			return zero, ErrInventory
		}
	}
	t, e := f.readResultTransaction("commit")
	if e != nil {
		return zero, e
	}
	if e = b.verifyTargets(ctx, t, true); e != nil {
		return zero, e
	}
	return t, nil
}

func resultBounded(ctx context.Context) bool { _, ok := ctx.Deadline(); return ok && ctx.Err() == nil }
func (b resultBootstrap) committedResult(t resultTransaction) (Result, error) {
	_, p, e := b.effectivePolicy(t, true)
	if e != nil {
		return Result{}, e
	}
	return Result{Version: 1, Revision: p.Revision, FilesCommitted: true}, nil
}
func (b resultBootstrap) policyReceipt(ctx context.Context, t resultTransaction, m serviceManager, reconcile bool) (bool, error) {
	managed, ok := m.(managedServiceManager)
	if !ok {
		return false, ErrPlatform
	}
	_, p, e := b.effectivePolicy(t, true)
	if e != nil {
		return false, e
	}
	pin, e := gateway.SnapshotDigest(p.Snapshot)
	if e != nil {
		return false, e
	}
	art, e := descriptor(t.Release)
	if e != nil {
		return false, e
	}
	return managed.policy(ctx, p.Revision, pin, art["gateway"].SHA256, reconcile)
}
