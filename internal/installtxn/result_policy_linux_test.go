//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
)

// Original owned-file result-cold model and optional real TEST-ELF self pin.
// Model programs/manager ACK are NOT real builder/ABI/systemd/KVM qualification.
func resultPolicyFixture(t *testing.T, self bool) (resultBootstrap, resultTransaction, RotationPlan) {
	t.Helper()
	b, p := resultColdModel(t)
	if self {
		pinModelSelf(t, p)
	}
	ctx, cancel := resultTestContext()
	defer cancel()
	tx, e := resultModelInstall(ctx, b, p, request(), &modelManager{})
	if e != nil {
		t.Fatal(e)
	}
	return b, tx, resultPolicySource(t, b, tx, "/bootstrap/result-policy-next.json", 2)
}
func resultPolicySource(t *testing.T, b resultBootstrap, tx resultTransaction, path string, epoch uint64) RotationPlan {
	t.Helper()
	_, p, e := b.effectivePolicy(tx, true)
	if e != nil {
		t.Fatal(e)
	}
	s := p.Snapshot
	s.Epoch = epoch
	s.Keys = append([]gateway.ClientKey(nil), s.Keys...)
	s.Keys[0].TokenSHA256 = digest([]byte(strings.Repeat(string(rune('c'+epoch)), 40)))
	raw := encode(s)
	if e = os.MkdirAll(b.fs.root.Name()+"/bootstrap", 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(b.fs.root.Name()+path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return RotationPlan{Version: 1, Policy: firecracker.Asset{Path: path, SHA256: digest(raw)}}
}
func resultPolicyLockedModel(ctx context.Context, b resultBootstrap, tx resultTransaction, p RotationPlan, expected uint64, id string, ready func() error) (gateway.PolicyEnvelope, error) {
	done, e := b.fs.ordinaryOperationLock(ctx, false)
	if e != nil {
		return gateway.PolicyEnvelope{}, e
	}
	defer done()
	unlock, e := b.fs.existingLock(ctx, true)
	if e != nil {
		return gateway.PolicyEnvelope{}, e
	}
	defer unlock()
	return b.rotationLocked(ctx, tx, p, expected, id, ready)
}
func resultPolicyManager() *rotationModelManager {
	return &rotationModelManager{managedModelManager: &managedModelManager{modelManager: &modelManager{}, active: true}}
}

func TestResultPolicyMaintenanceConsumesActualVersionedBaseAndPreservesState(t *testing.T) {
	b, tx, p := resultPolicyFixture(t, true)
	ctx, cancel := resultTestContext()
	defer cancel()
	original := mustResultCommit(t, b.fs)
	backend, e := os.ReadFile(b.fs.root.Name() + Root + "/backend.json")
	if e != nil {
		t.Fatal(e)
	}
	// Opaque preservation sentinels only, not a claim of valid retained-state ABI.
	preserved := b.fs.root.Name() + stateDir + "/results/preserved.json"
	if e = os.MkdirAll(b.fs.root.Name()+stateDir+"/results", 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(preserved, []byte("opaque-state-must-not-be-repaired"), 0600); e != nil {
		t.Fatal(e)
	}
	m := resultPolicyManager()
	held := 0
	m.onPolicy = func(revision uint64, reconcile bool) {
		if !reconcile || revision < 2 {
			return
		}
		wait, done := context.WithTimeout(ctx, 30*time.Millisecond)
		defer done()
		unlock, err := b.fs.operationLock(wait, true)
		if err == nil {
			unlock()
			t.Fatal("activation lost original operation lease")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		held++
	}
	id := strings.Repeat("b", 32)
	got, e := b.reconfigurePolicyOperation(ctx, p, 1, id, m)
	if e != nil || got.Revision != 2 || !got.ManagerReconciled || !got.FilesCommitted || got.ProductionReady || held == 0 {
		t.Fatal("consumed versioned policy producer/ACK", got, e)
	}
	if _, e = b.fs.readTransaction("commit"); e == nil {
		t.Fatal("legacy reader accepted actual2")
	}
	if _, e = b.startupFilesLocked(ctx); e != nil {
		t.Fatal("actual2 startup rejected current policy", e)
	}
	if _, e = b.reconcile(ctx, tx.RequestID, m); !errors.Is(e, ErrConflict) {
		t.Fatal("initial request normalized to rotated request", e)
	}
	if e = os.Remove(b.fs.root.Name() + p.Policy.Path); e != nil {
		t.Fatal(e)
	}
	if _, e = b.reconcilePolicyOperation(ctx, id, m); e != nil {
		t.Fatal("source-independent lost response retry", e)
	}
	if _, e = b.reconfigurePolicyOperation(ctx, p, 1, id, m); e != nil {
		t.Fatal("exact source-independent producer retry", e)
	}
	next := resultPolicySource(t, b, tx, "/bootstrap/result-policy-third.json", 3)
	if _, e = b.reconfigurePolicyOperation(ctx, next, 2, id, m); !errors.Is(e, ErrConflict) {
		t.Fatal("old request reblessed new epoch", e)
	}
	if _, e = b.reconfigurePolicyOperation(ctx, next, 2, strings.Repeat("c", 32), m); e != nil {
		t.Fatal("next CURRENT policy transition", e)
	}
	if _, e = b.reconcilePolicyOperation(ctx, id, m); !errors.Is(e, ErrConflict) {
		t.Fatal("old request restored stale authority", e)
	}
	if !bytes.Equal(original, mustResultCommit(t, b.fs)) {
		t.Fatal("immutable2 genesis rewritten")
	}
	now, e := os.ReadFile(b.fs.root.Name() + Root + "/backend.json")
	if e != nil || !bytes.Equal(now, backend) {
		t.Fatal("FULLConfig4 binding changed", e)
	}
	now, e = os.ReadFile(preserved)
	if e != nil || string(now) != "opaque-state-must-not-be-repaired" {
		t.Fatal("retained bytes changed", e)
	}
	if m.reconcileCalls != 0 {
		t.Fatal("policy update restarted main/initial install")
	}
}

func TestResultPolicyMaintenanceEveryOriginalDurabilityCutRetriesActualVersion(t *testing.T) {
	stages := []string{"rotation-intent-written", "rotation-intent-synced", "rotation-intent-renamed", "rotation-intent-durable", "policy-written", "policy-synced", "policy-prepared", "policy-renamed", "policy-durable", "policy-confirmed", "policy-intent-removed"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			b, tx, p := resultPolicyFixture(t, stage == "policy-intent-removed")
			ctx, cancel := resultTestContext()
			defer cancel()
			original := mustResultCommit(t, b.fs)
			hit := false
			id := strings.Repeat("b", 32)
			b.fs.hook = func(at string) error {
				if at == stage {
					hit = true
					return interrupted
				}
				return nil
			}
			_, e := resultPolicyLockedModel(ctx, b, tx, p, 1, id, func() error { return nil })
			if stage == "policy-intent-removed" && e == nil {
				_, e = b.reconcilePolicyOperation(ctx, id, resultPolicyManager())
			}
			if !hit || !errors.Is(e, interrupted) {
				t.Fatal("original durability cut not reached", stage, e)
			}
			b.fs.hook = nil
			if strings.HasPrefix(stage, "policy-") {
				if e = os.Remove(b.fs.root.Name() + p.Policy.Path); e != nil {
					t.Fatal(e)
				}
			}
			root, e := os.Open(b.fs.root.Name())
			if e != nil {
				t.Fatal(e)
			}
			defer root.Close()
			fresh := resultBootstrap{fs: &filesystem{root: root}, programs: b.programs} // explicitly MODEL only
			actual, e := fresh.fs.readResultTransaction("commit")
			if e != nil {
				t.Fatal(e)
			}
			if _, e = resultPolicyLockedModel(ctx, fresh, actual, p, 1, id, nil); e != nil {
				t.Fatal("exact source/WAL retry", e)
			}
			if e = fresh.verifyTargets(ctx, actual, true); e != nil {
				t.Fatal("full actual2 target proof", e)
			}
			if !bytes.Equal(original, mustResultCommit(t, fresh.fs)) {
				t.Fatal("retry changed original2 genesis")
			}
			if stage == "policy-intent-removed" {
				if _, e = fresh.reconcilePolicyOperation(ctx, id, resultPolicyManager()); e != nil {
					t.Fatal("lost final ACK retry", e)
				}
			}
		})
	}
}

func TestResultPolicyMaintenanceFailedACKKeepsIntentAndOriginalAuthority(t *testing.T) {
	b, tx, p := resultPolicyFixture(t, true)
	ctx, cancel := resultTestContext()
	defer cancel()
	id := strings.Repeat("b", 32)
	original := mustResultCommit(t, b.fs)
	if _, e := resultPolicyLockedModel(ctx, b, tx, p, 1, id, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(b.fs.root.Name() + p.Policy.Path); e != nil {
		t.Fatal(e)
	}
	m := resultPolicyManager()
	m.active = false
	if _, e := b.reconcilePolicyOperation(ctx, id, m); e == nil {
		t.Fatal("missing actual ACK reported success")
	}
	if yes, e := b.fs.exists(Root + "/rotation-intent.json"); e != nil || !yes {
		t.Fatal("uncertain activation erased intent", e)
	}
	if !bytes.Equal(original, mustResultCommit(t, b.fs)) {
		t.Fatal("failure rewrote genesis")
	}
	m.active = true
	got, e := b.reconcilePolicyOperation(ctx, id, m)
	if e != nil || got.Revision != 2 || !got.ManagerReconciled || got.ProductionReady {
		t.Fatal("owned source-free reconcile", got, e)
	}
	if yes, e := b.fs.exists(Root + "/rotation-intent.json"); e != nil || yes {
		t.Fatal("matching confirmed intent survived", e)
	}
}

func TestResultPolicyMaintenanceRefusalsNeverNormalizeOrRepair(t *testing.T) {
	for _, name := range []string{"source-hash", "policy-scratch", "intent-scratch", "foreign-intent", "foreign-policy", "foreign-file", "auth-pin", "full-backend-pin", "program-gate", "runtime-namespace", "legacy-commit"} {
		t.Run(name, func(t *testing.T) {
			b, tx, p := resultPolicyFixture(t, true)
			ctx, cancel := resultTestContext()
			defer cancel()
			if name == "legacy-commit" {
				f, old, op := rotationFixture(t, true)
				b = resultBootstrap{fs: f, programs: b.programs}
				p = op
				if _, e := f.readTransaction("commit"); e != nil {
					t.Fatal("actual legacy fixture invalid", e)
				}
				if old.Version != 1 {
					t.Fatal("legacy fixture not original1")
				}
			}
			original := mustResultCommit(t, b.fs)
			var path string
			switch name {
			case "source-hash":
				p.Policy.SHA256 = strings.Repeat("e", 64)
			case "policy-scratch":
				path = Root + "/.policy.next"
			case "intent-scratch":
				path = Root + "/.rotation-intent.next"
			case "foreign-intent":
				path = Root + "/rotation-intent.json"
			case "foreign-policy":
				path = gateway.ManagedPolicyPath
			case "foreign-file":
				path = Root + "/unknown"
			case "auth-pin":
				path = Root + "/auth.json"
			case "full-backend-pin":
				path = Root + "/backend.json"
			case "program-gate":
				b.programs = func(context.Context, Plan, Release) error { return ErrPolicy }
			case "runtime-namespace":
				if e := os.Mkdir(b.fs.root.Name()+"/etc/xandbox-runtime-result-policy-test", 0700); e != nil {
					t.Fatal(e)
				}
			}
			if path != "" {
				if e := os.WriteFile(b.fs.root.Name()+path, []byte("unrecognized-original-bytes"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			m := resultPolicyManager()
			if _, e := b.reconfigurePolicyOperation(ctx, p, 1, strings.Repeat("b", 32), m); e == nil {
				t.Fatal("unowned/version/namespace/policy condition accepted", name)
			}
			if m.activationCalls != 0 {
				t.Fatal("refusal performed activation")
			}
			if !bytes.Equal(original, mustResultCommit(t, b.fs)) {
				t.Fatal("refusal repaired/reblessed original commit")
			}
			if path != "" {
				raw, e := os.ReadFile(b.fs.root.Name() + path)
				if e != nil || string(raw) != "unrecognized-original-bytes" {
					t.Fatal("refusal repaired/deleted bytes", e)
				}
			}
			_ = tx
		})
	}
}
