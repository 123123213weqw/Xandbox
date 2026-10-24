//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
)

func rotationFixture(t *testing.T, pinSelf bool) (*filesystem, transaction, RotationPlan) {
	t.Helper()
	f, p, m := managedFixture(t)
	if pinSelf {
		path, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		in, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { in.Close() })
		st, e := in.Stat()
		if e != nil {
			t.Fatal(e)
		}
		sum, e := hashFile(context.Background(), in, st.Size())
		if e != nil {
			t.Fatal(e)
		}
		p.plan.Self.SHA256 = sum
		for i := range p.targets {
			if p.targets[i].file.Path == SelfPath {
				p.targets[i].file.SHA256 = sum
				p.targets[i].file.Bytes = st.Size()
				p.targets[i].source = in
				p.targets[i].data = nil
			}
		}
	}
	tx, e := applyModel(context.Background(), f, p, request(), m)
	if e != nil {
		t.Fatal(e)
	}
	return f, tx, rotationSource(t, f, tx, "/bootstrap/next-snapshot.json", 2)
}
func rotationSource(t *testing.T, f *filesystem, tx transaction, path string, epoch uint64) RotationPlan {
	t.Helper()
	_, p, e := f.effectivePolicy(tx, true)
	if e != nil {
		t.Fatal(e)
	}
	s := p.Snapshot
	s.Epoch = epoch
	s.Keys = append([]gateway.ClientKey(nil), s.Keys...)
	s.Keys[0].TokenSHA256 = digest([]byte(strings.Repeat(string(rune('c'+epoch)), 40)))
	b := encode(s)
	if os.MkdirAll(f.root.Name()+"/bootstrap", 0700) != nil {
		t.Fatal("fixture dir")
	}
	if os.WriteFile(f.root.Name()+path, b, 0600) != nil {
		t.Fatal("fixture source")
	}
	return RotationPlan{Version: 1, Policy: firecracker.Asset{Path: path, SHA256: digest(b)}}
}
func rotateModel(ctx context.Context, f *filesystem, tx transaction, p RotationPlan, expected uint64, req string, ready func() error) (gateway.PolicyEnvelope, error) {
	unlock, e := f.existingLock(ctx, true)
	if e != nil {
		return gateway.PolicyEnvelope{}, e
	}
	defer unlock()
	return f.rotationLocked(ctx, tx, p, expected, req, ready)
}
func TestRotationAtomicCommitKeepsIntentUntilActivationAndExactRetryNeedsNoSource(t *testing.T) {
	f, tx, p := rotationFixture(t, false)
	req := strings.Repeat("b", 32)
	before, e := f.read(Root+"/commit.json", 65536, 0600)
	if e != nil {
		t.Fatal(e)
	}
	got, e := rotateModel(context.Background(), f, tx, p, 1, req, func() error { return nil })
	if e != nil || got.Revision != 2 {
		t.Fatal("file transaction", e)
	}
	if yes, _ := f.exists(Root + "/rotation-intent.json"); !yes {
		t.Fatal("intent removed before ACK")
	}
	after, _ := f.read(Root+"/commit.json", 65536, 0600)
	if !bytes.Equal(before, after) {
		t.Fatal("initial commit rewritten")
	}
	for _, v := range tx.Files {
		if v.Path != gateway.ManagedPolicyPath && f.verify(context.Background(), v) != nil {
			t.Fatal("immutable target changed")
		}
	}
	os.Remove(f.root.Name() + p.Policy.Path)
	writes := 0
	f.hook = func(string) error { writes++; return nil }
	if _, e = rotateModel(context.Background(), f, tx, p, 1, req, nil); e != nil || writes != 0 {
		t.Fatal("postcommit retry reread source or persisted", e)
	}
	f.hook = nil
	if _, e = rotateModel(context.Background(), f, tx, p, 2, strings.Repeat("c", 32), nil); !errors.Is(e, ErrConflict) {
		t.Fatal("pending request replaced", e)
	}
	if _, e = rotateModel(context.Background(), f, tx, p, 1, tx.RequestID, nil); !errors.Is(e, ErrConflict) {
		t.Fatal("initial request ID reused")
	}
}

func TestRotationSelectedPersistenceCutsFreshHandleRecoveryAndStartupFence(t *testing.T) {
	for _, stage := range []string{"rotation-intent-written", "rotation-intent-synced", "rotation-intent-renamed", "rotation-intent-durable", "policy-written", "policy-synced", "policy-prepared", "policy-renamed", "policy-durable", "policy-confirmed"} {
		t.Run(stage, func(t *testing.T) {
			f, tx, p := rotationFixture(t, false)
			req := strings.Repeat("b", 32)
			hit := false
			f.hook = func(at string) error {
				if at == stage {
					hit = true
					return interrupted
				}
				return nil
			}
			if _, e := rotateModel(context.Background(), f, tx, p, 1, req, func() error { return nil }); !errors.Is(e, interrupted) || !hit {
				t.Fatal("cut not reached", e)
			}
			beforeAuthority := strings.HasPrefix(stage, "rotation-intent") || stage == "policy-written" || stage == "policy-synced" || stage == "policy-prepared"
			if beforeAuthority && f.verifyTransaction(context.Background(), tx) == nil {
				t.Fatal("pending startup accepted old policy")
			}
			if strings.HasPrefix(stage, "policy-") {
				os.Remove(f.root.Name() + p.Policy.Path)
			} // complete scratch or committed payload is sufficient
			root, e := os.Open(f.root.Name())
			if e != nil {
				t.Fatal(e)
			}
			defer root.Close()
			fresh := &filesystem{root: root}
			if _, e = rotateModel(context.Background(), fresh, tx, p, 1, req, nil); e != nil {
				t.Fatal("fresh-handle exact recovery", e)
			}
			if fresh.verifyTransaction(context.Background(), tx) != nil {
				t.Fatal("recovered policy proof")
			}
			if yes, _ := fresh.exists(Root + "/rotation-intent.json"); !yes {
				t.Fatal("file recovery stood in for ACK")
			}
		})
	}
}

type rotationModelManager struct {
	*managedModelManager
	activationCalls int
}

func (m *rotationModelManager) activateManaged(_ context.Context, revision uint64, _, _ string) (bool, error) {
	m.activationCalls++
	if m.onPolicy != nil {
		m.onPolicy(revision, true)
	}
	return m.active, nil
}
func TestRotationReconcileSourceAbsentRequiresACKThenRemovesOnlyMatchingIntent(t *testing.T) {
	f, tx, p := rotationFixture(t, true)
	req := strings.Repeat("b", 32)
	if _, e := rotateModel(context.Background(), f, tx, p, 1, req, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	os.Remove(f.root.Name() + p.Policy.Path)
	m := &rotationModelManager{managedModelManager: &managedModelManager{modelManager: &modelManager{}}}
	if _, e := reconcileRotation(context.Background(), f, req, m); e == nil {
		t.Fatal("missing ACK reported reconciled")
	}
	if yes, _ := f.exists(Root + "/rotation-intent.json"); !yes {
		t.Fatal("unconfirmed activation removed intent")
	}
	m.active = true
	got, e := reconcileRotation(context.Background(), f, req, m)
	if e != nil || got.Revision != 2 || !got.FilesCommitted || !got.ManagerReconciled || got.ProductionReady {
		t.Fatal("source-independent reconcile", e)
	}
	if yes, _ := f.exists(Root + "/rotation-intent.json"); yes {
		t.Fatal("matching intent survived ACK")
	}
	if _, e := reconcileRotation(context.Background(), f, req, m); e != nil {
		t.Fatal("lost final response retry", e)
	}
	if _, e := reconcile(context.Background(), f, tx.RequestID, m); !errors.Is(e, ErrConflict) {
		t.Fatal("old initial request operated on new policy", e)
	}
	if m.reconcileCalls != 0 {
		t.Fatal("policy recovery started/restarted main through initial reconcile")
	}
	next := rotationSource(t, f, tx, "/bootstrap/third.json", 3)
	if _, e := rotateModel(context.Background(), f, tx, next, 2, req, func() error { return nil }); !errors.Is(e, ErrConflict) {
		t.Fatal("last request reused for new epoch")
	}
	if _, e := rotateModel(context.Background(), f, tx, next, 2, strings.Repeat("c", 32), func() error { return nil }); e != nil {
		t.Fatal("next policy transaction", e)
	}
	if _, e := reconcileRotation(context.Background(), f, req, m); !errors.Is(e, ErrConflict) {
		t.Fatal("old request interfered with next intent", e)
	}
}

func TestRotationRejectsUnknownScratchAndBadSourceWithoutRepair(t *testing.T) {
	for _, kind := range []string{"source-hash", "unknown-policy-scratch", "unknown-intent-scratch", "unknown-intent", "unknown-file", "foreign-payload"} {
		t.Run(kind, func(t *testing.T) {
			f, tx, p := rotationFixture(t, false)
			var path string
			switch kind {
			case "source-hash":
				p.Policy.SHA256 = strings.Repeat("e", 64)
			case "unknown-policy-scratch":
				path = Root + "/.policy.next"
			case "unknown-intent-scratch":
				path = Root + "/.rotation-intent.next"
			case "unknown-intent":
				path = Root + "/rotation-intent.json"
			case "unknown-file":
				path = Root + "/foreign"
			case "foreign-payload":
				path = gateway.ManagedPolicyPath
			}
			if path != "" {
				if os.WriteFile(f.root.Name()+path, []byte("unrecognized"), 0600) != nil {
					t.Fatal("fixture")
				}
			}
			if _, e := rotateModel(context.Background(), f, tx, p, 1, strings.Repeat("b", 32), func() error { return nil }); e == nil {
				t.Fatal("foreign inventory/source accepted")
			}
			if path != "" {
				b, e := os.ReadFile(f.root.Name() + path)
				if e != nil || string(b) != "unrecognized" {
					t.Fatal("unknown bytes repaired/removed")
				}
			}
		})
	}
}

func TestManagedFinalReceiptRechecksPolicyAfterActivationObservation(t *testing.T) {
	f, tx, _ := rotationFixture(t, true)
	m := &rotationModelManager{managedModelManager: &managedModelManager{modelManager: &modelManager{}, active: true}}
	m.onPolicy = func(revision uint64, reconcile bool) {
		if reconcile && revision == 1 {
			_, b, _ := writeManagedModelNext(t, f, tx)
			publishModelPolicy(t, f, b)
		}
		if !reconcile && revision == 2 {
			m.active = false
		}
	}
	if _, e := reconcile(context.Background(), f, tx.RequestID, m); e == nil {
		t.Fatal("ACK for an old target certified a newer file revision")
	}
}
