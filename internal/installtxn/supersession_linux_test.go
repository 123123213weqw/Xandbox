//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/gateway"
)

// Anchored shadow files/locks are real; manager/ACK and current-state effects
// are MODELED. Real gateway confirmation has separate store tests. No root CLI,
// systemd, positive kernel-empty, TLS child or KVM acceptance is implied here.
type supModel struct {
	high               uint64
	confirms, advances int
}

func supPrimitives(t *testing.T, f *filesystem, tx transaction, m *recoveryModelManager, state *supModel) (policyAdvance, policyAdvance) {
	t.Helper()
	check := func(c gateway.Config, auth, payload []byte, base string) (gateway.PolicyEnvelope, error) {
		if !m.inside {
			t.Fatal("maintenance primitive outside stopped ingress scope")
		}
		b, e := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
		if e != nil || !bytes.Equal(b, payload) || base != digest(encode(tx)) || digest(auth) != tx.Plan.Auth.SHA256 {
			t.Fatal("current authority overwritten before state proof")
		}
		return gateway.DecodeManagedEnvelope(c, payload, base)
	}
	advance := func(c gateway.Config, a, b []byte, base string) error {
		p, e := check(c, a, b, base)
		if e != nil {
			return e
		}
		state.advances++
		if p.Revision != state.high && p.Revision != state.high+1 {
			return ErrConflict
		}
		state.high = p.Revision
		return nil
	}
	confirm := func(c gateway.Config, a, b []byte, base string) error {
		p, e := check(c, a, b, base)
		if e != nil {
			return e
		}
		state.confirms++
		if p.Revision != state.high {
			return ErrConflict
		}
		return nil
	}
	return advance, confirm
}
func supSource(t *testing.T, f *filesystem, tx transaction, path string, epoch uint64) RotationPlan {
	t.Helper()
	c, base, e := f.rotationBase(tx)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
	if e != nil {
		t.Fatal(e)
	}
	env, e := gateway.DecodeManagedEnvelope(c, raw, base)
	if e != nil {
		t.Fatal(e)
	}
	s := env.Snapshot
	s.Epoch = epoch
	s.Keys = append([]gateway.ClientKey(nil), s.Keys...)
	s.Keys[0].TokenSHA256 = digest([]byte("fresh-test-only-authority-" + path))
	b := encode(s)
	if e = os.WriteFile(f.root.Name()+path, b, 0600); e != nil {
		t.Fatal(e)
	}
	p := RotationPlan{Version: 1}
	p.Policy.Path = path
	p.Policy.SHA256 = digest(b)
	return p
}
func supFixture(t *testing.T, recovery bool) (*filesystem, transaction, RotationPlan, *recoveryModelManager, *supModel, uint64, string, policyAdvance, policyAdvance) {
	t.Helper()
	ctx := context.Background()
	var f *filesystem
	var tx transaction
	var abandoned RotationPlan
	var m *recoveryModelManager
	var expected uint64
	var replaces string
	if recovery {
		f, tx, abandoned, m, _, _ = recoveryFixture(t)
		expected = 2
		replaces = strings.Repeat("c", 32)
	} else {
		f, tx, abandoned = rotationFixture(t, true)
		expected = 1
		replaces = strings.Repeat("b", 32)
		m = &recoveryModelManager{rotationModelManager: &rotationModelManager{managedModelManager: &managedModelManager{modelManager: &modelManager{}}}, t: t, fs: f, allowACK: true}
	}
	next := supSource(t, f, tx, "/bootstrap/replacement.json", expected+1)
	stage := "rotation-intent-durable"
	if recovery {
		stage = "policy-recovery-durable"
	}
	f.hook = func(at string) error {
		if at == stage {
			return interrupted
		}
		return nil
	}
	var e error
	if recovery {
		_, e = recoveryOperation(ctx, f, abandoned, 2, replaces, strings.Repeat("b", 32), m, func(gateway.Config, []byte, []byte, string) error {
			t.Fatal("advance before declaration cut")
			return ErrPolicy
		})
	} else {
		_, e = rotateModel(ctx, f, tx, abandoned, 1, replaces, func() error { return nil })
	}
	if !errors.Is(e, interrupted) {
		t.Fatal("proposal cut", e)
	}
	f.hook = nil
	if e = os.Remove(f.root.Name() + abandoned.Policy.Path); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(f.root.Name()+Root+"/.policy.next", []byte("opaque partial abandoned proposal data"), 0600); e != nil {
		t.Fatal(e)
	}
	state := &supModel{high: 1}
	advance, confirm := supPrimitives(t, f, tx, m, state)
	return f, tx, next, m, state, expected, replaces, advance, confirm
}
func TestSupersessionMissingAbandonedSourcesKeepsUnconsumedEpochAndExactReceipt(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal-first", true: "recovery"}[recovery], func(t *testing.T) {
			f, tx, p, m, state, n, old, advance, confirm := supFixture(t, recovery)
			req := strings.Repeat("d", 32)
			if e := f.verifyTransaction(context.Background(), tx); e == nil {
				t.Fatal("pending predecessor startup allowed")
			}
			out, e := supersessionOperation(context.Background(), f, p, n, req, old, m, advance, confirm)
			if e != nil || out.Revision != n+1 || !out.ManagerReconciled || !out.FilesCommitted || out.ProductionReady {
				t.Fatal("replacement receipt", e)
			}
			if state.high != n || state.confirms == 0 || (!recovery && state.advances != 0) {
				t.Fatal("unconsumed proposal advanced durable epoch")
			}
			if f.verifyTransaction(context.Background(), tx) != nil {
				t.Fatal("final installed proof")
			}
			for _, name := range []string{"policy-supersession.json", ".policy-supersession.next", "policy-recovery.json", "rotation-intent.json", ".rotation-intent.next", ".policy.next"} {
				if yes, _ := f.exists(Root + "/" + name); yes {
					t.Fatal("unfinished metadata", name)
				}
			}
			if e = os.Remove(f.root.Name() + p.Policy.Path); e != nil {
				t.Fatal(e)
			}
			stops := m.maintenanceCalls
			if _, e = supersessionOperation(context.Background(), f, p, n, req, old, m, advance, confirm); e != nil || stops != m.maintenanceCalls {
				t.Fatal("source-free lost receipt", e)
			}
		})
	}
}

var supersessionStages = []string{"policy-supersession-written", "policy-supersession-synced", "policy-supersession-renamed", "policy-supersession-durable", "supersession-current-confirmed", "supersession-discard-ready", "supersession-proposal-discarded", "supersession-intent-written", "supersession-intent-synced", "supersession-intent-renamed", "supersession-intent-durable", "supersession-policy-written", "supersession-policy-synced", "supersession-policy-prepared", "policy-renamed", "policy-durable", "supersession-files-confirmed", "supersession-record-removed", "policy-intent-removed"}

func TestSupersessionEveryBoundaryRetriesExactAndFencesPredecessor(t *testing.T) {
	for _, stage := range supersessionStages {
		t.Run(stage, func(t *testing.T) {
			f, tx, p, m, state, n, old, advance, confirm := supFixture(t, false)
			req := strings.Repeat("d", 32)
			hit := false
			f.hook = func(at string) error {
				if at == stage {
					hit = true
					return interrupted
				}
				return nil
			}
			if _, e := supersessionOperation(context.Background(), f, p, n, req, old, m, advance, confirm); !errors.Is(e, interrupted) || !hit {
				t.Fatal("cut not reached", e)
			}
			f.hook = nil
			if stage == "supersession-policy-written" || stage == "supersession-policy-synced" || stage == "supersession-policy-prepared" || stage == "policy-renamed" || stage == "policy-durable" || stage == "supersession-files-confirmed" || stage == "supersession-record-removed" || stage == "policy-intent-removed" {
				os.Remove(f.root.Name() + p.Policy.Path)
			}
			raw, _ := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
			c, base, _ := f.rotationBase(tx)
			env, _ := gateway.DecodeManagedEnvelope(c, raw, base)
			if env.Revision == n && f.verifyTransaction(context.Background(), tx) == nil {
				t.Fatal("old policy revival across cut")
			}
			if _, e := supersessionOperation(context.Background(), f, p, n, req, old, m, advance, confirm); e != nil {
				t.Fatal("exact retry", e)
			}
			if state.high != n || state.advances != 0 {
				t.Fatal("proposal consumed by retry")
			}
		})
	}
}
func TestSupersessionRepeatedUncommittedRequestsNeedNoAbandonedKeysOrHistory(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "recovery"}[recovery], func(t *testing.T) {
			f, tx, p, m, state, n, old, advance, confirm := supFixture(t, recovery)
			for _, req := range []string{strings.Repeat("d", 32), strings.Repeat("e", 32), strings.Repeat("f", 32)} {
				f.hook = func(at string) error {
					if at == "policy-supersession-durable" {
						return interrupted
					}
					return nil
				}
				if _, e := supersessionOperation(context.Background(), f, p, n, req, old, m, advance, confirm); !errors.Is(e, interrupted) {
					t.Fatal("uncommitted cut", e)
				}
				f.hook = nil
				os.Remove(f.root.Name() + p.Policy.Path)
				p = supSource(t, f, tx, "/bootstrap/next-"+req[:1]+".json", n+1)
				old = req
				names, _ := f.names(Root)
				if len(names) > 15 {
					t.Fatal("metadata history expanded")
				}
			}
			out, e := supersessionOperation(context.Background(), f, p, n, strings.Repeat("1", 32), old, m, advance, confirm)
			if e != nil || out.Revision != n+1 || state.high != n {
				t.Fatal("repeated replacement", e)
			}
		})
	}
}
func TestSupersessionRecoveryFutureIntentFencesBeforeOldJournalRemoval(t *testing.T) {
	for _, stage := range []string{"supersession-predecessor-durable", "supersession-intent-written", "supersession-intent-renamed", "supersession-intent-durable", "recovery-record-removed"} {
		t.Run(stage, func(t *testing.T) {
			f, tx, p, m, state, n, old, advance, confirm := supFixture(t, true)
			req := strings.Repeat("d", 32)
			hit := false
			f.hook = func(at string) error {
				if at == stage {
					hit = true
					return interrupted
				}
				return nil
			}
			if _, e := supersessionOperation(context.Background(), f, p, n, req, old, m, advance, confirm); !errors.Is(e, interrupted) || !hit {
				t.Fatal("settlement cut", e)
			}
			f.hook = nil
			if f.verifyTransaction(context.Background(), tx) == nil {
				t.Fatal("old current policy could start during recovery settlement")
			}
			os.Remove(f.root.Name() + p.Policy.Path)
			next := supSource(t, f, tx, "/bootstrap/later.json", n+1)
			if _, e := supersessionOperation(context.Background(), f, next, n, strings.Repeat("e", 32), req, m, advance, confirm); e != nil || state.high != n {
				t.Fatal("later replacement of interrupted declaration", e)
			}
		})
	}
}
func TestSupersessionCommittedReplacementCannotReuseEpochAndRecoveryConsumesIt(t *testing.T) {
	f, tx, p, m, state, n, old, advance, confirm := supFixture(t, false)
	req := strings.Repeat("d", 32)
	m.allowACK = false
	if _, e := supersessionOperation(context.Background(), f, p, n, req, old, m, advance, confirm); e == nil {
		t.Fatal("missing real ACK declared success")
	}
	future := supSource(t, f, tx, "/bootstrap/later.json", n+2)
	if _, e := supersessionOperation(context.Background(), f, p, n, strings.Repeat("e", 32), req, m, advance, confirm); e == nil {
		t.Fatal("committed epoch reused")
	}
	m.allowACK = true
	out, e := recoveryOperation(context.Background(), f, future, n+1, strings.Repeat("e", 32), req, m, advance)
	if e != nil || out.Revision != n+2 || state.high != n+1 {
		t.Fatal("committed replacement recovery", e)
	}
}
func TestSupersessionRejectsBadCASForeignInventoryAndFailedExistingStateProof(t *testing.T) {
	for _, kind := range []string{"expected", "request", "old-request", "source", "foreign", "intent-scratch", "recovery-scratch", "scratch-link", "scratch-hardlink", "scratch-mode", "confirm", "missing-state", "already-consumed", "advance"} {
		t.Run(kind, func(t *testing.T) {
			f, _, p, m, state, n, old, advance, confirm := supFixture(t, kind == "advance")
			req := strings.Repeat("d", 32)
			switch kind {
			case "expected":
				n++
			case "request":
				req = old
			case "old-request":
				old = strings.Repeat("f", 32)
			case "source":
				p.Policy.SHA256 = strings.Repeat("f", 64)
			case "missing-state":
				state.high = 0
			case "already-consumed":
				state.high = n + 1
			case "confirm":
				confirm = func(gateway.Config, []byte, []byte, string) error { return interrupted }
			case "advance":
				advance = func(gateway.Config, []byte, []byte, string) error { return interrupted }
			case "scratch-link":
				os.Remove(f.root.Name() + Root + "/.policy.next")
				os.Symlink("gateway-policy.json", f.root.Name()+Root+"/.policy.next")
			case "scratch-hardlink":
				os.Remove(f.root.Name() + Root + "/.policy.next")
				os.Link(f.root.Name()+gateway.ManagedPolicyPath, f.root.Name()+Root+"/.policy.next")
			case "scratch-mode":
				os.Chmod(f.root.Name()+Root+"/.policy.next", 0644)
			default:
				name := map[string]string{"foreign": "foreign", "intent-scratch": ".rotation-intent.next", "recovery-scratch": ".policy-recovery.next"}[kind]
				os.WriteFile(f.root.Name()+Root+"/"+name, []byte("foreign"), 0600)
			}
			before, _ := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
			if _, e := supersessionOperation(context.Background(), f, p, n, req, old, m, advance, confirm); e == nil {
				t.Fatal("invalid replacement accepted")
			}
			after, _ := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
			if !bytes.Equal(before, after) || m.activationCalls != 0 {
				t.Fatal("rejected request published/activated")
			}
		})
	}
}

func TestSupersessionPriorSettlementCutDoesNotPretendNextRequestWasDeclared(t *testing.T) {
	f, tx, p, m, _, n, old, advance, confirm := supFixture(t, false)
	d, eReq := strings.Repeat("d", 32), strings.Repeat("e", 32)
	f.hook = func(at string) error {
		if at == "policy-supersession-durable" {
			return interrupted
		}
		return nil
	}
	if _, e := supersessionOperation(context.Background(), f, p, n, d, old, m, advance, confirm); !errors.Is(e, interrupted) {
		t.Fatal("D not declared", e)
	}
	f.hook = nil
	os.Remove(f.root.Name() + p.Policy.Path)
	next := supSource(t, f, tx, "/bootstrap/later.json", n+1)
	f.hook = func(at string) error {
		if at == "supersession-current-confirmed" {
			return interrupted
		}
		return nil
	}
	if _, e := supersessionOperation(context.Background(), f, next, n, eReq, d, m, advance, confirm); !errors.Is(e, interrupted) {
		t.Fatal("prior settlement not cut", e)
	}
	f.hook = nil
	c, base, _ := f.rotationBase(tx)
	b, _ := f.read(Root+"/policy-supersession.json", gateway.MaxPolicySupersession, 0600)
	s, e := gateway.DecodePolicySupersession(c, base, b)
	if e != nil || s.RequestID != d {
		t.Fatal("E falsely declared during D settlement")
	}
	if _, e = supersessionOperation(context.Background(), f, next, n, eReq, d, m, advance, confirm); e != nil {
		t.Fatal("exact E retries old D authority", e)
	}
}

func TestSupersessionReconcileDispatchPrecedesOldRecoveryAndOrdinaryMutatorsRefuse(t *testing.T) {
	f, tx, p, m, _, n, old, advance, confirm := supFixture(t, true)
	req := strings.Repeat("d", 32)
	f.hook = func(at string) error {
		if at == "policy-supersession-durable" {
			return interrupted
		}
		return nil
	}
	if _, e := supersessionOperation(context.Background(), f, p, n, req, old, m, advance, confirm); !errors.Is(e, interrupted) {
		t.Fatal(e)
	}
	f.hook = nil
	before := m.activationCalls
	if _, e := reconcileOperationMaintenance(context.Background(), f, old, m, advance, confirm); e == nil || m.activationCalls != before {
		t.Fatal("old request bypassed pending replacement")
	}
	if _, e := rotateModel(context.Background(), f, tx, p, n, req, func() error { return nil }); e == nil {
		t.Fatal("ordinary rotation bypassed maintenance declaration")
	}
	if _, e := reconcileOperationMaintenance(context.Background(), f, req, m, advance, confirm); e != nil {
		t.Fatal("EX dispatch/reproof", e)
	}
}

func TestSupersessionOpaqueProposalDiscardRejectsInodeReplacement(t *testing.T) {
	f, _, p, m, _, n, old, advance, confirm := supFixture(t, false)
	hit := false
	f.hook = func(at string) error {
		if at == "supersession-discard-ready" {
			hit = true
			if e := os.Rename(f.root.Name()+Root+"/.policy.next", f.root.Name()+"/bootstrap/original-proposal"); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(f.root.Name()+Root+"/.policy.next", []byte("foreign replacement"), 0600); e != nil {
				t.Fatal(e)
			}
		}
		return nil
	}
	if _, e := supersessionOperation(context.Background(), f, p, n, strings.Repeat("d", 32), old, m, advance, confirm); e == nil || !hit {
		t.Fatal("inode replacement adopted")
	}
	b, e := f.readPrefix(Root+"/.policy.next", gateway.MaxSnapshotBytes)
	if e != nil || string(b) != "foreign replacement" || m.activationCalls != 0 {
		t.Fatal("foreign proposal deleted")
	}
}

func TestSupersessionOrdinaryLaterEpochConfirmsWithoutAdvancingAbandonedProposal(t *testing.T) {
	f, tx, _, m, _, _ := recoveryFixture(t)
	if _, e := reconcileRotation(context.Background(), f, strings.Repeat("b", 32), m); e != nil {
		t.Fatal("complete epoch2", e)
	}
	abandoned := supSource(t, f, tx, "/bootstrap/later-abandoned.json", 3)
	next := supSource(t, f, tx, "/bootstrap/later-replacement.json", 3)
	f.hook = func(at string) error {
		if at == "rotation-intent-durable" {
			return interrupted
		}
		return nil
	}
	if _, e := rotateModel(context.Background(), f, tx, abandoned, 2, strings.Repeat("c", 32), func() error { return nil }); !errors.Is(e, interrupted) {
		t.Fatal("later pending intent", e)
	}
	f.hook = nil
	os.Remove(f.root.Name() + abandoned.Policy.Path)
	state := &supModel{high: 2}
	advance, confirm := supPrimitives(t, f, tx, m, state)
	out, e := supersessionOperation(context.Background(), f, next, 2, strings.Repeat("d", 32), strings.Repeat("c", 32), m, advance, confirm)
	if e != nil || out.Revision != 3 || state.high != 2 || state.advances != 0 {
		t.Fatal("unconsumed epoch3 advanced/skipped", e)
	}
}
