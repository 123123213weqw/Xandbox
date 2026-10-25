//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// Shadow install root, model main/ingress/ACK and model high-water advancement.
// Real file sync/rename/OFD/flock. This is NOT root CLI/real TLS child/KVM proof.
type recoveryModelManager struct {
	*rotationModelManager
	t                *testing.T
	fs               *filesystem
	maintenanceCalls int
	allowACK         bool
	inside           bool
	beforeWork       func()
}

func (m *recoveryModelManager) maintainIngress(ctx context.Context, work func() error) error {
	m.maintenanceCalls++
	operationDenied(m.t, m.fs, false)
	gate, e := m.fs.existingLock(ctx, false)
	if e != nil {
		return e
	}
	gate()
	m.inside = true
	defer func() { m.inside = false }()
	if m.beforeWork != nil {
		m.beforeWork()
	}
	return work()
}
func (m *recoveryModelManager) activateManaged(ctx context.Context, epoch uint64, sha, art string) (bool, error) {
	m.activationCalls++
	gate, e := m.fs.existingLock(ctx, false)
	if e != nil {
		return false, e
	}
	gate()
	m.active = m.allowACK
	return m.active, nil
}
func recoveryFixture(t *testing.T) (*filesystem, transaction, RotationPlan, *recoveryModelManager, policyAdvance, *uint64) {
	t.Helper()
	f, tx, p2 := rotationFixture(t, true)
	if _, e := rotateModel(context.Background(), f, tx, p2, 1, strings.Repeat("b", 32), func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	p3 := rotationSource(t, f, tx, "/bootstrap/third.json", 3)
	m := &recoveryModelManager{rotationModelManager: &rotationModelManager{managedModelManager: &managedModelManager{modelManager: &modelManager{}}}, t: t, fs: f, allowACK: true}
	highwater := uint64(1)
	advance := func(c gateway.Config, auth, payload []byte, base string) error {
		if !m.inside {
			t.Fatal("advance outside stopped ingress/main scope")
		}
		onDisk, e := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
		if e != nil || !bytes.Equal(onDisk, payload) {
			t.Fatal("predecessor was overwritten before durable advance")
		}
		if base != digest(encode(tx)) || digest(auth) != tx.Plan.Auth.SHA256 {
			t.Fatal("authority/base drift")
		}
		env, e := gateway.DecodeManagedEnvelope(c, payload, base)
		if e != nil {
			return e
		}
		if env.Revision != highwater && env.Revision != highwater+1 {
			return ErrConflict
		}
		highwater = env.Revision
		return nil
	}
	return f, tx, p3, m, advance, &highwater
}
func expireCommittedModelPolicy(t *testing.T, f *filesystem, tx transaction) {
	t.Helper()
	c, base, e := f.rotationBase(tx)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
	if e != nil {
		t.Fatal(e)
	}
	p, e := gateway.DecodeManagedEnvelope(c, raw, base)
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair([]byte(p.Snapshot.CertificatePEM), []byte(p.Snapshot.PrivateKeyPEM))
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	leaf.NotBefore = time.Now().Add(-48 * time.Hour)
	leaf.NotAfter = time.Now().Add(-24 * time.Hour)
	der, e := x509.CreateCertificate(rand.Reader, leaf, leaf, leaf.PublicKey, pair.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	p.Snapshot.CertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	raw, e = gateway.EncodePolicyEnvelope(p)
	if e != nil {
		t.Fatal(e)
	}
	publishModelPolicy(t, f, raw)
	b, e := f.read(Root+"/rotation-intent.json", gateway.MaxPolicyIntent, 0600)
	if e != nil {
		t.Fatal(e)
	}
	intent, e := gateway.DecodePolicyIntent(c, base, b)
	if e != nil {
		t.Fatal(e)
	}
	if intent.RequestID == p.RequestID {
		intent.NewPayloadSHA256 = digest(raw)
		if e = os.WriteFile(f.root.Name()+Root+"/rotation-intent.json", encode(intent), 0600); e != nil {
			t.Fatal(e)
		}
	}

	// If a prior recovery declaration remains, preserve its exact new-file hash.
	b, e = f.read(Root+"/policy-recovery.json", gateway.MaxPolicyRecovery, 0600)
	if e == nil {
		record, e := gateway.DecodePolicyRecovery(c, base, b)
		if e != nil {
			t.Fatal(e)
		}
		record.NewPayloadSHA256 = digest(raw)
		if e = os.WriteFile(f.root.Name()+Root+"/policy-recovery.json", encode(record), 0600); e != nil {
			t.Fatal(e)
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
}
func TestRecoveryCommittedExpiredPredecessorAdvancesBeforePublicationAndExactReceiptRetry(t *testing.T) {
	f, tx, p, m, advance, high := recoveryFixture(t)
	expireCommittedModelPolicy(t, f, tx)
	req, old := strings.Repeat("c", 32), strings.Repeat("b", 32)
	c, base, e := f.rotationBase(tx)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
	if f.validateCandidate(c, base, raw) == nil {
		t.Fatal("expired predecessor still current-time valid")
	}
	got, e := recoveryOperation(context.Background(), f, p, 2, req, old, m, advance)
	if e != nil || got.Revision != 3 || !got.FilesCommitted || !got.ManagerReconciled || got.ProductionReady || *high != 2 {
		t.Fatal("recovery receipt", e)
	}
	if m.maintenanceCalls != 1 || m.activationCalls != 1 {
		t.Fatal("wrong maintenance/ACK count")
	}
	for _, name := range []string{"policy-recovery.json", "rotation-intent.json", ".policy.next", ".rotation-intent.next", ".policy-recovery.next"} {
		if yes, _ := f.exists(Root + "/" + name); yes {
			t.Fatal("unfinished metadata", name)
		}
	}
	os.Remove(f.root.Name() + p.Policy.Path)
	if _, e = recoveryOperation(context.Background(), f, p, 2, req, old, m, advance); e != nil || m.maintenanceCalls != 1 {
		t.Fatal("lost final receipt/source absence retry", e)
	}
	if f.verifyTransaction(context.Background(), tx) != nil {
		t.Fatal("full install proof changed")
	}
}

var recoveryStages = []string{"policy-recovery-written", "policy-recovery-synced", "policy-recovery-renamed", "policy-recovery-durable", "recovery-predecessor-durable", "recovery-policy-written", "recovery-policy-synced", "recovery-policy-prepared", "policy-renamed", "policy-durable", "recovery-intent-written", "recovery-intent-synced", "recovery-intent-renamed", "recovery-intent-durable", "recovery-files-confirmed", "recovery-record-removed", "policy-intent-removed"}

func TestRecoveryEveryJournalPublicationIntentAndReceiptBoundaryResumesExactRequest(t *testing.T) {
	for _, stage := range recoveryStages {
		t.Run(stage, func(t *testing.T) {
			f, tx, p, m, advance, high := recoveryFixture(t)
			hit := false
			f.hook = func(at string) error {
				if at == stage {
					hit = true
					return interrupted
				}
				return nil
			}
			req, old := strings.Repeat("c", 32), strings.Repeat("b", 32)
			if _, e := recoveryOperation(context.Background(), f, p, 2, req, old, m, advance); !errors.Is(e, interrupted) || !hit {
				t.Fatal("boundary not reached", e)
			}
			f.hook = nil
			if stage == "recovery-policy-written" || stage == "recovery-policy-synced" || stage == "recovery-policy-prepared" || (stage == "policy-renamed" || stage == "policy-durable" || stage == "policy-intent-removed") || strings.HasPrefix(stage, "recovery-intent") || stage == "recovery-files-confirmed" || stage == "recovery-record-removed" {
				os.Remove(f.root.Name() + p.Policy.Path)
			}
			if _, e := recoveryOperation(context.Background(), f, p, 2, req, old, m, advance); e != nil {
				t.Fatal("exact recovery failed", e)
			}
			if *high != 2 || f.verifyTransaction(context.Background(), tx) != nil {
				t.Fatal("durable predecessor/full proof")
			}
		})
	}
}
func TestRecoveryRejectsCompetingArgumentsForeignInventoryAndAdvanceFailure(t *testing.T) {
	for _, kind := range []string{"expected", "request", "supersedes", "source", "unknown", "policy-scratch", "intent-scratch", "record-scratch", "advance"} {
		t.Run(kind, func(t *testing.T) {
			f, tx, p, m, advance, _ := recoveryFixture(t)
			expected := uint64(2)
			req, old := strings.Repeat("c", 32), strings.Repeat("b", 32)
			switch kind {
			case "expected":
				expected = 3
			case "request":
				req = tx.RequestID
			case "supersedes":
				old = strings.Repeat("d", 32)
			case "source":
				p.Policy.SHA256 = strings.Repeat("f", 64)
			case "advance":
				advance = func(gateway.Config, []byte, []byte, string) error { return interrupted }
			default:
				name := map[string]string{"unknown": "unknown", "policy-scratch": ".policy.next", "intent-scratch": ".rotation-intent.next", "record-scratch": ".policy-recovery.next"}[kind]
				if e := os.WriteFile(f.root.Name()+Root+"/"+name, []byte("foreign"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			before, _ := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
			if _, e := recoveryOperation(context.Background(), f, p, expected, req, old, m, advance); e == nil {
				t.Fatal("invalid recovery accepted")
			}
			after, _ := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
			if !bytes.Equal(before, after) || m.activationCalls != 0 {
				t.Fatal("refusal changed policy or activated")
			}
			if kind != "advance" && m.maintenanceCalls != 0 {
				t.Fatal("invalid request stopped ingress")
			}
		})
	}
}
func TestRecoveryRepeatedCommittedNeverACKedExpiryKeepsSingleBoundedRecord(t *testing.T) {
	f, tx, p3, m, advance, high := recoveryFixture(t)
	m.allowACK = false
	rq3, rq2 := strings.Repeat("c", 32), strings.Repeat("b", 32)
	if _, e := recoveryOperation(context.Background(), f, p3, 2, rq3, rq2, m, advance); e == nil {
		t.Fatal("unconfirmed ACK reported success")
	}
	if *high != 2 {
		t.Fatal("predecessor not durable")
	}
	// Build a valid fourth source BEFORE the modeled third certificate expires.
	p4 := rotationSource(t, f, tx, "/bootstrap/fourth.json", 4)
	expireCommittedModelPolicy(t, f, tx)
	os.Remove(f.root.Name() + p3.Policy.Path)
	m.allowACK = true
	rq4 := strings.Repeat("d", 32)
	got, e := recoveryOperation(context.Background(), f, p4, 3, rq4, rq3, m, advance)
	if e != nil || got.Revision != 4 || !got.ManagerReconciled || *high != 3 {
		t.Fatal("successive recovery", e)
	}
	if yes, _ := f.exists(Root + "/policy-recovery.json"); yes {
		t.Fatal("recovery history accumulated")
	}
	if _, e = recoveryOperation(context.Background(), f, p3, 2, rq3, rq2, m, advance); e == nil {
		t.Fatal("superseded request revived")
	}
}

func TestRecoveryPendingJournalRoutesReconcileWithSourceGoneAndBlocksOrdinaryMutators(t *testing.T) {
	f, tx, p, m, advance, _ := recoveryFixture(t)
	req, old := strings.Repeat("c", 32), strings.Repeat("b", 32)
	f.hook = func(at string) error {
		if at == "recovery-policy-prepared" {
			return interrupted
		}
		return nil
	}
	if _, e := recoveryOperation(context.Background(), f, p, 2, req, old, m, advance); !errors.Is(e, interrupted) {
		t.Fatal(e)
	}
	f.hook = nil
	os.Remove(f.root.Name() + p.Policy.Path)
	if _, e := reconfigureOperation(context.Background(), f, p, 2, req, m); e == nil {
		t.Fatal("ordinary rotation bypassed maintenance journal")
	}
	if _, e := reconcileOperationAdvance(context.Background(), f, old, m, advance); !errors.Is(e, ErrConflict) {
		t.Fatal("superseded request operated on future recovery", e)
	}
	got, e := reconcileOperationAdvance(context.Background(), f, req, m, advance)
	if e != nil || got.Revision != 3 || !got.ManagerReconciled {
		t.Fatal("declared source-independent reconcile", e)
	}
	if f.verifyTransaction(context.Background(), tx) != nil {
		t.Fatal("full proof")
	}
}

func TestRecoveryJournalAloneDoesNotInventMissingCandidateBytes(t *testing.T) {
	for _, stage := range recoveryStages[:4] {
		t.Run(stage, func(t *testing.T) {
			f, _, p, m, advance, _ := recoveryFixture(t)
			source, e := os.ReadFile(f.root.Name() + p.Policy.Path)
			if e != nil {
				t.Fatal(e)
			}
			f.hook = func(at string) error {
				if at == stage {
					return interrupted
				}
				return nil
			}
			req, old := strings.Repeat("c", 32), strings.Repeat("b", 32)
			if _, e = recoveryOperation(context.Background(), f, p, 2, req, old, m, advance); !errors.Is(e, interrupted) {
				t.Fatal(e)
			}
			f.hook = nil
			os.Remove(f.root.Name() + p.Policy.Path)
			before, _ := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
			calls := m.maintenanceCalls
			if _, e = recoveryOperation(context.Background(), f, p, 2, req, old, m, advance); e == nil {
				t.Fatal("metadata invented candidate")
			}
			after, _ := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
			if !bytes.Equal(before, after) || m.maintenanceCalls != calls {
				t.Fatal("source refusal mutated policy/stopped ingress")
			}
			if e = os.WriteFile(f.root.Name()+p.Policy.Path, source, 0600); e != nil {
				t.Fatal(e)
			}
			if _, e = recoveryOperation(context.Background(), f, p, 2, req, old, m, advance); e != nil {
				t.Fatal("exact source restore", e)
			}
		})
	}
}

func futureRecoverySource(t *testing.T, f *filesystem, p RotationPlan) RotationPlan {
	t.Helper()
	b, e := os.ReadFile(f.root.Name() + p.Policy.Path)
	if e != nil {
		t.Fatal(e)
	}
	var s gateway.Snapshot
	if strictjson.Decode(b, &s) != nil {
		t.Fatal("snapshot input")
	}
	s.Epoch = 4
	s.Keys[0].TokenSHA256 = digest([]byte(strings.Repeat("f", 40)))
	b = encode(s)
	path := "/bootstrap/fourth.json"
	if e = os.WriteFile(f.root.Name()+path, b, 0600); e != nil {
		t.Fatal(e)
	}
	return RotationPlan{Version: 1, Policy: firecracker.Asset{Path: path, SHA256: digest(b)}}
}
func TestRecoverySupersedingCommittedOldIntentWindowSurvivesSettlementCuts(t *testing.T) {
	for _, stage := range []string{"recovery-predecessor-durable", "recovery-intent-written", "recovery-intent-synced", "recovery-intent-renamed", "recovery-intent-durable", "recovery-record-removed", "policy-recovery-written", "policy-recovery-durable"} {
		t.Run(stage, func(t *testing.T) {
			f, tx, p3, m, advance, high := recoveryFixture(t)
			f.hook = func(at string) error {
				if at == "policy-renamed" {
					return interrupted
				}
				return nil
			}
			rq3, rq2 := strings.Repeat("c", 32), strings.Repeat("b", 32)
			if _, e := recoveryOperation(context.Background(), f, p3, 2, rq3, rq2, m, advance); !errors.Is(e, interrupted) {
				t.Fatal(e)
			}
			f.hook = nil
			p4 := futureRecoverySource(t, f, p3)
			expireCommittedModelPolicy(t, f, tx)
			os.Remove(f.root.Name() + p3.Policy.Path)
			hit := false
			f.hook = func(at string) error {
				if at == stage {
					hit = true
					return interrupted
				}
				return nil
			}
			rq4 := strings.Repeat("d", 32)
			if _, e := recoveryOperation(context.Background(), f, p4, 3, rq4, rq3, m, advance); !errors.Is(e, interrupted) || !hit {
				t.Fatal("settlement cut not reached", e)
			}
			f.hook = nil
			got, e := recoveryOperation(context.Background(), f, p4, 3, rq4, rq3, m, advance)
			if e != nil || got.Revision != 4 || !got.ManagerReconciled || *high != 3 {
				t.Fatal("settlement retry", e)
			}
			if f.verifyTransaction(context.Background(), tx) != nil {
				t.Fatal("full proof")
			}
		})
	}
}
func TestRecoveryDoesNotSupersedeUncommittedEpochOrInventMissingAuthority(t *testing.T) {
	f, _, p3, m, advance, high := recoveryFixture(t)
	p4 := futureRecoverySource(t, f, p3)
	f.hook = func(at string) error {
		if at == "policy-recovery-durable" {
			return interrupted
		}
		return nil
	}
	if _, e := recoveryOperation(context.Background(), f, p3, 2, strings.Repeat("c", 32), strings.Repeat("b", 32), m, advance); !errors.Is(e, interrupted) {
		t.Fatal(e)
	}
	f.hook = nil
	before, _ := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
	if _, e := recoveryOperation(context.Background(), f, p4, 3, strings.Repeat("d", 32), strings.Repeat("c", 32), m, advance); e == nil {
		t.Fatal("uncommitted candidate treated as consumed epoch")
	}
	after, _ := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
	if !bytes.Equal(before, after) || *high != 1 || m.maintenanceCalls != 0 {
		t.Fatal("unproven supersession changed authority/stopped ingress")
	}
}
func TestRecoveryPinnedCandidateInMemorySurvivesSourceRemovalDuringStop(t *testing.T) {
	f, _, p, m, advance, _ := recoveryFixture(t)
	m.beforeWork = func() { os.Remove(f.root.Name() + p.Policy.Path) }
	if _, e := recoveryOperation(context.Background(), f, p, 2, strings.Repeat("c", 32), strings.Repeat("b", 32), m, advance); e != nil {
		t.Fatal("already pinned candidate reread missing source", e)
	}
}
