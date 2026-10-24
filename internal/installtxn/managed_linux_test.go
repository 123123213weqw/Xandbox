//go:build linux

package installtxn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// A real filesystem, but shadow root/model artifacts/manager. No service,
// privilege transition, fixed system path, real frontend ACK or KVM acceptance.
func managedFixture(t *testing.T) (*filesystem, *prepared, *modelManager) {
	t.Helper()
	f, p, m := fixture(t)
	_, input, _, _ := inputFixture(t)
	var g gateway.Config
	if strictjson.Decode(input["gateway.json"], &g) != nil {
		t.Fatal("fixture config")
	}
	s := gateway.Snapshot{Version: 1, Epoch: 1, UID: g.UID, GID: g.GID, Listen: g.Listen, ServerName: g.ServerName, CertificatePEM: string(input["tls.pem"]), PrivateKeyPEM: string(input["tls.key"]), Keys: g.Keys}
	raw, e := gateway.EncodePolicyEnvelope(gateway.PolicyEnvelope{Version: 1, Revision: 1, Snapshot: s})
	if e != nil {
		t.Fatal(e)
	}
	g.Version = 2
	g.CertificateFile = ""
	g.PrivateKeyFile = ""
	g.Keys = nil
	g.ManagedPolicyFile = gateway.ManagedPolicyPath
	g.InitialPolicySHA256 = digest(raw)
	p.plan.Version = 2
	p.plan.Certificate = firecracker.Asset{}
	p.plan.PrivateKey = firecracker.Asset{}
	p.plan.Policy = &firecracker.Asset{Path: "/bootstrap/policy.json", SHA256: digest(raw)}
	p.plan.Gateway.SHA256 = digest(encode(g))
	p.plan.Auth.SHA256 = digest(input["auth.json"])
	art, e := descriptor(p.release)
	if e != nil {
		t.Fatal(e)
	}
	generated, e := render(p.plan, "1:1", art)
	if e != nil {
		t.Fatal(e)
	}
	keep := []target{}
	for _, v := range p.targets {
		if v.file.Path == Root+"/tls.pem" || v.file.Path == Root+"/tls.key" || v.file.Path == Root+"/gateway.json" || v.file.Path == Root+"/auth.json" {
			continue
		}
		if _, replace := generated[v.file.Path]; replace {
			continue
		}
		keep = append(keep, v)
	}
	p.targets = keep
	for path, b := range generated {
		p.targets = append(p.targets, target{file: File{Path: path, SHA256: digest(b), Bytes: int64(len(b)), Mode: 0600}, data: b})
	}
	for path, b := range map[string][]byte{Root + "/gateway.json": encode(g), gateway.ManagedPolicyPath: raw, Root + "/auth.json": input["auth.json"]} {
		p.targets = append(p.targets, target{file: File{Path: path, SHA256: digest(b), Bytes: int64(len(b)), Mode: 0600}, data: b})
	}
	orderTargets(p.targets)
	if len(p.targets) != 24 || !validFileList(p.transaction(request())) {
		t.Fatal("invalid v2 model")
	}
	return f, p, m
}

func TestManagedInitial24TargetsSameRequestAndClosedInventory(t *testing.T) {
	f, p, m := managedFixture(t)
	tx, e := applyModel(context.Background(), f, p, request(), m)
	if e != nil {
		t.Fatal(e)
	}
	if len(tx.Files) != 24 || f.verifyTransaction(context.Background(), tx) != nil {
		t.Fatal("v2 file proof")
	}
	if _, e = applyModel(context.Background(), f, p, request(), m); e != nil {
		t.Fatal("exact initial retry", e)
	}
	if _, e = applyModel(context.Background(), f, p, strings.Repeat("b", 32), m); !errors.Is(e, ErrConflict) {
		t.Fatal("competing initial request")
	}
	for _, path := range []string{Root + "/tls.pem", Root + "/tls.key"} {
		if yes, _ := f.exists(path); yes {
			t.Fatal("separate TLS files created")
		}
	}
	if os.WriteFile(f.root.Name()+Root+"/tls.key", []byte("foreign"), 0600) != nil {
		t.Fatal("fixture")
	}
	if f.verifyTransaction(context.Background(), tx) == nil {
		t.Fatal("legacy extra adopted by v2")
	}
	legacy, lp, lm := fixture(t)
	ltx, e := applyModel(context.Background(), legacy, lp, request(), lm)
	if e != nil {
		t.Fatal(e)
	}
	if os.WriteFile(legacy.root.Name()+gateway.ManagedPolicyPath, []byte("foreign"), 0600) != nil {
		t.Fatal("fixture")
	}
	if legacy.verifyTransaction(context.Background(), ltx) == nil {
		t.Fatal("v1 inventory widened")
	}
}

func TestManagedInitialPersistenceBoundariesRecoverSame24TargetProof(t *testing.T) {
	_, base, _ := managedFixture(t)
	stages := []string{"intent-written", "intent-synced", "intent-renamed", "intent-durable", "commit-written", "commit-synced", "commit-renamed", "commit-durable", "commit-confirmed", "intent-removed"}
	for _, v := range base.targets {
		for _, phase := range []string{"written", "synced", "sealed"} {
			stages = append(stages, "file-"+filepath.Base(v.file.Path)+"-"+phase)
		}
	}
	if len(stages) != 82 {
		t.Fatal("boundary inventory")
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			f, p, m := managedFixture(t)
			hit := false
			f.hook = func(at string) error {
				if at == stage {
					hit = true
					return interrupted
				}
				return nil
			}
			if _, e := applyModel(context.Background(), f, p, request(), m); !errors.Is(e, interrupted) || !hit {
				t.Fatal("unreached v2 boundary", e)
			}
			f.hook = nil
			tx, e := applyModel(context.Background(), f, p, request(), m)
			if e != nil || f.verifyTransaction(context.Background(), tx) != nil {
				t.Fatal("same v2 request recovery", e)
			}
			if m.reconcileCalls != 0 {
				t.Fatal("file recovery activated services")
			}
		})
	}
}

func writeManagedModelNext(t *testing.T, f *filesystem, tx transaction) (gateway.PolicyEnvelope, []byte, gateway.Config) {
	t.Helper()
	raw, e := f.read(Root+"/gateway.json", gateway.MaxSnapshotBytes, 0600)
	if e != nil {
		t.Fatal(e)
	}
	var c gateway.Config
	if strictjson.Decode(raw, &c) != nil {
		t.Fatal("config")
	}
	old, e := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
	if e != nil {
		t.Fatal(e)
	}
	p, e := gateway.DecodeManagedEnvelope(c, old, digest(encode(tx)))
	if e != nil {
		t.Fatal(e)
	}
	p.Revision++
	p.ExpectedRevision = p.Revision - 1
	p.RequestID = strings.Repeat("c", 32)
	p.BaseCommitSHA256 = digest(encode(tx))
	p.ConfigSHA256, _ = gateway.ManagedConfigDigest(c)
	p.InitialPolicySHA256 = c.InitialPolicySHA256
	p.Source = gateway.PolicySource{Path: "/bootstrap/new-snapshot.json", SHA256: strings.Repeat("f", 64)}
	p.Snapshot.Epoch = p.Revision
	b, e := gateway.EncodePolicyEnvelope(p)
	if e != nil {
		t.Fatal(e)
	}
	return p, b, c
}
func publishModelPolicy(t *testing.T, f *filesystem, b []byte) {
	t.Helper()
	path := f.root.Name() + gateway.ManagedPolicyPath
	if e := os.WriteFile(path+".test", b, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(path+".test", path); e != nil {
		t.Fatal(e)
	}
	if e := f.syncDir(Root); e != nil {
		t.Fatal(e)
	}
}
func TestManagedOnlyAtomicBoundEnvelopeCanReplaceOneTarget(t *testing.T) {
	f, p, m := managedFixture(t)
	tx, e := applyModel(context.Background(), f, p, request(), m)
	if e != nil {
		t.Fatal(e)
	}
	if os.WriteFile(f.root.Name()+gateway.ManagedPolicyPath, []byte("foreign"), 0600) != nil {
		t.Fatal("fixture")
	}
	if f.verifyTransaction(context.Background(), tx) == nil {
		t.Fatal("raw hash exception accepted")
	}
	for _, v := range p.targets {
		if v.file.Path == gateway.ManagedPolicyPath {
			publishModelPolicy(t, f, v.data)
		}
	}
	next, b, _ := writeManagedModelNext(t, f, tx)
	publishModelPolicy(t, f, b)
	if f.verifyTransaction(context.Background(), tx) != nil {
		t.Fatal("bound atomic authority not recognized")
	}
	r, e := f.committedResult(tx)
	if e != nil || r.Revision != 2 || r.ManagerReconciled || r.ProductionReady {
		t.Fatal("policy file proof inflated", r, e)
	}
	bad := next
	bad.BaseCommitSHA256 = strings.Repeat("e", 64)
	raw, _ := gateway.EncodePolicyEnvelope(bad)
	publishModelPolicy(t, f, raw)
	if f.verifyTransaction(context.Background(), tx) == nil {
		t.Fatal("foreign base authority accepted")
	}
	publishModelPolicy(t, f, b)
	if os.WriteFile(f.root.Name()+Root+"/auth.json", []byte("different backend authority"), 0600) != nil {
		t.Fatal("fixture")
	}
	if f.verifyTransaction(context.Background(), tx) == nil {
		t.Fatal("policy override waived backend pin")
	}
}

func TestManagedPendingIntentAndScratchFenceBeforeNewAuthority(t *testing.T) {
	f, p, m := managedFixture(t)
	tx, e := applyModel(context.Background(), f, p, request(), m)
	if e != nil {
		t.Fatal(e)
	}
	old, e := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
	if e != nil {
		t.Fatal(e)
	}
	next, b, c := writeManagedModelNext(t, f, tx)
	i := gateway.PolicyIntent{Version: 1, ExpectedRevision: 1, RequestID: next.RequestID, BaseCommitSHA256: next.BaseCommitSHA256, ConfigSHA256: next.ConfigSHA256, InitialPolicySHA256: c.InitialPolicySHA256, OldPayloadSHA256: digest(old), NewPayloadSHA256: digest(b), Source: next.Source}
	path := f.root.Name() + Root + "/rotation-intent.json"
	if os.WriteFile(path, encode(i), 0600) != nil {
		t.Fatal("fixture")
	}
	if f.verifyTransaction(context.Background(), tx) == nil {
		t.Fatal("pending restart revived old policy")
	}
	publishModelPolicy(t, f, b)
	if f.verifyTransaction(context.Background(), tx) != nil {
		t.Fatal("committed matching intent refused")
	}
	for _, name := range []string{".rotation-intent.next", ".policy.next"} {
		path := f.root.Name() + Root + "/" + name
		if os.WriteFile(path, []byte("pending"), 0600) != nil {
			t.Fatal("fixture")
		}
		if f.verifyTransaction(context.Background(), tx) == nil {
			t.Fatal("scratch authorized startup")
		}
		os.Remove(path)
	}
	i.NewPayloadSHA256 = strings.Repeat("d", 64)
	if os.WriteFile(path, encode(i), 0600) != nil {
		t.Fatal("fixture")
	}
	if f.verifyTransaction(context.Background(), tx) == nil {
		t.Fatal("unmatched intent adopted")
	}
}

type managedModelManager struct {
	*modelManager
	active      bool
	policyCalls int
	onPolicy    func(uint64, bool)
}

func (m *managedModelManager) reconcileManaged(ctx context.Context) error { return m.reconcile(ctx) }
func (m *managedModelManager) policy(_ context.Context, revision uint64, _, _ string, reconcile bool) (bool, error) {
	m.policyCalls++
	if m.onPolicy != nil {
		m.onPolicy(revision, reconcile)
	}
	return m.active, nil
}
func TestManagedStatusNeedsExactPolicyObservationNotJustActiveUnits(t *testing.T) {
	f, p, m := managedFixture(t)
	if _, e := applyModel(context.Background(), f, p, request(), m); e != nil {
		t.Fatal(e)
	}
	if _, e := f.status(context.Background(), m); e == nil {
		t.Fatal("v2 receipt fell back to legacy manager")
	}
	manager := &managedModelManager{modelManager: m}
	r, e := f.status(context.Background(), manager)
	if e != nil || r.ManagerReconciled || !r.FilesCommitted || manager.policyCalls != 1 {
		t.Fatal("active units stood in for child ACK", e)
	}
	manager.active = true
	r, e = f.status(context.Background(), manager)
	if e != nil || !r.ManagerReconciled || r.ProductionReady {
		t.Fatal("modeled exact status rejected", e)
	}
}
