//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real owned shadow files and journal mechanics; model programs/ACK only.
// No root command, fixed host namespace, service, KVM or real ABI approval.
func resultColdModel(t *testing.T) (resultBootstrap, *prepared) {
	t.Helper()
	f, p, _ := managedFixture(t)
	_, inputs, _, _ := inputFixture(t)
	cfg, e := firecracker.DecodeInspectionConfig(inputs["backend.json"])
	if e != nil {
		t.Fatal(e)
	}
	art, e := descriptor(p.release)
	if e != nil {
		t.Fatal(e)
	}
	cfg.Version = 4
	cfg.Results = &firecracker.ResultPolicy{Version: 1, Bytes: 4 << 20, TenantBytes: 4 << 20, Records: 10}
	for role, a := range map[string]*firecracker.Asset{"firecracker": &cfg.Firecracker, "jailer": &cfg.Jailer, "warden": &cfg.Warden, "kernel": &cfg.Kernel, "initrd": &cfg.Initrd, "workspace": &cfg.Workspace} {
		*a = firecracker.Asset{Path: rolePath(role), SHA256: art[role].SHA256}
	}
	raw := encode(cfg)
	if _, e = firecracker.DecodeInspectionConfig(raw); e != nil {
		t.Fatal("MODEL must fit ORIGINAL node budgets", e)
	}
	p.plan.Backend.SHA256 = digest(raw)
	generated, e := renderResults(p.plan, cfg.IO.Device, art, *cfg.Results)
	if e != nil {
		t.Fatal(e)
	}
	generated[Root+"/backend.json"] = raw
	for i := range p.targets {
		if b, ok := generated[p.targets[i].file.Path]; ok {
			p.targets[i].data = b
			p.targets[i].file.SHA256 = digest(b)
			p.targets[i].file.Bytes = int64(len(b))
		}
	}
	b := resultBootstrap{fs: f, programs: func(context.Context, Plan, Release) error { return nil }}
	if !validResultTransaction(p.resultTransaction(request())) {
		t.Fatal("invalid result MODEL")
	}
	return b, p
}
func resultModelInstall(ctx context.Context, b resultBootstrap, p *prepared, id string, m serviceManager) (resultTransaction, error) {
	done, e := b.fs.ordinaryInitialOperationLock(ctx)
	if e != nil {
		return resultTransaction{}, e
	}
	defer done()
	unlock, e := b.fs.existingLock(ctx, true)
	if e != nil {
		return resultTransaction{}, e
	}
	defer unlock()
	return b.installLocked(ctx, p.plan, id, m, func(context.Context, Plan, bool) (*prepared, func(), error) { return p, func() {}, nil })
}
func resultTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

func TestResultBootstrapColdCommitFreshRetryStartupAndLegacyRefusal(t *testing.T) {
	b, p := resultColdModel(t)
	ctx, cancel := resultTestContext()
	defer cancel()
	m := &modelManager{}
	tx, e := resultModelInstall(ctx, b, p, request(), m)
	if e != nil {
		t.Fatal(e)
	}
	before := coreTree(t, b.fs.root.Name())
	if _, e = b.startupFilesLocked(ctx); e != nil {
		t.Fatal("versioned startup proof", e)
	}
	if _, e = b.fs.startupFilesLocked(ctx); e == nil {
		t.Fatal("old startup accepted new commit")
	}
	if _, e = resultModelInstall(ctx, b, p, request(), m); e != nil {
		t.Fatal("exact retry", e)
	}
	if _, e = resultModelInstall(ctx, b, p, strings.Repeat("b", 32), m); !errors.Is(e, ErrConflict) {
		t.Fatal("request conflict", e)
	}
	if !bytes.Equal(encode(tx), mustResultCommit(t, b.fs)) || !sameCoreTree(before, coreTree(t, b.fs.root.Name())) {
		t.Fatal("retry/startup changed files or authority")
	}
	if m.reconcileCalls != 0 {
		t.Fatal("file-only model started a manager")
	}
	for _, name := range []string{"runtime-files-pending.json", "rotation-intent.json", "policy-recovery.json", "policy-supersession.json"} {
		if yes, e := b.fs.exists(Root + "/" + name); e != nil || yes {
			t.Fatal("bootstrap created a side journal", name, e)
		}
	}
}
func mustResultCommit(t *testing.T, f *filesystem) []byte {
	t.Helper()
	raw, e := f.read(Root+"/commit.json", 65536, 0600)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func sameCoreTree(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for n, v := range a {
		if b[n] != v {
			return false
		}
	}
	return true
}

func TestResultBootstrapAllOriginalPersistenceCutsRetryExactNewVersion(t *testing.T) {
	_, p := resultColdModel(t)
	stages := []string{"intent-written", "intent-synced", "intent-renamed", "intent-durable", "commit-written", "commit-synced", "commit-renamed", "commit-durable", "commit-confirmed", "intent-removed"}
	for _, v := range p.targets {
		for _, phase := range []string{"written", "synced", "sealed"} {
			stages = append(stages, "file-"+filepath.Base(v.file.Path)+"-"+phase)
		}
	}
	if len(stages) != 82 {
		t.Fatal("new cold cut roster", len(stages))
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			b, p := resultColdModel(t)
			ctx, cancel := resultTestContext()
			defer cancel()
			hit := false
			b.fs.hook = func(at string) error {
				if at == stage {
					hit = true
					return interrupted
				}
				return nil
			}
			if _, e := resultModelInstall(ctx, b, p, request(), &modelManager{}); !errors.Is(e, interrupted) || !hit {
				t.Fatal("unreached result cut", stage, e)
			}
			b.fs.hook = nil
			tx, e := resultModelInstall(ctx, b, p, request(), &modelManager{})
			if e != nil || tx.Version != 2 || b.verifyTargets(ctx, tx, true) != nil {
				t.Fatal("new-version retry", e)
			}
		})
	}
}

func TestResultBootstrapNeverAdoptsOldStateOrIgnoresProgramGate(t *testing.T) {
	for _, name := range []string{"legacy-commit", "existing-binding", "missing-verifier", "program-refusal", "foreign-file", "runtime-namespace", "wrong-backend"} {
		t.Run(name, func(t *testing.T) {
			b, p := resultColdModel(t)
			ctx, cancel := resultTestContext()
			defer cancel()
			var e error
			switch name {
			case "legacy-commit":
				unlock, lockErr := b.fs.initialLock(ctx)
				if lockErr != nil {
					t.Fatal(lockErr)
				}
				unlock()
				e = b.fs.record("commit", encode(p.transaction(request())))
			case "existing-binding":
				e = os.MkdirAll(b.fs.root.Name()+stateDir+"/firecracker", 0700)
				if e == nil {
					e = os.WriteFile(b.fs.root.Name()+stateDir+"/firecracker/config.json", []byte("old binding is never deleted"), 0600)
				}
			case "missing-verifier":
				b.programs = nil
			case "program-refusal":
				b.programs = func(context.Context, Plan, Release) error { return ErrPolicy }
			case "foreign-file":
				e = os.WriteFile(b.fs.root.Name()+Root+"/foreign", []byte("x"), 0600)
			case "runtime-namespace":
				e = os.Mkdir(b.fs.root.Name()+"/etc/xandbox-runtime-future", 0700)
			case "wrong-backend":
				for i := range p.targets {
					if p.targets[i].file.Path == Root+"/backend.json" {
						p.targets[i].data = bytes.Replace(p.targets[i].data, []byte(`"version":4`), []byte(`"version":3`), 1)
						p.targets[i].file.SHA256 = digest(p.targets[i].data)
						p.plan.Backend.SHA256 = p.targets[i].file.SHA256
					}
				}
			}
			if e != nil {
				t.Fatal(e)
			}
			before := coreTree(t, b.fs.root.Name())
			m := &modelManager{}
			if _, e = resultModelInstall(ctx, b, p, request(), m); e == nil {
				t.Fatal("adopted unsupported state or program", name)
			}
			if m.reconcileCalls != 0 {
				t.Fatal("activated refused bootstrap")
			}
			if name == "existing-binding" {
				raw, e := os.ReadFile(b.fs.root.Name() + stateDir + "/firecracker/config.json")
				if e != nil || string(raw) != "old binding is never deleted" {
					t.Fatal("old binding modified", e)
				}
			}
			if name == "legacy-commit" && !bytes.Equal(mustResultCommit(t, b.fs), encode(p.transaction(request()))) {
				t.Fatal("legacy genesis rewritten")
			}
			if name == "missing-verifier" && !sameCoreTree(before, coreTree(t, b.fs.root.Name())) { // Creating original lock is the sole bootstrap setup, never targets.
				if yes, _ := b.fs.exists(Root + "/intent.json"); yes {
					t.Fatal("nil verifier wrote intent")
				}
			}
		})
	}
}

func TestResultBootstrapUsesNewGatewayGenesisNotLegacyHash(t *testing.T) {
	b, p := resultColdModel(t)
	tx := p.resultTransaction(request())
	var config gateway.Config
	var raw []byte
	for _, v := range p.targets {
		if v.file.Path == Root+"/gateway.json" {
			raw = v.data
		}
	}
	if e := strictjson.Decode(raw, &config); e != nil {
		t.Fatal(e)
	}
	base, e := gateway.ValidateManagedResultBase(config, raw, encode(tx))
	if e != nil || base != digest(encode(tx)) {
		t.Fatal(base, e)
	}
	if _, e = gateway.ValidateManagedBase(config, raw, encode(tx)); e == nil {
		t.Fatal("new genesis normalized to legacy")
	}
	if _, e = gateway.ValidateManagedResultBase(config, raw, encode(p.transaction(request()))); e == nil {
		t.Fatal("legacy genesis accepted as new")
	}
	if got, e := gateway.ValidateManagedBaseReference(config, raw, encode(tx)); e != nil || got != base {
		t.Fatal("actual gateway dispatcher", got, e)
	}
	_ = b
}

type resultACKModel struct {
	modelManager
	bootstrap resultBootstrap
	ack       bool
	gates     int
}

func (m *resultACKModel) reconcileManaged(ctx context.Context) error {
	unlock, e := m.bootstrap.fs.startupReadLock(ctx)
	if e != nil {
		return e
	}
	defer unlock()
	if _, e = m.bootstrap.startupFilesLocked(ctx); e != nil {
		return e
	}
	m.gates++
	return nil
}
func (m *resultACKModel) policy(context.Context, uint64, string, string, bool) (bool, error) {
	return m.ack, nil
}

func TestResultBootstrapConsumedReconcileGateAndReopenedRootModel(t *testing.T) {
	b, p := resultColdModel(t)
	ctx, cancel := resultTestContext()
	defer cancel()
	exe, e := os.Open("/proc/self/exe")
	if e != nil {
		t.Fatal(e)
	}
	defer exe.Close()
	st, e := exe.Stat()
	if e != nil {
		t.Fatal(e)
	}
	pin, e := hashFile(ctx, exe, st.Size())
	if e != nil {
		t.Fatal(e)
	}
	p.plan.Self.SHA256 = pin
	for i := range p.targets {
		if p.targets[i].file.Path == SelfPath {
			p.targets[i].data = nil
			p.targets[i].source = exe
			p.targets[i].file.SHA256 = pin
			p.targets[i].file.Bytes = st.Size()
		}
	}
	manager := &resultACKModel{bootstrap: b, ack: true}
	result, e := b.installOperation(ctx, p.plan, request(), manager, func(context.Context, Plan, bool) (*prepared, func(), error) { return p, func() {}, nil })
	if e != nil || !result.FilesCommitted || !result.ManagerReconciled || result.ProductionReady || manager.gates != 1 {
		t.Fatal("consumed MODEL gate/reconcile", result, e, manager.gates)
	}
	commit := mustResultCommit(t, b.fs)
	root, e := os.Open(b.fs.root.Name())
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	reboot := resultBootstrap{fs: &filesystem{root: root}, programs: func(context.Context, Plan, Release) error { return nil }}
	manager.bootstrap = reboot
	manager.ack = false
	if _, e = reboot.reconcile(ctx, request(), manager); e == nil {
		t.Fatal("missing MODEL ACK became activation")
	}
	if !bytes.Equal(commit, mustResultCommit(t, reboot.fs)) {
		t.Fatal("failed MODEL activation rewrote genesis/state")
	}
	manager.ack = true
	if r, e := reboot.reconcile(ctx, request(), manager); e != nil || !r.ManagerReconciled || r.ProductionReady {
		t.Fatal("reopened original root MODEL", r, e)
	}
}
