//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
)

var interrupted = errors.New("TEST interrupted persistence boundary")

type modelManager struct {
	freshCalls, reconcileCalls int
	fail                       error
	check                      func() error
}

func (m *modelManager) fresh(context.Context) error { m.freshCalls++; return m.fail }
func (m *modelManager) reconcile(context.Context) error {
	m.reconcileCalls++
	if m.check != nil {
		return m.check()
	}
	return m.fail
}
func (m *modelManager) current(context.Context) (bool, error) { return m.fail == nil, m.fail }
func fixture(t *testing.T) (*filesystem, *prepared, *modelManager) {
	t.Helper()
	base := t.TempDir()
	if e := os.Chmod(base, 0700); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{Root, UnitDir, "/usr/libexec", "/srv", "/sys/fs/cgroup/system.slice"} {
		if e := os.MkdirAll(base+p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	root, e := os.Open(base)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { root.Close() })

	f := &filesystem{root: root}
	t.Cleanup(func() {
		// Only this test-owned shadow's sealed chroot is made removable AFTER
		// assertions. Production mode remains0555 and no service GC is inferred.
		dir, e := f.directory(childRoot)
		if e == nil {
			defer dir.Close()
			if e = dir.Chmod(0700); e != nil {
				t.Error(e)
			}
		}
	})
	p := samplePlan()
	desc := Release{Version: 1, SourceRevision: strings.Repeat("a", 40), Toolchain: "go1.27.3", GOARCH: runtime.GOARCH}
	art := map[string]Artifact{}
	data := map[string][]byte{}
	for _, role := range roles {
		b := bytes.Repeat([]byte(role+"-model\n"), 8)
		data[role] = b
		a := Artifact{role, digest(b), int64(len(b))}
		art[role] = a
		desc.Files = append(desc.Files, a)
	}
	p.Release = digest(encode(desc))
	p.Self.SHA256 = digest([]byte("model-self"))
	cfg := firecracker.Config{Version: 3, RuntimeRoot: runtimeDir, CgroupRoot: unitRoot + "/node/instances", Node: &firecracker.NodePolicy{CgroupRoot: unitRoot + "/node"}, IO: &firecracker.IOPolicy{Device: "1:1"}, Quota: &firecracker.QuotaPolicy{}}
	for role, a := range map[string]*firecracker.Asset{"firecracker": &cfg.Firecracker, "jailer": &cfg.Jailer, "warden": &cfg.Warden, "kernel": &cfg.Kernel, "initrd": &cfg.Initrd, "workspace": &cfg.Workspace} {
		*a = firecracker.Asset{Path: rolePath(role), SHA256: art[role].SHA256}
	}
	payload := map[string][]byte{"backend.json": encode(cfg), "auth.json": []byte("model-private-auth"), "gateway.json": []byte("model-private-gateway"), "tls.pem": []byte("model-certificate"), "tls.key": []byte("model-private-key")}
	p.Backend.SHA256 = digest(payload["backend.json"])
	p.Auth.SHA256 = digest(payload["auth.json"])
	p.Gateway.SHA256 = digest(payload["gateway.json"])
	p.Certificate.SHA256 = digest(payload["tls.pem"])
	p.PrivateKey.SHA256 = digest(payload["tls.key"])
	prepared := &prepared{plan: p, release: desc}
	appendData := func(path string, b []byte, mode uint32) {
		prepared.targets = append(prepared.targets, target{file: File{path, digest(b), int64(len(b)), mode}, data: b})
	}
	for _, role := range roles {
		mode := uint32(0444)
		if executable(role) {
			mode = 0555
		}
		appendData(rolePath(role), data[role], mode)
	}
	appendData(SelfPath, []byte("model-self"), 0555)
	appendData(childRoot+"/gateway", data["gateway"], 0555)
	for name, b := range payload {
		appendData(Root+"/"+name, b, 0600)
	}
	rendered, e := render(p, "1:1", art)
	if e != nil {
		t.Fatal(e)
	}
	for path, b := range rendered {
		appendData(path, b, 0600)
	}
	orderTargets(prepared.targets)
	if !validFileList(prepared.transaction(strings.Repeat("a", 32))) {
		t.Fatal("bad fixture descriptor")
	}
	return f, prepared, &modelManager{}
}
func request() string { return strings.Repeat("a", 32) }
func TestStatusCannotCreateLockOrActivateManager(t *testing.T) {
	f, p, m := fixture(t)
	if _, e := f.status(context.Background(), m); e == nil {
		t.Fatal("missing installation reported valid")
	}
	if yes, e := f.exists(Root + "/.lock"); e != nil || yes {
		t.Fatal("status created lock", e)
	}
	if _, e := applyModel(context.Background(), f, p, request(), m); e != nil {
		t.Fatal(e)
	}
	got, e := f.status(context.Background(), m)
	if e != nil || !got.FilesCommitted || !got.ManagerReconciled || got.ProductionReady {
		t.Fatal(got, e)
	}
	if m.reconcileCalls != 0 {
		t.Fatal("status activated manager")
	}
	if e := os.WriteFile(f.root.Name()+Root+"/unknown", []byte("foreign"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = f.status(context.Background(), m); e == nil {
		t.Fatal("status accepted unknown inventory")
	}
}
func applyModel(ctx context.Context, f *filesystem, p *prepared, req string, m serviceManager) (transaction, error) {
	unlock, e := f.initialLock(ctx)
	if e != nil {
		return transaction{}, e
	}
	defer unlock()
	return f.installLocked(ctx, p.plan, req, m, func(context.Context, Plan, bool) (*prepared, func(), error) { return p, func() {}, nil })
}
func TestLostPermanentInstallerLockIsNotRecreated(t *testing.T) {
	f, p, m := fixture(t)
	if _, e := applyModel(context.Background(), f, p, request(), m); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(f.root.Name() + Root + "/.lock"); e != nil {
		t.Fatal(e)
	}
	if _, e := applyModel(context.Background(), f, p, request(), m); e == nil {
		t.Fatal("lost lock silently replaced")
	}
	if _, e := f.existingLock(context.Background(), true); e == nil {
		t.Fatal("reconciliation recreated lock")
	}
	if yes, e := f.exists(Root + "/.lock"); e != nil || yes {
		t.Fatal("permanent lock recreated", e)
	}
}
func TestInitialFilesCommitAndRetryNoManagerUnderLock(t *testing.T) {
	f, p, m := fixture(t)
	tx, e := applyModel(context.Background(), f, p, request(), m)
	if e != nil {
		t.Fatal(e)
	}
	if m.freshCalls != 1 || m.reconcileCalls != 0 {
		t.Fatal("commit unexpectedly activated services")
	}
	if e = f.verifyTransaction(context.Background(), tx); e != nil {
		t.Fatal(e)
	}
	got, e := applyModel(context.Background(), f, p, request(), m)
	if e != nil || !bytes.Equal(encode(got), encode(tx)) || m.freshCalls != 1 {
		t.Fatal("retry changed initial commit", e)
	}
	if _, e = applyModel(context.Background(), f, p, strings.Repeat("b", 32), m); !errors.Is(e, ErrConflict) {
		t.Fatal("new request replaced commit", e)
	}
	if yes, _ := f.exists(Root + "/intent.json"); yes {
		t.Fatal("committed intent not cleaned")
	}
	if _, e = f.readTransaction("commit"); e != nil {
		t.Fatal(e)
	}
	if r := fileCommitted(tx); !r.FilesCommitted || r.ManagerReconciled || r.ProductionReady {
		t.Fatal("activation or maturity inflated")
	}
}
func TestAllSelectedPersistenceBoundariesRecoverSameRequest(t *testing.T) {
	_, base, _ := fixture(t)
	stages := []string{"intent-written", "intent-synced", "intent-renamed", "intent-durable", "commit-written", "commit-synced", "commit-renamed", "commit-durable", "commit-confirmed", "intent-removed"}
	for _, v := range base.targets {
		for _, phase := range []string{"written", "synced", "sealed"} {
			stages = append(stages, "file-"+filepath.Base(v.file.Path)+"-"+phase)
		}
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			f, p, m := fixture(t)
			hit := false
			f.hook = func(at string) error {
				if at == stage {
					hit = true
					return interrupted
				}
				return nil
			}
			if _, e := applyModel(context.Background(), f, p, request(), m); !errors.Is(e, interrupted) || !hit {
				t.Fatal("boundary not reached", e, hit)
			}
			f.hook = nil
			tx, e := applyModel(context.Background(), f, p, request(), m)
			if e != nil {
				t.Fatal("same request recovery failed", e)
			}
			if e = f.verifyTransaction(context.Background(), tx); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestPartialAndUnknownInventoryNoRepairOrAdoption(t *testing.T) {
	for _, kind := range []string{"matching-prefix", "wrong-prefix", "hardlink", "symlink", "unknown-root", "unknown-assets", "duplicate-scratch"} {
		t.Run(kind, func(t *testing.T) {
			f, p, m := fixture(t)
			stage := "file-sandboxd-written"
			f.hook = func(at string) error {
				if at == stage {
					return interrupted
				}
				return nil
			}
			if _, e := applyModel(context.Background(), f, p, request(), m); !errors.Is(e, interrupted) {
				t.Fatal(e)
			}
			f.hook = nil
			path := f.root.Name() + rolePath("daemon")
			var data []byte
			for _, v := range p.targets {
				if v.file.Path == rolePath("daemon") {
					data = v.data
				}
			}
			switch kind {
			case "matching-prefix":
				if e := os.WriteFile(path, data[:7], 0600); e != nil {
					t.Fatal(e)
				}
			case "wrong-prefix":
				if e := os.WriteFile(path, []byte("unrelated"), 0600); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(path, path+"-alias"); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				os.Remove(path)
				if e := os.Symlink("missing", path); e != nil {
					t.Fatal(e)
				}
			case "unknown-root":
				if e := os.WriteFile(f.root.Name()+Root+"/foreign", []byte("unknown"), 0600); e != nil {
					t.Fatal(e)
				}
			case "unknown-assets":
				if e := os.WriteFile(f.root.Name()+assetDir+"/foreign", []byte("unknown"), 0600); e != nil {
					t.Fatal(e)
				}
			case "duplicate-scratch":
				if e := os.WriteFile(f.root.Name()+Root+"/.intent.next", []byte("unknown"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			_, e := applyModel(context.Background(), f, p, request(), m)
			if kind == "matching-prefix" {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("unknown inventory accepted")
			}
		})
	}
}
func TestCommittedCorruptionNeverRepairedFromInputs(t *testing.T) {
	f, p, m := fixture(t)
	tx, e := applyModel(context.Background(), f, p, request(), m)
	if e != nil {
		t.Fatal(e)
	}
	path := f.root.Name() + Root + "/auth.json"
	if e = os.WriteFile(path, []byte("corruption"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = f.verifyTransaction(context.Background(), tx); e == nil {
		t.Fatal("corrupt commit passed startup gate")
	}
	if _, e = applyModel(context.Background(), f, p, request(), m); e == nil {
		t.Fatal("committed file silently repaired")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "corruption" {
		t.Fatal("corrupt evidence overwritten")
	}
}
func TestReboundDescriptorAndUngatedUnitRejected(t *testing.T) {
	f, p, m := fixture(t)
	tx, e := applyModel(context.Background(), f, p, request(), m)
	if e != nil {
		t.Fatal(e)
	}
	bad := tx
	bad.Files = append([]File(nil), tx.Files...)
	bad.Plan.Self.SHA256 = strings.Repeat("b", 64)
	if validFileList(bad) {
		t.Fatal("self pin not bound")
	}
	bad = tx
	bad.Release.Files = append([]Artifact(nil), tx.Release.Files...)
	bad.Release.Files[0].SHA256 = strings.Repeat("b", 64)
	if validFileList(bad) {
		t.Fatal("release descriptor rebound")
	}
	unit := f.root.Name() + UnitDir + "/" + MainUnit
	b, e := os.ReadFile(unit)
	if e != nil {
		t.Fatal(e)
	}
	b = bytes.ReplaceAll(b, []byte("ExecStartPre="+SelfPath+" verify\n"), nil)
	if e = os.WriteFile(unit, b, 0600); e != nil {
		t.Fatal(e)
	}
	// Even coordinated file-list tampering cannot replace the generated gate.
	for i := range tx.Files {
		if tx.Files[i].Path == UnitDir+"/"+MainUnit {
			tx.Files[i].SHA256 = digest(b)
			tx.Files[i].Bytes = int64(len(b))
		}
	}
	if e = f.verifyTransaction(context.Background(), tx); e == nil {
		t.Fatal("ungated unit accepted")
	}
}
func TestCancellationAndInitialManagerRefusalDoNotActivate(t *testing.T) {
	f, p, m := fixture(t)
	m.fail = ErrInventory
	if _, e := applyModel(context.Background(), f, p, request(), m); e == nil {
		t.Fatal("existing manager inventory adopted")
	}
	if yes, _ := f.exists(Root + "/intent.json"); yes {
		t.Fatal("intent before fresh manager refusal")
	}
	m.fail = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := applyModel(ctx, f, p, request(), m); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	unlock, e := f.lock(context.Background(), Root+"/.lock", true)
	if e != nil {
		t.Fatal(e)
	}
	defer unlock()
	if _, e = f.lock(ctx, Root+"/.lock", false); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
}
