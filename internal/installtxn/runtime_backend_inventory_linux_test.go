//go:build linux

package installtxn

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

func backendModel(t *testing.T) (*stopTestModel, *runtimeScope, firecracker.Config, backendInspectionProofs, sandbox.Record) {
	t.Helper()
	f, tx := runtimeShortInstallPrepared(t, func(p *prepared) {
		// Existing generic lifecycle fixture is intentionally minimal/invalid as
		// real backend policy. Use the existing valid policy BEFORE committing,
		// with the fixture's own pinned model assets. Do not relax production.
		_, inputs, _, _ := inputFixture(t)
		cfg, e := firecracker.DecodeInspectionConfig(inputs["backend.json"])
		if e != nil {
			t.Fatal(e)
		}
		art, e := descriptor(p.release)
		if e != nil {
			t.Fatal(e)
		}
		for role, a := range map[string]*firecracker.Asset{"firecracker": &cfg.Firecracker, "jailer": &cfg.Jailer, "warden": &cfg.Warden, "kernel": &cfg.Kernel, "initrd": &cfg.Initrd, "workspace": &cfg.Workspace} {
			a.SHA256 = art[role].SHA256
		}
		data := encode(cfg)
		p.plan.Backend.SHA256 = digest(data)
		generated, e := render(p.plan, cfg.IO.Device, art)
		if e != nil {
			t.Fatal(e)
		}
		generated[Root+"/backend.json"] = data
		for n := range p.targets {
			if b, yes := generated[p.targets[n].file.Path]; yes {
				p.targets[n].data = b
				p.targets[n].file.SHA256 = digest(b)
				p.targets[n].file.Bytes = int64(len(b))
			}
		}
		if _, e = firecracker.DecodeInspectionConfig(data); e != nil {
			t.Fatal(e)
		}
	})
	x := stopModelInstalled(t, "", f, tx)
	s := x.scope(t)
	x.drain(t, s)
	if _, e := x.stop(context.Background(), s, x.client); e != nil {
		t.Fatal(e)
	}
	r, _ := seedCoreModel(t, x)
	raw, e := x.f.read(Root+"/backend.json", 16384, 0600)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := firecracker.DecodeInspectionConfig(raw)
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{stateDir + "/firecracker", runtimeDir + "/j/firecracker"} {
		if e = os.MkdirAll(x.f.root.Name()+p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.WriteFile(x.f.root.Name()+stateDir+"/firecracker/config.json", raw, 0600); e != nil {
		t.Fatal(e)
	}
	proof := backendInspectionProofs{empty: x.proof.empty, cgroup: func(int) error { return nil }, projects: func(_ context.Context, c firecracker.Config, f *os.File, owners []firecracker.InspectionOwnership) (firecracker.InspectionProjects, error) {
		// MODELED quota/mount/IO observation. Actual pinned runtime FD and all
		// original locks/path/metadata/joins are still checked by the adapter.
		st, e := f.Stat()
		if e != nil || !st.IsDir() {
			return firecracker.InspectionProjects{}, ErrInventory
		}
		return firecracker.InspectionProjects{Reserved: c.UIDCount, Empty: c.UIDCount - len(owners), Owned: len(owners), AllReleased: len(owners) == 0}, nil
	}}
	return x, s, cfg, proof, r
}
func inspectBackendModel(ctx context.Context, x *stopTestModel, s *runtimeScope, p backendInspectionProofs) (runtimeBackendInventory, error) {
	return s.inspectStoppedBackendWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), x.manager, p)
}
func writeBackendOwner(t *testing.T, x *stopTestModel, cfg firecracker.Config, r sandbox.Record) firecracker.InspectionOwnership {
	t.Helper()
	o := firecracker.InspectionOwnership{Version: 3, Ref: r.Ref, UID: cfg.UIDStart, ProjectID: cfg.Quota.ProjectStart, QuotaAttempted: true}
	if e := os.WriteFile(x.f.root.Name()+stateDir+"/firecracker/"+r.ID+r.Generation+".json", encode(o), 0600); e != nil {
		t.Fatal(e)
	}
	return o
}
func backendGroup(t *testing.T, x *stopTestModel, path string) {
	t.Helper()
	modelIngressGroup(t, x.f.root.Name()+unitRoot+"/"+path, "populated 0\nfrozen 0\n")
}

func TestRuntimeBackendInventoryObservesColdReleaseOnlyUnderBothOriginalLeases(t *testing.T) {
	x, s, _, proof, _ := backendModel(t)
	before := coreTree(t, x.f.root.Name())
	if _, e := inspectBackendModel(context.Background(), x, s, proof); e == nil {
		t.Fatal("state lease omitted")
	}
	if e := ownStateModel(context.Background(), x, s); e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 2; n++ {
		out, e := inspectBackendModel(context.Background(), x, s, proof)
		if e != nil || !out.BackendInventoryParsed || !out.BackendResourcesAbsent || !out.Core.CoreAuthorityParsed || !out.Projects.AllReleased || out.Owners != 0 || out.Jails != 0 || out.InstanceGroups != 0 || out.NodeEnvelopePresent || out.AcceptedWorkComplete || out.ResourcesReclaimed || out.ActivationAllowed || out.Core.ResourcesReclaimed {
			t.Fatal(out, e)
		}
	}
	if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
		t.Fatal("reader wrote or repaired private inventory")
	}
	s.close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e := runtimeApply(ctx, x.f, x.tx, 0, runtimeReq("c"), "forward", nil); !errors.Is(e, ErrInventory) {
		t.Fatal("backend observation authorized file selection", e)
	}
}

func TestRuntimeBackendInventoryRetainsUnfinishedOwnersNamespacesAndLedger(t *testing.T) {
	for _, kind := range []string{"owned-absent-resources", "owned-nested", "unreclaimed-ledger", "node-envelope"} {
		t.Run(kind, func(t *testing.T) {
			x, s, cfg, proof, r := backendModel(t)
			if kind != "node-envelope" {
				r.State = sandbox.Reclaiming
				r.DestroyedAt = time.Time{}
				writeCoreModel(t, x, "ledger", r.ID, r)
			}
			if strings.HasPrefix(kind, "owned-") {
				writeBackendOwner(t, x, cfg, r)
			}
			if kind == "owned-nested" {
				if e := os.Mkdir(x.f.root.Name()+runtimeDir+"/j/firecracker/"+r.ID+r.Generation, 0700); e != nil {
					t.Fatal(e)
				}
			}
			if kind == "node-envelope" || kind == "owned-nested" {
				for _, p := range []string{"node", "node/control", "node/instances"} {
					backendGroup(t, x, p)
				}
				if kind == "owned-nested" {
					backendGroup(t, x, "node/instances/"+r.ID+r.Generation)
					backendGroup(t, x, "node/instances/"+r.ID+r.Generation+"/jailer-child")
				}
			}
			before := coreTree(t, x.f.root.Name())
			if e := ownStateModel(context.Background(), x, s); e != nil {
				t.Fatal(e)
			}
			out, e := inspectBackendModel(context.Background(), x, s, proof)
			if e != nil || !out.BackendInventoryParsed || out.BackendResourcesAbsent || out.ResourcesReclaimed || out.AcceptedWorkComplete || out.ActivationAllowed {
				t.Fatal(out, e)
			}
			if kind == "owned-nested" && (out.Owners != 1 || out.Jails != 1 || out.InstanceGroups != 1 || !out.NodeEnvelopePresent) {
				t.Fatal(out)
			}
			if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("unfinished resources changed")
			}
		})
	}
}

func TestRuntimeBackendInventoryUnknownBindingsResourcesAndQuotaRefuseWithoutRepair(t *testing.T) {
	for _, kind := range []string{"cold-catalog", "runtime-extra", "j-extra", "unowned-jail", "jail-symlink", "orphan-owner", "terminal-owner", "duplicate-slot", "foreign-uid", "unknown-owner-field", "owner-temp", "wrong-binding", "missing-binding", "owner-filename", "owner-mode", "missing-parent", "unowned-group", "unit-foreign-group", "node-foreign-group", "control-foreign-group", "kernel-frozen", "kernel-populated", "fake-cgroup", "quota-error", "quota-count", "quota-claimed-released"} {
		t.Run(kind, func(t *testing.T) {
			x, s, cfg, proof, r := backendModel(t)
			if e := ownStateModel(context.Background(), x, s); e != nil {
				t.Fatal(e)
			}
			root := x.f.root.Name()
			registry := root + stateDir + "/firecracker"
			check := func(e error) {
				if e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "cold-catalog":
				check(os.Mkdir(registry+"/catalog", 0700))
			case "runtime-extra":
				check(os.WriteFile(root+runtimeDir+"/foreign", []byte("foreign"), 0600))
			case "j-extra":
				check(os.Mkdir(root+runtimeDir+"/j/foreign", 0700))
			case "unowned-jail":
				check(os.Mkdir(root+runtimeDir+"/j/firecracker/"+strings.Repeat("9", 64), 0700))
			case "jail-symlink":
				check(os.Symlink("/arbitrary", root+runtimeDir+"/j/firecracker/"+strings.Repeat("9", 64)))
			case "orphan-owner", "terminal-owner", "duplicate-slot", "foreign-uid", "unknown-owner-field", "owner-filename", "owner-mode":
				if kind != "terminal-owner" {
					r.State = sandbox.Reclaiming
					r.DestroyedAt = time.Time{}
					writeCoreModel(t, x, "ledger", r.ID, r)
				}
				o := writeBackendOwner(t, x, cfg, r)
				path := registry + "/" + r.ID + r.Generation + ".json"
				switch kind {
				case "orphan-owner":
					o.Ref.Generation = runtimeReq("9")
					check(os.Remove(path))
					check(os.WriteFile(registry+"/"+o.Ref.ID+o.Ref.Generation+".json", encode(o), 0600))
				case "duplicate-slot":
					r.ID = runtimeReq("9")
					r.CreateKeyHash = strings.Repeat("a", 64)
					writeCoreModel(t, x, "ledger", r.ID, r)
					writeBackendOwner(t, x, cfg, r)
				case "foreign-uid":
					o.UID--
					check(os.WriteFile(path, encode(o), 0600))
				case "unknown-owner-field":
					b := encode(o)
					check(os.WriteFile(path, append([]byte(`{"foreign":true,`), b[1:]...), 0600))
				case "owner-filename":
					check(os.Rename(path, registry+"/"+strings.Repeat("9", 64)+".json"))
				case "owner-mode":
					check(os.Chmod(path, 0644))
				}
			case "owner-temp":
				check(os.WriteFile(registry+"/.atomic-123", []byte("partial"), 0600))
			case "wrong-binding":
				cfg.UIDStart++
				check(os.WriteFile(registry+"/config.json", encode(cfg), 0600))
			case "missing-binding":
				check(os.Remove(registry + "/config.json"))
			case "missing-parent":
				check(os.Rename(root+runtimeDir+"/j", root+runtimeDir+"/j.old"))
			case "unowned-group":
				backendGroup(t, x, "node")
				backendGroup(t, x, "node/instances")
				backendGroup(t, x, "node/instances/"+strings.Repeat("9", 64))
			case "unit-foreign-group":
				backendGroup(t, x, "foreign")
			case "node-foreign-group":
				backendGroup(t, x, "node")
				backendGroup(t, x, "node/foreign")
			case "control-foreign-group":
				backendGroup(t, x, "node")
				backendGroup(t, x, "node/control")
				backendGroup(t, x, "node/control/foreign")
			case "kernel-frozen", "kernel-populated":
				backendGroup(t, x, "node")
				v := "populated 0\nfrozen 1\n"
				if kind == "kernel-populated" {
					v = "populated 1\nfrozen 0\n"
				}
				p := root + unitRoot + "/node/cgroup.events"
				check(os.Chmod(p, 0600))
				check(os.WriteFile(p, []byte(v), 0600))
				check(os.Chmod(p, 0444))
			case "fake-cgroup":
				proof.cgroup = cgroup2FD
			case "quota-error":
				proof.projects = func(context.Context, firecracker.Config, *os.File, []firecracker.InspectionOwnership) (firecracker.InspectionProjects, error) {
					return firecracker.InspectionProjects{}, unix.EIO
				}
			case "quota-count", "quota-claimed-released":
				proof.projects = func(context.Context, firecracker.Config, *os.File, []firecracker.InspectionOwnership) (firecracker.InspectionProjects, error) {
					return firecracker.InspectionProjects{Reserved: cfg.UIDCount, Empty: cfg.UIDCount - 1, AllReleased: true}, nil
				}
				if kind == "quota-count" {
					proof.projects = func(context.Context, firecracker.Config, *os.File, []firecracker.InspectionOwnership) (firecracker.InspectionProjects, error) {
						return firecracker.InspectionProjects{Reserved: cfg.UIDCount + 1}, nil
					}
				}
			}
			before := coreTree(t, root)
			out, e := inspectBackendModel(context.Background(), x, s, proof)
			if e == nil || out != (runtimeBackendInventory{}) {
				t.Fatal("uncertain backend report escaped", out, e)
			}
			if !reflect.DeepEqual(before, coreTree(t, root)) {
				t.Fatal("invalid backend was repaired")
			}
		})
	}
}

func TestRuntimeBackendInventoryReadBoundariesDriftAndCancellationNeverPublishPartial(t *testing.T) {
	for _, cut := range []string{"runtime-backend-after-registry", "runtime-backend-after-jails", "runtime-backend-after-groups", "runtime-backend-after-quota", "core-drift", "registry-drift", "jail-added", "runtime-rebind", "cancel"} {
		t.Run(cut, func(t *testing.T) {
			x, s, _, proof, r := backendModel(t)
			root := x.f.root.Name()
			if e := ownStateModel(context.Background(), x, s); e != nil {
				t.Fatal(e)
			}
			x.f.hook = func(at string) error {
				if at == cut {
					return interrupted
				}
				if at != "runtime-backend-after-quota" {
					return nil
				}
				switch cut {
				case "core-drift":
					r.LastError = "forward change preserved"
					writeCoreModel(t, x, "ledger", r.ID, r)
				case "registry-drift":
					return os.WriteFile(root+stateDir+"/firecracker/.atomic-123", []byte("partial"), 0600)
				case "jail-added":
					return os.Mkdir(root+runtimeDir+"/j/firecracker/"+strings.Repeat("9", 64), 0700)
				case "runtime-rebind":
					if e := os.Rename(root+runtimeDir, root+runtimeDir+".original"); e != nil {
						return e
					}
					return os.MkdirAll(root+runtimeDir+"/j/firecracker", 0700)
				}
				return nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cut == "cancel" {
				cancel()
			}
			out, e := inspectBackendModel(ctx, x, s, proof)
			if e == nil || out != (runtimeBackendInventory{}) {
				t.Fatal("partial report escaped", out, e)
			}
			if cut == "core-drift" {
				b, e := os.ReadFile(root + stateDir + "/ledger/" + r.ID + ".json")
				if e != nil || !strings.Contains(string(b), "forward change preserved") {
					t.Fatal("forward authority rewound", e)
				}
			}
			if cut == "registry-drift" {
				if _, e := os.Lstat(root + stateDir + "/firecracker/.atomic-123"); e != nil {
					t.Fatal("temp repaired", e)
				}
			}
		})
	}
}

func TestRuntimeBackendInventoryProductionProofsRejectModelsBeforeQuota(t *testing.T) {
	x, s, _, proof, _ := backendModel(t)
	if e := ownStateModel(context.Background(), x, s); e != nil {
		t.Fatal(e)
	}
	if out, e := s.inspectStoppedBackend(context.Background(), digest(encode(x.tx)), runtimeReq("b"), x.manager); e == nil || out != (runtimeBackendInventory{}) {
		t.Fatal("production accepted modeled domains", out, e)
	}
	calls := 0
	proof.cgroup = cgroup2FD
	proof.projects = func(context.Context, firecracker.Config, *os.File, []firecracker.InspectionOwnership) (firecracker.InspectionProjects, error) {
		calls++
		return firecracker.InspectionProjects{}, nil
	}
	if _, e := inspectBackendModel(context.Background(), x, s, proof); e == nil || calls != 0 {
		t.Fatal("fake cgroup reached quota observations", e, calls)
	}
}
