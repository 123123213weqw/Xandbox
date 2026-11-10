//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func maintainModel(ctx context.Context, x *stopTestModel, s *runtimeScope) (runtimeMaintenanceResult, error) {
	return s.maintainWithProof(ctx, digest(encode(x.tx)), runtimeReq("b"), x.client, x.manager, x.proof.process)
}
func (x *stopTestModel) maintain(t *testing.T, s *runtimeScope) {
	t.Helper()
	r, e := maintainModel(context.Background(), x, s)
	if e != nil || !r.MaintenanceHeld || !r.AdmissionDrained || r.AcceptedWorkComplete || r.StopObserved || r.ResourcesReclaimed || r.ActivationAllowed {
		t.Fatal(r, e)
	}
}
func modelMaintenanceIntent(base, operation string, id nodecontrol.ProcessIdentity, before nodecontrol.State) runtimeDrainIntent {
	p := runtimeDrainIntent{Version: 2, Base: base, Request: operation, Process: id, Before: before}
	p.Maintenance = &nodecontrol.MaintenanceRecord{Version: 1, Before: before, Request: nodecontrol.MaintenanceRequest{Version: 1, Owner: nodecontrol.MaintenanceOwner{Version: 1, InstallCommitSHA256: base, OperationID: operation}, Command: nodecontrol.Command{Version: 1, Epoch: before.Epoch, ExpectedRevision: before.Revision, RequestID: maintenanceCommandID(p)}}}
	return p
}

func TestRuntimeMaintenanceV2WALBeforeRPCAndOriginalScopeWithoutFileFlock(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	protected := runtimeProtectedBytes(t, x.f, x.tx)
	stages := map[string]bool{}
	x.f.hook = func(at string) error {
		if at == "runtime-maintenance-before-rpc" || at == "runtime-maintenance-after-rpc" {
			p, e := x.f.runtimeDrainReadIntent()
			if e != nil || !validRuntimeMaintenance(p) {
				return ErrInventory
			}
			if _, e = x.f.startupFilesLocked(context.Background()); !errors.Is(e, ErrInventory) {
				return ErrInventory
			}
			r, e := x.client.MaintenanceStatus(context.Background())
			if e != nil {
				return e
			}
			if at == "runtime-maintenance-before-rpc" && r.Record != nil {
				return ErrConflict
			}
			if at == "runtime-maintenance-after-rpc" && !maintenanceReady(r, p) {
				return ErrConflict
			}
			stages[at] = true
		}
		return nil
	}
	proof := func(ctx context.Context, tx transaction, unit string, id nodecontrol.ProcessIdentity) error {
		file, e := x.f.existingLock(ctx, true)
		if e != nil {
			return e
		}
		file()
		deadline, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
		defer cancel()
		if free, e := x.f.operationLock(deadline, false); e == nil {
			free()
			return errors.New("original OFD lost during RPC")
		} else if !errors.Is(e, context.DeadlineExceeded) {
			return e
		}
		return x.proof.process(ctx, tx, unit, id)
	}
	r, e := s.maintainWithProof(context.Background(), digest(encode(x.tx)), runtimeReq("b"), x.client, x.manager, proof)
	if e != nil || !r.MaintenanceHeld || r.Revision != 2 || !r.WasOpen || len(stages) != 2 {
		t.Fatal(r, e, stages)
	}
	x.f.hook = nil
	again, e := maintainModel(context.Background(), x, s)
	if e != nil || again != r {
		t.Fatal(again, e)
	}
	p, e := x.f.runtimeDrainReadIntent()
	if e != nil || p.Version != 2 || p.Maintenance.Request.Command.RequestID == p.Request {
		t.Fatal(p, e)
	}
	if len(x.jobs) != 0 {
		t.Fatal("maintenance ran stop job", x.jobs)
	}
	unchangedRuntimeProtected(t, x.f, protected)
}

func TestRuntimeMaintenancePreexistingDrainAndOrdinaryResumeCannotBypass(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	r, e := x.client.Status(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	before, e := x.client.Drain(context.Background(), nodecontrol.Command{Version: 1, Epoch: r.Control.Committed.Epoch, ExpectedRevision: r.Control.Committed.Revision, RequestID: runtimeReq("e")})
	if e != nil {
		t.Fatal(e)
	}
	x.maintain(t, s)
	p, e := x.f.runtimeDrainReadIntent()
	if e != nil || p.Before != before.Control.Committed || p.Maintenance.After() != p.Before {
		t.Fatal(p, e)
	}
	legacy, e := nodecontrol.NewClient(x.f.root.Name() + stateDir)
	if e != nil {
		t.Fatal(e)
	}
	defer legacy.Close()
	if _, e = legacy.Change(context.Background(), nodecontrol.ModeOpen, nodecontrol.Command{Version: 1, Epoch: p.Before.Epoch, ExpectedRevision: p.Before.Revision, RequestID: runtimeReq("f")}); e == nil {
		t.Fatal("ordinary resume bypassed owner")
	}
	current, e := x.client.MaintenanceStatus(context.Background())
	if e != nil || current.Control.Committed != before.Control.Committed {
		t.Fatal(current, e)
	}
}

var maintenanceAdapterCuts = []string{"runtime-maintenance-intent-written", "runtime-maintenance-intent-synced", "runtime-maintenance-intent-renamed", "runtime-maintenance-intent-durable", "runtime-maintenance-before-rpc", "runtime-maintenance-after-rpc", "runtime-maintenance-receipt-written", "runtime-maintenance-receipt-synced", "runtime-maintenance-receipt-renamed", "runtime-maintenance-receipt-durable"}

func TestRuntimeMaintenanceWriteAheadCutsFreshScopeRecoversSameBeforeOwnerAndCAS(t *testing.T) {
	for _, cut := range maintenanceAdapterCuts {
		t.Run(cut, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			hit := false
			x.f.hook = func(at string) error {
				if at == cut && !hit {
					hit = true
					return interrupted
				}
				return nil
			}
			if _, e := maintainModel(context.Background(), x, s); !errors.Is(e, interrupted) || !hit {
				t.Fatal("cut missed", e)
			}
			x.f.hook = nil
			original, pending, e := x.f.readMaintenanceIntent()
			if e != nil || !pending {
				t.Fatal(original, pending, e)
			}
			s.close()
			fresh, e := os.Open(x.f.root.Name())
			if e != nil {
				t.Fatal(e)
			}
			defer fresh.Close()
			f := &filesystem{root: fresh}
			next, e := f.beginRuntimeScope(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer next.close()
			m := systemManager{f, x.manager.command}
			r, e := next.maintainWithProof(context.Background(), digest(encode(x.tx)), runtimeReq("b"), x.client, m, x.proof.process)
			if e != nil || !r.MaintenanceHeld || r.Revision != 2 || r.StopObserved || r.ActivationAllowed {
				t.Fatal(r, e)
			}
			p, e := f.runtimeDrainReadIntent()
			if e != nil || !bytes.Equal(encode(p), encode(original)) {
				t.Fatal("Before/CAS/owner regenerated", e)
			}
			if len(x.jobs) != 0 {
				t.Fatal("recovery issued manager mutation")
			}
		})
	}
}

func TestRuntimeMaintenanceUnknownForeignAndPartialWALRefuseUnchanged(t *testing.T) {
	for _, kind := range []string{"empty-prefix", "partial-prefix", "foreign-operation", "duplicate", "old-version", "wrong-CAS", "wrong-before", "unknown-field", "premature-receipt"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			before, e := x.client.Status(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			p := modelMaintenanceIntent(digest(encode(x.tx)), runtimeReq("b"), x.client.Identity(), before.Control.Committed)
			if e = x.f.mkdir(runtimeDrainRoot, 0700); e != nil {
				t.Fatal(e)
			}
			path := x.f.root.Name() + runtimeDrainRoot + "/intent.json"
			raw := encode(p)
			switch kind {
			case "empty-prefix":
				path = x.f.root.Name() + runtimeDrainRoot + "/.intent.json.next"
				raw = nil
			case "partial-prefix":
				path = x.f.root.Name() + runtimeDrainRoot + "/.intent.json.next"
				raw = raw[:17]
			case "foreign-operation":
				p = modelMaintenanceIntent(p.Base, runtimeReq("d"), p.Process, p.Before)
				raw = encode(p)
			case "duplicate":
				if e = os.WriteFile(x.f.root.Name()+runtimeDrainRoot+"/.intent.json.next", raw, 0600); e != nil {
					t.Fatal(e)
				}
			case "old-version":
				p.Version = 1
				raw = encode(p)
			case "wrong-CAS":
				p.Maintenance.Request.Command.RequestID = runtimeReq("d")
				raw = encode(p)
			case "wrong-before":
				p.Maintenance.Before.Epoch = runtimeReq("d")
				raw = encode(p)
			case "unknown-field":
				raw = append([]byte(`{"adopt":true,`), raw[1:]...)
			case "premature-receipt":
				if e = os.WriteFile(x.f.root.Name()+runtimeDrainRoot+"/drain.json", encode(runtimeDrainReceipt{Version: 1, Input: digest(raw), After: drainedRuntimeState(p)}), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if e = os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			snapshot := coreTree(t, x.f.root.Name())
			if _, e = maintainModel(context.Background(), x, s); e == nil {
				t.Fatal("unknown WAL adopted")
			}
			if !reflect.DeepEqual(snapshot, coreTree(t, x.f.root.Name())) {
				t.Fatal("failed coordinator repaired or changed files")
			}
			reply, e := x.client.MaintenanceStatus(context.Background())
			if e != nil || reply.Record != nil || reply.Control.Committed != p.Before {
				t.Fatal(reply, e)
			}
		})
	}
}

func TestRuntimeMaintenanceV1AndV2NeverSilentlyAdoptEachOther(t *testing.T) {
	for _, kind := range []string{"v1-first", "v2-first"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			if kind == "v1-first" {
				x.drain(t, s)
			} else {
				x.maintain(t, s)
			}
			snapshot := coreTree(t, x.f.root.Name())
			var e error
			if kind == "v1-first" {
				_, e = maintainModel(context.Background(), x, s)
			} else {
				_, e = s.drain(context.Background(), digest(encode(x.tx)), runtimeReq("b"), x.client)
			}
			if !errors.Is(e, ErrConflict) || !reflect.DeepEqual(snapshot, coreTree(t, x.f.root.Name())) {
				t.Fatal(e)
			}
		})
	}
}

func TestRuntimeMaintenanceForeignNodeStateOrOwnerNeverOverwritesOriginalIntent(t *testing.T) {
	for _, kind := range []string{"ordinary-drain", "ordinary-resume", "foreign-owner", "held-at-start"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			if kind != "held-at-start" {
				x.f.hook = func(at string) error {
					if at == "runtime-maintenance-before-rpc" {
						return interrupted
					}
					return nil
				}
				if _, e := maintainModel(context.Background(), x, s); !errors.Is(e, interrupted) {
					t.Fatal(e)
				}
				x.f.hook = nil
			}
			status, e := x.client.Status(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			state := status.Control.Committed
			if kind == "foreign-owner" || kind == "held-at-start" {
				other := modelMaintenanceIntent(digest(encode(x.tx)), runtimeReq("e"), x.client.Identity(), state)
				if _, e = x.client.BeginMaintenance(context.Background(), state, other.Maintenance.Request); e != nil {
					t.Fatal(e)
				}
			} else {
				drained, e := x.client.Drain(context.Background(), nodecontrol.Command{Version: 1, Epoch: state.Epoch, ExpectedRevision: state.Revision, RequestID: runtimeReq("e")})
				if e != nil {
					t.Fatal(e)
				}
				if kind == "ordinary-resume" {
					c, e := nodecontrol.NewClient(x.f.root.Name() + stateDir)
					if e != nil {
						t.Fatal(e)
					}
					defer c.Close()
					if _, e = c.Change(context.Background(), nodecontrol.ModeOpen, nodecontrol.Command{Version: 1, Epoch: state.Epoch, ExpectedRevision: drained.Control.Committed.Revision, RequestID: runtimeReq("f")}); e != nil {
						t.Fatal(e)
					}
				}
			}
			before := coreTree(t, x.f.root.Name())
			if _, e = maintainModel(context.Background(), x, s); !errors.Is(e, ErrConflict) {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("foreign state repaired")
			}
			if kind == "held-at-start" {
				if exists, _ := x.f.exists(runtimeDrainRoot); exists {
					t.Fatal("new intent written before ownership verified")
				}
			}
		})
	}
}

func TestRuntimeMaintenanceManagerImageOrCanceledScopeRefuseBeforeNamespace(t *testing.T) {
	for _, kind := range []string{"wrong-image", "foreign-unit", "replacement-main", "real-proof", "canceled", "foreign-manager"} {
		t.Run(kind, func(t *testing.T) {
			modelKind := kind
			if kind == "real-proof" || kind == "canceled" || kind == "foreign-manager" {
				modelKind = ""
			}
			x := stopModel(t, modelKind)
			s := x.scope(t)
			ctx := context.Background()
			if kind == "canceled" {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			var e error
			if kind == "real-proof" {
				_, e = s.maintain(ctx, digest(encode(x.tx)), runtimeReq("b"), x.client, x.manager)
			} else if kind == "foreign-manager" {
				m := x.manager
				m.fs = &filesystem{root: x.f.root}
				_, e = s.maintainWithProof(ctx, digest(encode(x.tx)), runtimeReq("b"), x.client, m, x.proof.process)
			} else {
				_, e = maintainModel(ctx, x, s)
			}
			if e == nil {
				t.Fatal("uncertain process/manager reached intent")
			}
			if exists, _ := x.f.exists(runtimeDrainRoot); exists {
				t.Fatal("refused operation initialized WAL")
			}
			if len(x.jobs) != 0 {
				t.Fatal("refused maintenance issued stop")
			}
		})
	}
}

func TestRuntimeMaintenanceV2StopsOwnProcessesThenJoinsExactStateCoreAuthority(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	seedCoreModel(t, x)
	x.maintain(t, s)
	p, e := x.f.runtimeDrainReadIntent()
	if e != nil {
		t.Fatal(e)
	}
	before := runtimeProtectedBytes(t, x.f, x.tx)
	out, e := x.stop(context.Background(), s, x.client)
	if e != nil || !out.ExecutionStopped || out.AcceptedWorkComplete || out.ResourcesReclaimed || out.ActivationAllowed {
		t.Fatal(out, e)
	}
	if e = ownStateModel(context.Background(), x, s); e != nil {
		t.Fatal(e)
	}
	snapshot := coreTree(t, x.f.root.Name()+stateDir)
	joined, e := inspectCoreModel(context.Background(), x, s)
	if e != nil || !joined.CoreAuthorityParsed || joined.LedgerRecords != 1 || joined.SessionRecords != 1 || joined.AcceptedWorkComplete || joined.ResourcesReclaimed || joined.ActivationAllowed {
		t.Fatal(joined, e)
	}
	if _, _, e = readCoreAuthority(context.Background(), s.state.root, p.Maintenance.After()); e == nil {
		t.Fatal("legacy reader adopted maintenance")
	}
	if !reflect.DeepEqual(snapshot, coreTree(t, x.f.root.Name()+stateDir)) {
		t.Fatal("core join changed state")
	}
	unchangedRuntimeProtected(t, x.f, before)
	if len(x.jobs) != 2 || x.jobs[0] != IngressUnit || x.jobs[1] != MainUnit {
		t.Fatal(x.jobs)
	}
}

func TestRuntimeMaintenanceV2CoreJoinRefusesOwnerAnchorAndPathCorruptionReadOnly(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	seedCoreModel(t, x)
	x.maintain(t, s)
	if _, e := x.stop(context.Background(), s, x.client); e != nil {
		t.Fatal(e)
	}
	if e := ownStateModel(context.Background(), x, s); e != nil {
		t.Fatal(e)
	}
	root := x.f.root.Name() + stateDir
	path := root + "/admission/" + nodecontrol.MaintenanceName
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	anchor, e := os.ReadFile(root + "/maintenance.identity")
	if e != nil {
		t.Fatal(e)
	}
	p, e := x.f.runtimeDrainReadIntent()
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"owner", "before", "anchor", "missing-anchor", "missing-record", "record-mode", "record-link", "record-symlink", "duplicate-scratch", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			check := func(e error) {
				if e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "owner":
				r := *p.Maintenance
				r.Request.Owner.OperationID = runtimeReq("e")
				check(os.WriteFile(path, encode(r), 0600))
				check(os.WriteFile(root+"/maintenance.identity", []byte(`{"version":1,"record_sha256":"`+digest(encode(r))+`"}`), 0600))
			case "before":
				r := *p.Maintenance
				r.Before.Epoch = runtimeReq("e")
				check(os.WriteFile(path, encode(r), 0600))
			case "anchor":
				check(os.WriteFile(root+"/maintenance.identity", []byte(`{"version":1,"record_sha256":"`+strings.Repeat("e", 64)+`"}`), 0600))
			case "missing-anchor":
				check(os.Remove(root + "/maintenance.identity"))
			case "missing-record":
				check(os.Remove(path))
			case "record-mode":
				check(os.Chmod(path, 0644))
			case "record-link":
				check(os.Link(path, root+"/alias"))
			case "record-symlink":
				check(os.Rename(path, root+"/saved-record"))
				check(os.Symlink(root+"/saved-record", path))
			case "duplicate-scratch":
				check(os.WriteFile(root+"/admission/.maintenance-next", original, 0600))
			case "unknown-field":
				check(os.WriteFile(path, append([]byte(`{"adopt":true,`), original[1:]...), 0600))
			}
			snapshot := coreTree(t, root)
			if _, e := inspectCoreModel(context.Background(), x, s); e == nil {
				t.Fatal("uncertain binding accepted")
			}
			if !reflect.DeepEqual(snapshot, coreTree(t, root)) {
				t.Fatal("failed pure join repaired state")
			}
			// TEST-ONLY restoration between independent corruption controls; reader has
			// already been proved effect-free. No genesis/authority adoption in code.
			for _, name := range []string{path, root + "/maintenance.identity", root + "/alias", root + "/saved-record", root + "/admission/.maintenance-next"} {
				if e := os.Remove(name); e != nil && !os.IsNotExist(e) {
					t.Fatal(e)
				}
			}
			check(os.WriteFile(path, original, 0600))
			check(os.WriteFile(root+"/maintenance.identity", anchor, 0600))
		})
	}
}

func TestRuntimeMaintenanceCoreByteSetIncludesAdmissionAndRootBindings(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	seedCoreModel(t, x)
	x.maintain(t, s)
	if _, e := x.stop(context.Background(), s, x.client); e != nil {
		t.Fatal(e)
	}
	if e := ownStateModel(context.Background(), x, s); e != nil {
		t.Fatal(e)
	}
	first, e := inspectCoreModel(context.Background(), x, s)
	if e != nil {
		t.Fatal(e)
	}
	path := x.f.root.Name() + stateDir + "/admission.identity"
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, append(b, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	second, e := inspectCoreModel(context.Background(), x, s)
	if e != nil || first.authorityDigest == second.authorityDigest {
		t.Fatal("root admission binding not byte-set bound", e)
	}
}

func TestRuntimeMaintenanceLegacyCoreRejectsOrphanRootMaintenanceAnchor(t *testing.T) {
	x, s := stoppedCoreModel(t)
	seedCoreModel(t, x)
	if e := ownStateModel(context.Background(), x, s); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(x.f.root.Name()+stateDir+"/maintenance.identity", []byte(`{"version":1,"record_sha256":"`+strings.Repeat("e", 64)+`"}`), 0600); e != nil {
		t.Fatal(e)
	}
	before := coreTree(t, x.f.root.Name()+stateDir)
	if _, e := inspectCoreModel(context.Background(), x, s); e == nil {
		t.Fatal("legacy reader ignored maintenance anchor")
	}
	if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name()+stateDir)) {
		t.Fatal("orphan anchor repaired")
	}
}

func TestRuntimeMaintenanceV2SchemaDistinctCASAndUnchangedV1Encoding(t *testing.T) {
	before := nodecontrol.State{Version: 1, Epoch: runtimeReq("a"), Revision: 1, Mode: nodecontrol.ModeOpen}
	id := nodecontrol.ProcessIdentity{PID: 2, BootID: "11111111-1111-1111-1111-111111111111", StartTicks: 1}
	p := modelMaintenanceIntent(strings.Repeat("a", 64), runtimeReq("b"), id, before)
	if !validRuntimeDrain(p) || p.Maintenance.Request.Command.RequestID == p.Request {
		t.Fatal(p)
	}
	old := p
	old.Version = 1
	old.Maintenance = nil
	want := struct {
		Version int                         `json:"version"`
		Base    string                      `json:"base_commit_sha256"`
		Request string                      `json:"request_id"`
		Process nodecontrol.ProcessIdentity `json:"process"`
		Before  nodecontrol.State           `json:"before"`
	}{1, p.Base, p.Request, p.Process, p.Before}
	if !bytes.Equal(encode(old), encode(want)) {
		t.Fatal("v1 bytes silently changed")
	}
	for _, kind := range []string{"version", "owner", "base", "operation", "CAS", "before", "epoch", "process", "v1-with-owner", "v2-without-owner"} {
		t.Run(kind, func(t *testing.T) {
			copy := p
			record := *p.Maintenance
			copy.Maintenance = &record
			switch kind {
			case "version":
				copy.Version = 3
			case "owner":
				copy.Maintenance.Request.Owner.Version = 2
			case "base":
				copy.Base = strings.Repeat("c", 64)
			case "operation":
				copy.Request = runtimeReq("c")
			case "CAS":
				copy.Maintenance.Request.Command.RequestID = copy.Request
			case "before":
				copy.Before.Mode = nodecontrol.ModeDrained
			case "epoch":
				copy.Maintenance.Request.Command.Epoch = runtimeReq("c")
			case "process":
				copy.Process.StartTicks++
			case "v1-with-owner":
				copy.Version = 1
			case "v2-without-owner":
				copy.Maintenance = nil
			}
			if validRuntimeDrain(copy) {
				t.Fatal("foreign v2 joins accepted")
			}
		})
	}
	before.Mode = nodecontrol.ModeDrained
	before.Revision = math.MaxUint64
	before.LastExpectedRevision = math.MaxUint64 - 1
	before.LastRequestID = runtimeReq("e")
	terminal := modelMaintenanceIntent(p.Base, p.Request, p.Process, before)
	if !validRuntimeDrain(terminal) || drainedRuntimeState(terminal) != before {
		t.Fatal("preexisting terminal drain advanced")
	}
}

func TestRuntimeMaintenanceV2BackendJoinsExactCoreSetAndNeverCertifiesReclaim(t *testing.T) {
	x, s, _, proof, _ := backendModelPrepared(t, func(x *stopTestModel, s *runtimeScope) { x.maintain(t, s) })
	if e := ownStateModel(context.Background(), x, s); e != nil {
		t.Fatal(e)
	}
	before := coreTree(t, x.f.root.Name())
	out, e := inspectBackendModel(context.Background(), x, s, proof)
	if e != nil || !out.BackendInventoryParsed || !out.BackendResourcesAbsent || out.AcceptedWorkComplete || out.ResourcesReclaimed || out.ActivationAllowed {
		t.Fatal(out, e)
	}
	if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
		t.Fatal("backend join changed files")
	}
	hit := false
	x.f.hook = func(at string) error {
		if at == "runtime-backend-after-registry" {
			hit = true
			return os.WriteFile(x.f.root.Name()+stateDir+"/maintenance.identity", []byte(`{"version":1,"record_sha256":"`+strings.Repeat("e", 64)+`"}`), 0600)
		}
		return nil
	}
	if _, e = inspectBackendModel(context.Background(), x, s, proof); e == nil || !hit {
		t.Fatal("backend accepted cross-stage maintenance drift", e)
	}
}

type maintenanceAdapterPrewriteStore struct {
	nodecontrol.MaintenanceStore
	verify func() error
}

func (s maintenanceAdapterPrewriteStore) EnsureMaintenance(r nodecontrol.MaintenanceRecord) error {
	if e := s.verify(); e != nil {
		return e
	}
	return s.MaintenanceStore.EnsureMaintenance(r)
}

func TestRuntimeMaintenanceNodePrewriteFailureStillHasDurableInstallerStartupFence(t *testing.T) {
	f, tx := runtimeShortInstall(t)
	managerLinks(t, f)
	file, e := nodecontrol.OpenStore(f.root.Name() + stateDir)
	if e != nil {
		t.Fatal(e)
	}
	checked := false
	wrapped := maintenanceAdapterPrewriteStore{MaintenanceStore: file, verify: func() error {
		p, e := f.runtimeDrainReadIntent()
		if e != nil || !validRuntimeMaintenance(p) {
			return ErrInventory
		}
		if e = f.exact(runtimeDrainRoot+"/intent.json", encode(p), 0600); e != nil {
			return e
		}
		lockCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		free, e := f.existingLock(lockCtx, true)
		if e != nil {
			return e
		}
		free()
		lockCtx, cancel2 := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel2()
		if free, e = f.operationLock(lockCtx, false); e == nil {
			free()
			return ErrConflict
		} else if !errors.Is(e, context.DeadlineExceeded) {
			return e
		}
		checked = true
		return interrupted // MODEL no node bytes ever accepted.
	}}
	control, e := nodecontrol.New(wrapped, sandbox.NewAdmissionGate(false))
	if e != nil {
		t.Fatal(e)
	}
	server, e := nodecontrol.Start(f.root.Name()+stateDir, control, func() sandbox.Stats { return sandbox.Stats{} })
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close(context.Background())
	client, e := nodecontrol.NewPinnedClient(f.root.Name()+stateDir, os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	before := control.Status().Committed
	manager := systemManager{f, func(_ context.Context, args []string) ([]byte, error) {
		if args[0] != "show" || args[len(args)-1] != MainUnit {
			return nil, ErrPolicy
		}
		return observationBytes(MainUnit, "loaded", "active", "enabled", os.Getpid()), nil
	}}
	proof := func(_ context.Context, _ transaction, unit string, id nodecontrol.ProcessIdentity) error {
		if unit != MainUnit || id.PID != os.Getpid() {
			return ErrConflict
		}
		return nil
	}
	scope, e := f.beginRuntimeScope(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer scope.close()
	if _, e = scope.maintainWithProof(context.Background(), digest(encode(tx)), runtimeReq("b"), client, manager, proof); !errors.Is(e, nodecontrol.ErrFenced) || !checked {
		t.Fatal(e, checked)
	}
	if control.Status().AdmissionOpen {
		t.Fatal("failed begin reopened live admission")
	}
	state, e := file.Load()
	if e != nil || state != before {
		t.Fatal("no-byte model wrote node state", state, e)
	}
	for _, name := range []string{"/admission/" + nodecontrol.MaintenanceName, "/maintenance.identity"} {
		if _, e = os.Lstat(f.root.Name() + stateDir + name); !os.IsNotExist(e) {
			t.Fatal("node wrote durable fence despite model", e)
		}
	}
	// The real existing cap0 startup verifier refuses the durable installer WAL
	// namespace. This is software gate execution, NOT an actual service reboot.
	if _, e = f.startupFilesLocked(context.Background()); !errors.Is(e, ErrInventory) {
		t.Fatal("no-byte node failure bypassed installer startup fence", e)
	}
}

func TestRuntimeMaintenanceUnsupportedNodeNeverFallsBackToOrdinaryDrain(t *testing.T) {
	f, tx, c, control := drainModel(t, nil) // Original Store-only wrapper: no capability.
	managerLinks(t, f)
	m := systemManager{f, func(_ context.Context, args []string) ([]byte, error) {
		if args[0] != "show" || args[len(args)-1] != MainUnit {
			return nil, ErrPolicy
		}
		return observationBytes(MainUnit, "loaded", "active", "enabled", os.Getpid()), nil
	}}
	proof := func(context.Context, transaction, string, nodecontrol.ProcessIdentity) error { return nil }
	s, e := f.beginRuntimeScope(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	if _, e = s.maintainWithProof(context.Background(), digest(encode(tx)), runtimeReq("b"), c, m, proof); !errors.Is(e, nodecontrol.ErrMaintenanceUnsupported) {
		t.Fatal(e)
	}
	if yes, _ := f.exists(runtimeDrainRoot); yes {
		t.Fatal("legacy failure initialized namespace")
	}
	if !control.Status().AdmissionOpen || control.Status().Committed.Revision != 1 {
		t.Fatal("ordinary drain fallback")
	}
}
