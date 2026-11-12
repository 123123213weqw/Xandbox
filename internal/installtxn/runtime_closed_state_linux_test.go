//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/diagnostics"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"golang.org/x/sys/unix"
)

func closedStateModel(t *testing.T) (*stopTestModel, *runtimeScope, *runtimeStoppedWorkProof, backendInspectionProofs) {
	t.Helper()
	return closedStateModelMetrics(t, true)
}
func closedStateModelMetrics(t *testing.T, metrics bool) (*stopTestModel, *runtimeScope, *runtimeStoppedWorkProof, backendInspectionProofs) {
	t.Helper()
	return closedStateModelMetricsWithInitial(t, metrics, closedStateInitialModel)
}

// TEST-only constructor selection; every post-initialization Stop, strict root,
// diagnostics and backend/model proof below is shared unchanged with restart.
func closedStateModelMetricsWithInitial(t *testing.T, metrics bool, initial func(*testing.T, *filesystem, transaction) *stopTestModel) (*stopTestModel, *runtimeScope, *runtimeStoppedWorkProof, backendInspectionProofs) {
	t.Helper()
	if initial == nil {
		t.Fatal("owned TEST initial main constructor required")
	}
	f, tx := runtimeShortInstallPrepared(t, func(p *prepared) {
		p.plan.Frontend.Metrics = metrics
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
	})
	x := initial(t, f, tx)
	s := x.scope(t)
	x.maintain(t, s)
	ctx, cancel := workStopContext(t)
	defer cancel()
	p, e := finishStopModel(ctx, x, s)
	if e != nil || p == nil {
		t.Fatal(p, e)
	}
	raw, e := f.read(Root+"/backend.json", 16384, 0600)
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{stateDir + "/firecracker", stateDir + "/diagnostics", runtimeDir + "/j/firecracker"} {
		if e = os.MkdirAll(f.root.Name()+path, 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.WriteFile(f.root.Name()+stateDir+"/firecracker/config.json", raw, 0600); e != nil {
		t.Fatal(e)
	}
	// Explicit synthetic ordinary-format ring, bound to the installed canonical
	// path rather than the shadow prefix. Ordinary-writer interoperability is
	// independently tested in diagnostics; this fixture is NOT a daemon/KVM.
	ring := make([]byte, diagnostics.RingBytes)
	copy(ring[:8], []byte{'X', 'B', 'D', 'R', 'I', 'N', 'G', 1})
	binary.LittleEndian.PutUint32(ring[8:12], 1)
	binary.LittleEndian.PutUint32(ring[12:16], diagnostics.RetainedRecords)
	binary.LittleEndian.PutUint32(ring[16:20], diagnostics.FrameBytes)
	scope := sha256.Sum256([]byte("Xandbox daemon diagnostics v1\x00" + stateDir + "/diagnostics"))
	copy(ring[32:64], scope[:])
	binary.LittleEndian.PutUint32(ring[124:128], crc32.Checksum(ring[:124], crc32.MakeTable(crc32.Castagnoli)))
	if e = os.WriteFile(f.root.Name()+stateDir+"/diagnostics/events.ring", ring, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(f.root.Name()+stateDir+"/diagnostics/logger.lock", nil, 0600); e != nil {
		t.Fatal(e)
	}
	proof := backendInspectionProofs{empty: x.proof.empty, cgroup: func(int) error { return nil }, projects: func(_ context.Context, c firecracker.Config, root *os.File, owners []firecracker.InspectionOwnership) (firecracker.InspectionProjects, error) {
		if st, e := root.Stat(); e != nil || !st.IsDir() {
			return firecracker.InspectionProjects{}, ErrInventory
		}
		return firecracker.InspectionProjects{Reserved: c.UIDCount, Empty: c.UIDCount - len(owners), Owned: len(owners), AllReleased: len(owners) == 0}, nil
	}}
	return x, s, p, proof
}

func inspectClosedStateModel(ctx context.Context, x *stopTestModel, s *runtimeScope, p *runtimeStoppedWorkProof, proof backendInspectionProofs) (runtimeClosedStateInventory, error) {
	return s.inspectClosedStateWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), p, x.manager, proof)
}

func closedStateRefusesUnchanged(t *testing.T, ctx context.Context, x *stopTestModel, s *runtimeScope, p *runtimeStoppedWorkProof, proof backendInspectionProofs) {
	t.Helper()
	before := coreTree(t, x.f.root.Name())
	if v, e := inspectClosedStateModel(ctx, x, s, p, proof); e == nil || v != (runtimeClosedStateInventory{}) {
		t.Fatal("partial/accepted refused join", v, e)
	}
	if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
		t.Fatal("refusal mutated original tree")
	}
}

func TestRuntimeCoreClosedStateJoinsWholePopulatedOriginalReadOnly(t *testing.T) {
	x, s, p, proof := closedStateModel(t)
	ctx, cancel := workStopContext(t)
	defer cancel()
	before := coreTree(t, x.f.root.Name())
	for n := 0; n < 2; n++ {
		v, e := inspectClosedStateModel(ctx, x, s, p, proof)
		if e != nil || !v.ClosedStateJoined || !v.Terminal.RawTerminalMatched || !v.Backend.BackendResourcesAbsent || v.Terminal.Core != v.Backend.Core || v.Terminal.CoreTerminal.Records != 1 || v.Terminal.SessionTerminal.Records != 1 || !digestPattern.MatchString(v.State.digest) || v.State.Files != 10 || v.State.Sockets != 1 || v.ResourcesReclaimed || v.ActivationAllowed || v.Backend.ResourcesReclaimed {
			t.Fatal(v, e)
		}
	}
	if len(x.jobs) != 2 || !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
		t.Fatal("join changed tree/jobs")
	}
	if v, e := s.inspectClosedState(ctx, digest(encode(x.tx)), runtimeReq("b"), p, x.manager); e == nil || v != (runtimeClosedStateInventory{}) {
		t.Fatal("production accepted model kernel/mount", v, e)
	}
}

func TestRuntimeCoreClosedStateUnknownRootNamespacesAndTypesRefuseWithoutRepair(t *testing.T) {
	x, s, p, proof := closedStateModel(t)
	ctx, cancel := workStopContext(t)
	defer cancel()
	root := x.f.root.Name() + stateDir
	for _, name := range []string{"catalog", "results", "instances", "unknown", ".identity-123", "node", "unknown.sock"} {
		t.Run(name, func(t *testing.T) {
			path := root + "/" + name
			if e := os.Mkdir(path, 0700); e != nil {
				t.Fatal(e)
			}
			closedStateRefusesUnchanged(t, ctx, x, s, p, proof)
			if e := os.Remove(path); e != nil {
				t.Fatal(e)
			}
		})
	}
	for _, kind := range []string{"symlink", "hardlink", "fifo", "public-socket", "socket-file"} {
		t.Run(kind, func(t *testing.T) {
			path := root + "/api.sock"
			switch kind {
			case "symlink":
				if e := os.Symlink(root+"/admission.identity", path); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(root+"/admission.identity", path); e != nil {
					t.Fatal(e)
				}
			case "fifo":
				if e := unix.Mkfifo(path, 0600); e != nil {
					t.Fatal(e)
				}
			case "public-socket":
				socketModel(t, path)
				if e := os.Chmod(path, 0666); e != nil {
					t.Fatal(e)
				}
			case "socket-file":
				if e := os.WriteFile(path, nil, 0600); e != nil {
					t.Fatal(e)
				}
			}
			closedStateRefusesUnchanged(t, ctx, x, s, p, proof)
			if e := os.Remove(path); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func socketModel(t *testing.T, path string) {
	t.Helper()
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	l.SetUnlinkOnClose(false)
	if e = l.Close(); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
}

func TestRuntimeCoreClosedStateOptionalSocketsRespectOriginalLaunchMetrics(t *testing.T) {
	for _, metrics := range []bool{false, true} {
		t.Run(map[bool]string{false: "metrics-disabled", true: "metrics-enabled"}[metrics], func(t *testing.T) {
			x, s, p, proof := closedStateModelMetrics(t, metrics)
			ctx, cancel := workStopContext(t)
			defer cancel()
			socketModel(t, x.f.root.Name()+stateDir+"/api.sock")
			socketModel(t, x.f.root.Name()+stateDir+"/metrics.sock")
			if !metrics {
				closedStateRefusesUnchanged(t, ctx, x, s, p, proof)
				return
			}
			before := coreTree(t, x.f.root.Name())
			v, e := inspectClosedStateModel(ctx, x, s, p, proof)
			if e != nil || !v.ClosedStateJoined || v.State.Sockets != 3 || !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal(v, e)
			}
		})
	}
}

func TestRuntimeCoreClosedStateDiagnosticNamespaceBoundsAndFramesRefuse(t *testing.T) {
	x, s, p, proof := closedStateModel(t)
	ctx, cancel := workStopContext(t)
	defer cancel()
	dir := x.f.root.Name() + stateDir + "/diagnostics"
	path := dir + "/events.ring"
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"missing-ring", "missing-lock", "unknown", "size-short", "size-long", "scope", "headers", "ring-mode", "lock-nonempty", "directory-mode"} {
		t.Run(kind, func(t *testing.T) {
			b := bytes.Clone(original)
			switch kind {
			case "missing-ring":
				if e = os.Remove(path); e != nil {
					t.Fatal(e)
				}
			case "missing-lock":
				if e = os.Remove(dir + "/logger.lock"); e != nil {
					t.Fatal(e)
				}
			case "unknown":
				if e = os.WriteFile(dir+"/unknown", nil, 0600); e != nil {
					t.Fatal(e)
				}
			case "size-short":
				if e = os.WriteFile(path, b[:len(b)-1], 0600); e != nil {
					t.Fatal(e)
				}
			case "size-long":
				if e = os.WriteFile(path, append(b, 0), 0600); e != nil {
					t.Fatal(e)
				}
			case "scope":
				b[32] ^= 1
				binary.LittleEndian.PutUint32(b[124:], crc32.Checksum(b[:124], crc32.MakeTable(crc32.Castagnoli)))
				if e = os.WriteFile(path, b, 0600); e != nil {
					t.Fatal(e)
				}
			case "headers":
				b[0] ^= 1
				if e = os.WriteFile(path, b, 0600); e != nil {
					t.Fatal(e)
				}
			case "ring-mode":
				if e = os.Chmod(path, 0644); e != nil {
					t.Fatal(e)
				}
			case "lock-nonempty":
				if e = os.WriteFile(dir+"/logger.lock", []byte("x"), 0600); e != nil {
					t.Fatal(e)
				}
			case "directory-mode":
				if e = os.Chmod(dir, 0755); e != nil {
					t.Fatal(e)
				}
			}
			closedStateRefusesUnchanged(t, ctx, x, s, p, proof)
			if kind == "unknown" {
				if e = os.Remove(dir + "/unknown"); e != nil {
					t.Fatal(e)
				}
			}
			if e = os.Chmod(dir, 0700); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(path, original, 0600); e != nil {
				t.Fatal(e)
			}
			if e = os.Chmod(path, 0600); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(dir+"/logger.lock", nil, 0600); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestRuntimeCoreClosedStateEveryOpaqueBindingAndContextRequired(t *testing.T) {
	x, s, p, proof := closedStateModel(t)
	ctx, cancel := workStopContext(t)
	defer cancel()
	for _, kind := range []string{"intent", "completion", "closure", "stop", "state", "scope", "nil", "unbounded", "canceled", "nil-empty", "nil-cgroup", "nil-projects"} {
		t.Run(kind, func(t *testing.T) {
			copy := *p
			ptr := &copy
			c := ctx
			pr := proof
			switch kind {
			case "intent":
				copy.intent = strings.Repeat("0", 64)
			case "completion":
				copy.completion = strings.Repeat("0", 64)
			case "closure":
				copy.closure = strings.Repeat("0", 64)
			case "stop":
				copy.stop = strings.Repeat("0", 64)
			case "state":
				copy.state.LockInode++
			case "scope":
				copy.scope = &runtimeScope{fs: x.f}
			case "nil":
				ptr = nil
			case "unbounded":
				c = context.Background()
			case "canceled":
				var done context.CancelFunc
				c, done = context.WithCancel(ctx)
				done()
			case "nil-empty":
				pr.empty = nil
			case "nil-cgroup":
				pr.cgroup = nil
			case "nil-projects":
				pr.projects = nil
			}
			closedStateRefusesUnchanged(t, c, x, s, ptr, pr)
		})
	}
	s.close()
	closedStateRefusesUnchanged(t, ctx, x, s, p, proof)
}

func TestRuntimeCoreClosedStateBoundaryErrorsReturnNoPartialObservation(t *testing.T) {
	x, s, p, proof := closedStateModel(t)
	ctx, cancel := workStopContext(t)
	defer cancel()
	for _, stage := range []string{"runtime-closed-state-after-root", "runtime-closed-state-after-backend", "runtime-closed-state-after-terminal", "runtime-terminal-after-core", "runtime-backend-after-quota"} {
		t.Run(stage, func(t *testing.T) {
			hit := false
			x.f.hook = func(at string) error {
				if at == stage {
					hit = true
					return interrupted
				}
				return nil
			}
			closedStateRefusesUnchanged(t, ctx, x, s, p, proof)
			if !hit {
				t.Fatal("cut not visited")
			}
			x.f.hook = nil
		})
	}
}

func TestRuntimeCoreClosedStateWholeRawBytesAndMetadataDriftNeverJoin(t *testing.T) {
	for _, kind := range []string{"diagnostic-staging-raw", "config-format", "record-format", "socket-mode", "root-added"} {
		t.Run(kind, func(t *testing.T) {
			x, s, p, proof := closedStateModel(t)
			ctx, cancel := workStopContext(t)
			defer cancel()
			hit := false
			x.f.hook = func(stage string) error {
				if stage != "runtime-closed-state-after-backend" || hit {
					return nil
				}
				hit = true
				root := x.f.root.Name() + stateDir
				path := ""
				switch kind {
				case "diagnostic-staging-raw":
					path = root + "/diagnostics/events.ring"
				case "config-format":
					path = root + "/firecracker/config.json"
				case "record-format":
					path = terminalRecordPath(t, x, true)
				case "socket-mode":
					return os.Chmod(root+"/operator.sock", 0644)
				case "root-added":
					return os.WriteFile(root+"/unknown", []byte("untouched"), 0600)
				}
				b, e := os.ReadFile(path)
				if e != nil {
					return e
				}
				if kind == "diagnostic-staging-raw" {
					b[len(b)-1] ^= 1
				} else {
					b = append([]byte(" \n"), b...)
				}
				return os.WriteFile(path, b, 0600)
			}
			if v, e := inspectClosedStateModel(ctx, x, s, p, proof); e == nil || v != (runtimeClosedStateInventory{}) || !hit {
				t.Fatal(v, e, hit)
			}
			after := coreTree(t, x.f.root.Name())
			x.f.hook = nil
			// A NEW observation may read a stable, ordinarily compatible raw-only
			// rewrite. There is no historical diagnostic/raw-format anchor. It may
			// never repair bytes, publish a partial error or grant activation.
			v, e := inspectClosedStateModel(ctx, x, s, p, proof)
			if e != nil && v != (runtimeClosedStateInventory{}) || v.ActivationAllowed || v.ResourcesReclaimed {
				t.Fatal(v, e)
			}
			if !reflect.DeepEqual(after, coreTree(t, x.f.root.Name())) {
				t.Fatal("drift repaired")
			}
		})
	}
}

func TestRuntimeCoreClosedStateFinalQuotaCallbackChangesAreRejoined(t *testing.T) {
	for _, kind := range []string{"quota-shape", "jail", "node-envelope", "registry", "source", "close-anchor", "diagnostic"} {
		t.Run(kind, func(t *testing.T) {
			x, s, p, proof := closedStateModel(t)
			ctx, cancel := workStopContext(t)
			defer cancel()
			original := proof.projects
			calls := 0
			proof.projects = func(c context.Context, cfg firecracker.Config, root *os.File, owners []firecracker.InspectionOwnership) (firecracker.InspectionProjects, error) {
				calls++
				v, e := original(c, cfg, root, owners)
				if calls != 2 || e != nil {
					return v, e
				}
				base := x.f.root.Name()
				switch kind {
				case "quota-shape":
					v.AllReleased = false
				case "jail":
					e = os.Mkdir(base+runtimeDir+"/j/firecracker/unknown", 0700)
				case "node-envelope":
					backendGroup(t, x, "node")
				case "registry":
					e = os.WriteFile(base+stateDir+"/firecracker/unknown", nil, 0600)
				case "source":
					e = os.WriteFile(base+Root+"/backend.json", []byte("bad"), 0600)
				case "close-anchor":
					e = os.WriteFile(base+runtimeCloseAnchor, []byte("bad"), 0600)
				case "diagnostic":
					e = os.WriteFile(base+stateDir+"/diagnostics/logger.lock", []byte("bad"), 0600)
				}
				return v, e
			}
			if v, e := inspectClosedStateModel(ctx, x, s, p, proof); e == nil || v != (runtimeClosedStateInventory{}) || calls != 2 {
				t.Fatal(v, e, calls)
			}
		})
	}
}

func TestRuntimeCoreClosedStateSameScopeExcludesCloseWithoutFileFlockCallback(t *testing.T) {
	x, s, p, proof := closedStateModel(t)
	ctx, cancel := workStopContext(t)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	first := true
	original := proof.empty
	proof.empty = func(unit string) error {
		if first {
			first = false
			unlock, e := x.f.existingLock(ctx, true)
			if e != nil {
				return e
			}
			unlock()
			close(entered)
			<-release
		}
		return original(unit)
	}
	done := make(chan error, 1)
	go func() { _, e := inspectClosedStateModel(ctx, x, s, p, proof); done <- e }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	closed := make(chan struct{})
	go func() { s.close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("scope closed during joined observation")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestRuntimeCoreClosedStateLeaseRebindingAndForeignManagerRefuse(t *testing.T) {
	x, s, p, proof := closedStateModel(t)
	ctx, cancel := workStopContext(t)
	defer cancel()
	foreign := x.manager
	foreign.fs = &filesystem{root: x.f.root}
	if v, e := s.inspectClosedStateWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), p, foreign, proof); e == nil || v != (runtimeClosedStateInventory{}) {
		t.Fatal(v, e)
	}
	path := x.f.root.Name() + stateDir + "/controller.lock"
	if e := os.Rename(path, path+".old"); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, nil, 0600); e != nil {
		t.Fatal(e)
	}
	closedStateRefusesUnchanged(t, ctx, x, s, p, proof)
}

func TestRuntimeCoreClosedStateObservationDoesNotAuthorizeStartupOrFileExchange(t *testing.T) {
	x, s, p, proof := closedStateModel(t)
	ctx, cancel := workStopContext(t)
	defer cancel()
	if v, e := inspectClosedStateModel(ctx, x, s, p, proof); e != nil || !v.ClosedStateJoined || v.ActivationAllowed || v.ResourcesReclaimed {
		t.Fatal(v, e)
	}
	if _, e := x.f.startupFilesLocked(ctx); e == nil {
		t.Fatal("join opened startup")
	}
	s.close()
	before := coreTree(t, x.f.root.Name())
	if _, e := runtimeApply(ctx, x.f, x.tx, 0, runtimeReq("c"), "forward", nil); !errors.Is(e, ErrInventory) {
		t.Fatal("joined observation bypassed old raw fence", e)
	}
	if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
		t.Fatal("raw refusal wrote")
	}
}
