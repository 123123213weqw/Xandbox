//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/diagnostics"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"golang.org/x/sys/unix"
)

// Authentic owned V2 result actor/work/close/Stop/retained-FD path. Only the
// backend label, cold config/diagnostic format, manager and kernel positives
// are explicit TEST MODELS. No forged result/closure receipt is installed.
func resultsStateModel(t *testing.T, metrics bool) (*stopTestModel, *runtimeScope, *runtimeResultsStoppedWorkProof, backendInspectionProofs) {
	t.Helper()
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
	var seed resultsWALFixtureSeed
	x := stopModelInstalledWithMain(t, "", f, tx, func() *exec.Cmd {
		var e error
		seed, e = seedResultsWALOriginalState(f)
		if e != nil {
			t.Fatal(e)
		}
		return resultsWALDaemon(t, f.root.Name(), "state-join-firecracker-model")
	})
	statusCtx, done := context.WithTimeout(context.Background(), 2*time.Second)
	status, e := x.client.Status(statusCtx)
	done()
	if e != nil || status.Control != seed.before || x.client.Identity().PID != x.children[MainUnit].Process.Pid {
		t.Fatal("actual original V2 actor did not reload entire seed", status.Control, seed.before, e)
	}
	s := x.scope(t)
	x.maintain(t, s)
	ctx, cancel := workStopContext(t)
	defer cancel()
	p, e := stopResultsModel(ctx, x, s)
	if e != nil || p == nil || s.state == nil || p.closed.observation.Core.Results.Records != 1 || len(x.jobs) != 2 {
		t.Fatal("authentic result-bound actor closure/Stop/lease unavailable", p, e, x.jobs)
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

func inspectResultsStateModel(ctx context.Context, x *stopTestModel, s *runtimeScope, p *runtimeResultsStoppedWorkProof, proof backendInspectionProofs) (runtimeResultsStateInventory, error) {
	return s.inspectResultsStoppedStateWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), p, x.manager, proof)
}
func resultsStateRefusesUnchanged(t *testing.T, x *stopTestModel, s *runtimeScope, p *runtimeResultsStoppedWorkProof, proof backendInspectionProofs) {
	t.Helper()
	ctx, cancel := workStopContext(t)
	defer cancel()
	before := coreTree(t, x.f.root.Name())
	jobs := append([]string(nil), x.jobs...)
	v, e := inspectResultsStateModel(ctx, x, s, p, proof)
	if e == nil || v != (runtimeResultsStateInventory{}) || !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) || !reflect.DeepEqual(jobs, x.jobs) {
		t.Fatal("unknown result state accepted, partial observation or mutation", v, e)
	}
}
func resultStateRow(t *testing.T, x *stopTestModel, dir string) string {
	t.Helper()
	entries, e := os.ReadDir(x.f.root.Name() + stateDir + "/" + dir)
	if e != nil {
		t.Fatal(e)
	}
	var rows []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			rows = append(rows, e.Name())
		}
	}
	if len(rows) != 1 {
		t.Fatal("one actual owned row required", dir, rows)
	}
	return x.f.root.Name() + stateDir + "/" + dir + "/" + rows[0]
}

func TestRuntimeResultsStopStateJoinsAuthenticActorCurrentBytesAndBackendWithoutAuthority(t *testing.T) {
	for _, metrics := range []bool{false, true} {
		name := "metrics-disabled"
		if metrics {
			name = "metrics-enabled"
		}
		t.Run(name, func(t *testing.T) {
			x, s, p, proof := resultsStateModel(t, metrics)
			ctx, cancel := workStopContext(t)
			defer cancel()
			before := coreTree(t, x.f.root.Name())
			protected := runtimeProtectedBytes(t, x.f, x.tx)
			fd := s.state.lock.Fd()
			if v, e := s.inspectResultsStoppedState(ctx, digest(encode(x.tx)), runtimeReq("b"), p, x.manager); e == nil || v != (runtimeResultsStateInventory{}) {
				t.Fatal("production kernel/quota proof accepted explicit MODEL", v, e)
			}
			tail := false
			counts := map[string]int{}
			check := func() {
				t.Helper()
				if tail {
					t.Fatal("external callback after final byte-tail boundary")
				}
				unlock, e := x.f.existingLock(ctx, true)
				if e != nil {
					t.Fatal("file flock held across external observation", e)
				}
				unlock()
			}
			originalManager := x.manager.command
			x.manager.command = func(c context.Context, args []string) ([]byte, error) { check(); return originalManager(c, args) }
			empty, cgroup, quota := proof.empty, proof.cgroup, proof.projects
			proof.empty = func(unit string) error { check(); return empty(unit) }
			proof.cgroup = func(fd int) error { check(); return cgroup(fd) }
			proof.projects = func(c context.Context, cfg firecracker.Config, root *os.File, owners []firecracker.InspectionOwnership) (firecracker.InspectionProjects, error) {
				check()
				return quota(c, cfg, root, owners)
			}
			x.f.hook = func(at string) error {
				counts[at]++
				if at == "runtime-results-state-before-final-root" {
					tail = true
				}
				return nil
			}
			var first runtimeResultsStateInventory
			for n := 0; n < 2; n++ {
				tail = false
				v, e := inspectResultsStateModel(ctx, x, s, p, proof)
				if e != nil || !v.ResultsStateJoined || !v.BackendResourcesAbsent || !v.Retained.DiskResultBytesMatched || v.Retained.Results != p.closed.observation.Core.Results || v.Retained.CoreTerminal != p.closed.observation.Core.Core || v.Retained.SessionTerminal != p.closed.observation.Sessions || v.Retained.Results.Records != 1 || v.Retained.Core.LedgerNonterminal != 0 || v.Retained.Core.SessionNonterminal != 0 || !digestPattern.MatchString(v.Retained.State.digest) || v.ResourcesReclaimed || v.ActivationAllowed || v.Retained.ResourcesReclaimed || v.Retained.ActivationAllowed || s.state.lock.Fd() != fd || len(x.jobs) != 2 {
					t.Fatal("original V2/Stop/current-root/backend join incomplete or authority widened", v, e)
				}
				if n == 0 {
					first = v
				} else if v != first {
					t.Fatal("read-only repeat changed current observation", first, v)
				}
			}
			x.f.hook = nil
			for _, at := range []string{"runtime-results-state-after-root", "runtime-results-state-after-backend", "runtime-results-state-after-peer", "runtime-results-state-before-final-root"} {
				if counts[at] != 2 {
					t.Fatal(at, counts)
				}
			}
			if len(counts) != 4 || !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("unexpected mutator/hook or root change", counts)
			}
			unchangedRuntimeProtected(t, x.f, protected)
		})
	}
}

func TestRuntimeResultsStopStateRejectsUnboundProofScopeContextAndKernelSeams(t *testing.T) {
	x, s, p, proof := resultsStateModel(t, true)
	for _, kind := range []string{"nil", "scope", "closed-scope", "stop", "work", "closure", "observation", "state", "unbounded", "cancelled", "foreign-manager", "nil-empty", "nil-cgroup", "nil-quota"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := workStopContext(t)
			defer cancel()
			fake := *p
			input := &fake
			target := s
			m := x.manager
			pr := proof
			switch kind {
			case "nil":
				input = nil
			case "scope":
				fake.scope = &runtimeScope{}
			case "closed-scope":
				target = &runtimeScope{fs: x.f, rootID: s.rootID}
				fake.scope = target
				fake.closed.scope = target
			case "stop":
				fake.stop = strings.Repeat("e", 64)
			case "work":
				fake.closed.work = strings.Repeat("e", 64)
			case "closure":
				fake.closed.closure = strings.Repeat("e", 64)
			case "observation":
				fake.closed.observation.Core.Results.Records++
			case "state":
				fake.state.LockInode++
			case "unbounded":
				ctx = context.Background()
			case "cancelled":
				cancel()
			case "foreign-manager":
				m.fs = &filesystem{root: x.f.root}
			case "nil-empty":
				pr.empty = nil
			case "nil-cgroup":
				pr.cgroup = nil
			case "nil-quota":
				pr.projects = nil
			}
			before := coreTree(t, x.f.root.Name())
			jobs := append([]string(nil), x.jobs...)
			v, e := target.inspectResultsStoppedStateWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), input, m, pr)
			if e == nil || v != (runtimeResultsStateInventory{}) || !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) || !reflect.DeepEqual(jobs, x.jobs) {
				t.Fatal("unbound proof/scope or context accepted or mutation", v, e)
			}
			if kind == "cancelled" && !errors.Is(e, context.Canceled) {
				t.Fatal("cancel cause lost", e)
			}
		})
	}
}

func TestRuntimeResultsStopStateUnknownCurrentNamespacesAndCorruptRowsRemainUntouched(t *testing.T) {
	x, s, p, proof := resultsStateModel(t, true)
	for _, kind := range []string{"unknown-state", "unknown-result", "orphan-result", "corrupt-result", "result-mode", "corrupt-ledger", "corrupt-session", "corrupt-admission", "corrupt-maintenance", "corrupt-diagnostics", "backend-catalog", "backend-owner"} {
		t.Run(kind, func(t *testing.T) {
			root := x.f.root.Name() + stateDir
			var cleanup func()
			switch kind {
			case "unknown-state", "backend-catalog":
				path := root + "/instances"
				if kind == "backend-catalog" {
					path = root + "/firecracker/catalog"
				}
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
				cleanup = func() {
					if e := os.Remove(path); e != nil {
						t.Fatal(e)
					}
				}
			case "unknown-result", "orphan-result", "backend-owner":
				path := root + "/results/.unknown.next"
				b := []byte("PRESERVE_UNKNOWN_TEST_PREFIX")
				if kind == "orphan-result" {
					path = root + "/results/" + runtimeReq("e") + ".json"
					var e error
					b, e = os.ReadFile(resultStateRow(t, x, "results"))
					if e != nil {
						t.Fatal(e)
					}
				}
				if kind == "backend-owner" {
					path = root + "/firecracker/" + strings.Repeat("e", 64) + ".json"
				}
				if e := os.WriteFile(path, b, 0600); e != nil {
					t.Fatal(e)
				}
				cleanup = func() {
					if e := os.Remove(path); e != nil {
						t.Fatal(e)
					}
				}
			default:
				path := resultStateRow(t, x, "results")
				switch kind {
				case "corrupt-ledger":
					path = resultStateRow(t, x, "ledger")
				case "corrupt-session":
					path = resultStateRow(t, x, "sessions")
				case "corrupt-admission":
					path = root + "/admission/state.json"
				case "corrupt-maintenance":
					path = root + "/admission/" + nodecontrol.MaintenanceName
				case "corrupt-diagnostics":
					path = root + "/diagnostics/events.ring"
				}
				b, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				if kind == "result-mode" {
					if e = os.Chmod(path, 0644); e != nil {
						t.Fatal(e)
					}
					cleanup = func() {
						if e := os.Chmod(path, 0600); e != nil {
							t.Fatal(e)
						}
					}
				} else {
					if e = os.WriteFile(path, []byte("CORRUPT_OWNED_TEST_ROW"), 0600); e != nil {
						t.Fatal(e)
					}
					cleanup = func() {
						if e := os.WriteFile(path, b, 0600); e != nil {
							t.Fatal(e)
						}
					}
				}
			}
			defer cleanup()
			resultsStateRefusesUnchanged(t, x, s, p, proof)
		})
	}
}

func TestRuntimeResultsStopStateLateBoundariesRejoinSourceResultsAndReceipts(t *testing.T) {
	for _, at := range []string{"runtime-results-state-after-root", "runtime-results-state-after-backend", "runtime-results-state-after-peer", "runtime-results-state-before-final-root"} {
		t.Run(at, func(t *testing.T) {
			x, s, p, proof := resultsStateModel(t, true)
			for _, kind := range []string{"source", "result", "receipt"} {
				t.Run(kind, func(t *testing.T) {
					path := x.f.root.Name() + Root + "/backend.json"
					if kind == "result" {
						path = resultStateRow(t, x, "results")
					}
					if kind == "receipt" {
						path = x.f.root.Name() + runtimeResultsStopRoot + "/stopped.json"
					}
					b, e := os.ReadFile(path)
					if e != nil {
						t.Fatal(e)
					}
					defer func() {
						x.f.hook = nil
						if e := os.WriteFile(path, b, 0600); e != nil {
							t.Fatal(e)
						}
					}()
					hit := false
					var after map[string]string
					x.f.hook = func(stage string) error {
						if stage == at && !hit {
							hit = true
							if e := os.WriteFile(path, []byte("PRESERVE_LATE_TEST_MUTATION"), 0600); e != nil {
								return e
							}
							after = coreTree(t, x.f.root.Name())
						}
						return nil
					}
					ctx, cancel := workStopContext(t)
					defer cancel()
					v, e := inspectResultsStateModel(ctx, x, s, p, proof)
					if !hit || e == nil || v != (runtimeResultsStateInventory{}) || !reflect.DeepEqual(after, coreTree(t, x.f.root.Name())) || len(x.jobs) != 2 {
						t.Fatal("late drift accepted/partial/repair", at, kind, hit, v, e)
					}
				})
			}
		})
	}
}

func TestRuntimeResultsStopStateLateManagerAndQuotaCallbacksCannotPublishCachedRoot(t *testing.T) {
	x, s, p, proof := resultsStateModel(t, true)
	for _, kind := range []string{"manager-source", "quota-source", "quota-result", "quota-receipt"} {
		t.Run(kind, func(t *testing.T) {
			path := x.f.root.Name() + Root + "/backend.json"
			if kind == "quota-result" {
				path = resultStateRow(t, x, "results")
			}
			if kind == "quota-receipt" {
				path = x.f.root.Name() + runtimeResultsCloseRoot + "/complete.json"
			}
			b, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			defer func() {
				if e := os.WriteFile(path, b, 0600); e != nil {
					t.Fatal(e)
				}
			}()
			pr := proof
			m := x.manager
			calls := 0
			hit := false
			var after map[string]string
			mutate := func() error {
				hit = true
				if e := os.WriteFile(path, []byte("PRESERVE_LATE_CALLBACK_MUTATION"), 0600); e != nil {
					return e
				}
				after = coreTree(t, x.f.root.Name())
				return nil
			}
			if kind == "manager-source" {
				original := m.command
				m.command = func(ctx context.Context, args []string) ([]byte, error) {
					b, e := original(ctx, args)
					if len(args) > 0 && args[0] == "show" {
						calls++
						if calls == 4 {
							if e := mutate(); e != nil {
								return nil, e
							}
						}
					}
					return b, e
				}
			} else {
				original := pr.projects
				pr.projects = func(ctx context.Context, cfg firecracker.Config, root *os.File, owners []firecracker.InspectionOwnership) (firecracker.InspectionProjects, error) {
					r, e := original(ctx, cfg, root, owners)
					calls++
					if calls == 2 {
						if e := mutate(); e != nil {
							return firecracker.InspectionProjects{}, e
						}
					}
					return r, e
				}
			}
			ctx, cancel := workStopContext(t)
			defer cancel()
			v, e := s.inspectResultsStoppedStateWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), p, m, pr)
			if !hit || e == nil || v != (runtimeResultsStateInventory{}) || !reflect.DeepEqual(after, coreTree(t, x.f.root.Name())) || len(x.jobs) != 2 {
				t.Fatal("post-callback source/result/receipt drift accepted or repaired", kind, calls, v, e)
			}
		})
	}
}

func TestRuntimeResultsStopStateOriginalFDMustRemainExclusiveAndUnique(t *testing.T) {
	for _, kind := range []string{"unlocked", "shared", "alias", "rebound", "mode", "closed"} {
		t.Run(kind, func(t *testing.T) {
			x, s, p, proof := resultsStateModel(t, true)
			fd := int(s.state.lock.Fd())
			path := x.f.root.Name() + stateDir + "/controller.lock"
			var e error
			switch kind {
			case "unlocked":
				e = unix.Flock(fd, unix.LOCK_UN)
			case "shared":
				e = unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB)
			case "alias":
				var alias int
				alias, e = unix.Dup(fd)
				if e == nil {
					defer unix.Close(alias)
				}
			case "rebound":
				e = os.Rename(path, path+".original")
				if e == nil {
					e = os.WriteFile(path, nil, 0600)
				}
			case "mode":
				e = os.Chmod(path, 0644)
			case "closed":
				s.close()
			}
			if e != nil {
				t.Fatal(e)
			}
			resultsStateRefusesUnchanged(t, x, s, p, proof)
		})
	}
}

func TestRuntimeResultsStopStateUnknownKernelOutcomesCannotReturnPartialJoin(t *testing.T) {
	x, s, p, proof := resultsStateModel(t, true)
	for _, kind := range []string{"service-empty", "cgroup", "quota-error", "quota-count", "quota-owned", "quota-not-released", "manager-live", "boundary-error"} {
		t.Run(kind, func(t *testing.T) {
			pr := proof
			m := x.manager
			switch kind {
			case "service-empty":
				pr.empty = func(string) error { return interrupted }
			case "cgroup":
				pr.cgroup = func(int) error { return interrupted }
			case "quota-error":
				pr.projects = func(context.Context, firecracker.Config, *os.File, []firecracker.InspectionOwnership) (firecracker.InspectionProjects, error) {
					return firecracker.InspectionProjects{}, interrupted
				}
			case "quota-count", "quota-owned", "quota-not-released":
				original := pr.projects
				pr.projects = func(c context.Context, cfg firecracker.Config, f *os.File, o []firecracker.InspectionOwnership) (firecracker.InspectionProjects, error) {
					v, e := original(c, cfg, f, o)
					switch kind {
					case "quota-count":
						v.Reserved++
					case "quota-owned":
						v.Owned++
					case "quota-not-released":
						v.AllReleased = false
					}
					return v, e
				}
			case "manager-live":
				original := m.command
				m.command = func(c context.Context, args []string) ([]byte, error) {
					b, e := original(c, args)
					return bytes.ReplaceAll(b, []byte("MainPID=0"), []byte("MainPID=2")), e
				}
			case "boundary-error":
				x.f.hook = func(at string) error {
					if at == "runtime-results-state-before-final-root" {
						return interrupted
					}
					return nil
				}
				defer func() { x.f.hook = nil }()
			}
			ctx, cancel := workStopContext(t)
			defer cancel()
			before := coreTree(t, x.f.root.Name())
			v, e := s.inspectResultsStoppedStateWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), p, m, pr)
			if e == nil || v != (runtimeResultsStateInventory{}) || !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) || len(x.jobs) != 2 {
				t.Fatal("unknown kernel/manager outcome accepted or partial", kind, v, e)
			}
			if (kind == "service-empty" || kind == "cgroup" || kind == "quota-error" || kind == "boundary-error") && !errors.Is(e, interrupted) {
				t.Fatal("primary boundary error lost", kind, e)
			}
		})
	}
}

func TestRuntimeResultsStopStateWholeScopeExcludesCloseWithoutFileFlockCallback(t *testing.T) {
	x, s, p, proof := resultsStateModel(t, true)
	ctx, cancel := workStopContext(t)
	defer cancel()
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	original := proof.projects
	calls := 0
	proof.projects = func(c context.Context, cfg firecracker.Config, root *os.File, o []firecracker.InspectionOwnership) (firecracker.InspectionProjects, error) {
		calls++
		if calls == 1 {
			close(entered)
			select {
			case <-release:
			case <-c.Done():
				return firecracker.InspectionProjects{}, c.Err()
			}
		}
		return original(c, cfg, root, o)
	}
	before := coreTree(t, x.f.root.Name())
	type reply struct {
		v runtimeResultsStateInventory
		e error
	}
	done := make(chan reply, 1)
	go func() { v, e := inspectResultsStateModel(ctx, x, s, p, proof); done <- reply{v, e} }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("stage did not reach owned observation", ctx.Err())
	}
	unlock, e := x.f.existingLock(ctx, true)
	if e != nil {
		t.Fatal("file flock held across quota observation", e)
	}
	unlock()
	short, stop := context.WithTimeout(ctx, 10*time.Millisecond)
	defer stop()
	if unlock, e := x.f.operationLock(short, false); e == nil {
		unlock()
		t.Fatal("original operation EX not held across join")
	}
	closed := make(chan struct{})
	go func() { s.close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("scope closed in the middle of the complete join")
	case <-time.After(10 * time.Millisecond):
	}
	unblock()
	select {
	case r := <-done:
		if r.e != nil || !r.v.ResultsStateJoined || r.v.ResourcesReclaimed || r.v.ActivationAllowed {
			t.Fatal(r.v, r.e)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("scope close not released after stage", ctx.Err())
	}
	if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
		t.Fatal("scope close/join mutated root")
	}
	resultsStateRefusesUnchanged(t, x, s, p, proof)
}

func TestRuntimeResultsStopStateNoLegacyConversionActivationOrIncompleteMockRoot(t *testing.T) {
	t.Run("complete-result-root-not-legacy", func(t *testing.T) {
		x, s, p, proof := resultsStateModel(t, true)
		ctx, cancel := workStopContext(t)
		defer cancel()
		v, e := inspectResultsStateModel(ctx, x, s, p, proof)
		if e != nil || !v.ResultsStateJoined || v.ResourcesReclaimed || v.ActivationAllowed {
			t.Fatal(v, e)
		}
		b, e := x.f.read(Root+"/backend.json", 16384, 0600)
		if e != nil {
			t.Fatal(e)
		}
		cfg, e := firecracker.DecodeInspectionConfig(b)
		if e != nil {
			t.Fatal(e)
		}
		before := coreTree(t, x.f.root.Name())
		if v, e := readClosedStateRoot(ctx, s.state.root, cfg, true); e == nil || v != (runtimeStateFootprint{}) {
			t.Fatal("legacy root reader adopted results", v, e)
		}
		if v, e := s.inspectClosedStateWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), &runtimeStoppedWorkProof{scope: s}, x.manager, proof); e == nil || v != (runtimeClosedStateInventory{}) {
			t.Fatal("new result state converted to legacy authority", v, e)
		}
		if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) || len(x.jobs) != 2 {
			t.Fatal("legacy refusal changed current joined root")
		}
	})
	t.Run("old-mock-root-not-complete-firecracker", func(t *testing.T) {
		x, s := resultsWALModel(t, "retained")
		ctx, cancel := workStopContext(t)
		defer cancel()
		p, e := stopResultsModel(ctx, x, s)
		if e != nil || p == nil {
			t.Fatal(p, e)
		}
		proof := backendInspectionProofs{empty: x.proof.empty, cgroup: func(int) error { return nil }, projects: func(context.Context, firecracker.Config, *os.File, []firecracker.InspectionOwnership) (firecracker.InspectionProjects, error) {
			t.Fatal("incomplete mock namespace reached quota report")
			return firecracker.InspectionProjects{}, ErrPolicy
		}}
		resultsStateRefusesUnchanged(t, x, s, p, proof)
	})
}
