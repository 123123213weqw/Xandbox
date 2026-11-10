//go:build linux

package installtxn

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"golang.org/x/sys/unix"
)

// Test ELF only. Parent owns every child handle and is the ONLY process that
// terminates/reaps it. Main hosts a real private operator/file store; ingress
// is a waiting helper. Neither is a real service, gateway, VMM or guest.
func TestRuntimeStopOperatorHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_TEST_STOP_ROOT")
	if root == "" {
		return
	}
	if os.Getenv("XANDBOX_TEST_STOP_ROLE") == "main" {
		// Match the ordinary daemon's ORIGINAL BSD flock, in a private test root.
		lock, e := os.OpenFile(root+stateDir+"/controller.lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
		if e != nil {
			os.Exit(69)
		}
		defer lock.Close()
		if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
			os.Exit(70)
		}
		switch os.Getenv("XANDBOX_TEST_CLOSE_MODE") {
		case "state-fd-unlocked":
			if unix.Flock(int(lock.Fd()), unix.LOCK_UN) != nil {
				os.Exit(81)
			}
		case "state-fd-shared":
			if unix.Flock(int(lock.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil {
				os.Exit(82)
			}
		case "state-fd-duplicate":
			fd, err := unix.Dup(int(lock.Fd()))
			if err != nil {
				os.Exit(83)
			}
			defer unix.Close(fd)
		}
		store, e := nodecontrol.OpenStore(root + stateDir)
		if e != nil {
			os.Exit(71)
		}
		g := sandbox.NewAdmissionGate(false)
		c, e := nodecontrol.New(store, g)
		if e != nil {
			os.Exit(72)
		}

		if os.Getenv("XANDBOX_TEST_CLOSE_MODE") != "unsupported" {
			ledger, err := sandbox.NewFileStore(root + stateDir + "/ledger")
			if err != nil {
				os.Exit(74)
			}
			mockRoot := root + stateDir + "/instances"
			if os.Getenv("XANDBOX_TEST_CLOSE_MODE") == "closed-state-firecracker-model" {
				mockRoot = root + "/TEST-backend-outside-installed-state"
			}
			driver, err := sandbox.NewMockDriver(mockRoot)
			if err != nil {
				os.Exit(75)
			}
			var d sandbox.Driver = driver
			if mode := os.Getenv("XANDBOX_TEST_CLOSE_MODE"); mode == "terminal-firecracker-model" || mode == "closed-state-firecracker-model" {
				// Explicit TEST-only metadata model, NEVER a real backend/VM.
				d = &terminalProjectionModelDriver{Driver: driver}
			}
			if os.Getenv("XANDBOX_TEST_CLOSE_MODE") == "cleanup-failed" {
				d = &runtimeCloseFailedDriver{Driver: driver}
			}
			core, err := sandbox.NewManager(ledger, d, sandbox.Options{AdmissionGate: g, RetryDelay: time.Millisecond, ReapInterval: time.Millisecond})
			if err != nil {
				os.Exit(76)
			}
			journal, err := session.NewFileStore(root + stateDir + "/sessions")
			if err != nil {
				os.Exit(77)
			}
			broker, err := session.New(core, journal, session.Options{RetryInterval: time.Millisecond})
			if err != nil {
				os.Exit(78)
			}
			mode := os.Getenv("XANDBOX_TEST_CLOSE_MODE")
			if mode == "populated" || mode == "cleanup-failed" || mode == "terminal-firecracker-model" || mode == "closed-state-firecracker-model" {
				if _, err = broker.Open(context.Background(), sandbox.Owner{TenantID: "alpha", MaxInstances: 4}, "original", sandbox.CreateRequest{}); err != nil {
					os.Exit(79)
				}
			}
			if c.AttachRuntime(core, broker) != nil {
				os.Exit(80)
			}
		}
		_, e = nodecontrol.Start(root+stateDir, c, func() sandbox.Stats { return sandbox.Stats{Active: 1, Capacity: 4} })
		if e != nil {
			os.Exit(73)
		}
	}
	fmt.Println("READY")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

type runtimeCloseFailedDriver struct{ sandbox.Driver }

func (d *runtimeCloseFailedDriver) Cleanup(context.Context, sandbox.Ref) error {
	return errors.New("owned mock cleanup failure")
}
func runtimeStopChild(t *testing.T, root, role string) *exec.Cmd {
	t.Helper()
	return runtimeStopChildMode(t, root, role, "")
}
func runtimeStopChildMode(t *testing.T, root, role, mode string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRuntimeStopOperatorHelper$")
	cmd.Env = []string{"GOMAXPROCS=2", "XANDBOX_TEST_STOP_ROOT=" + root, "XANDBOX_TEST_STOP_ROLE=" + role, "XANDBOX_TEST_CLOSE_MODE=" + mode}
	in, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		in.Close()
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
		out.Close()
	})
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(out).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "READY\n" {
			t.Fatal("helper not ready")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("helper readiness deadline")
	}
	return cmd
}

type stopTestModel struct {
	f        *filesystem
	tx       transaction
	client   *nodecontrol.PinnedClient
	children map[string]*exec.Cmd
	alive    map[string]bool
	jobs     []string
	proof    runtimeStopProofs
	manager  systemManager
	kind     string
}

func stopModel(t *testing.T, kind string) *stopTestModel {
	t.Helper()
	f, tx := runtimeShortInstall(t)
	return stopModelInstalled(t, kind, f, tx)
}

func stopModelInstalled(t *testing.T, kind string, f *filesystem, tx transaction) *stopTestModel {
	t.Helper()
	managerLinks(t, f)
	x := &stopTestModel{f: f, tx: tx, children: map[string]*exec.Cmd{}, alive: map[string]bool{}, kind: kind}
	for _, item := range []struct{ unit, role string }{{MainUnit, "main"}, {IngressUnit, "ingress"}} {
		x.children[item.unit] = runtimeStopChild(t, f.root.Name(), item.role)
		x.alive[item.unit] = true
		modelIngressGroup(t, f.root.Name()+ingressCgroupParent+"/"+item.unit, "populated 0\nfrozen 0\n")
	}
	c, e := nodecontrol.NewPinnedClient(f.root.Name()+stateDir, x.children[MainUnit].Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	x.client = c
	t.Cleanup(c.Close)
	x.manager = systemManager{f, func(ctx context.Context, args []string) ([]byte, error) {
		// Every manager request must run without file flock, with operation EX.
		lock, e := f.existingLock(ctx, true)
		if e != nil {
			return nil, e
		}
		lock()
		if args[0] == "show" {
			u := args[len(args)-1]
			state, pid := "inactive", 0
			if x.alive[u] {
				state, pid = "active", x.children[u].Process.Pid
			}
			if (kind == "replacement-main" || kind == "replacement-after-ingress" && !x.alive[IngressUnit]) && u == MainUnit {
				pid++
			}
			if kind == "lying-manager-zero" && u == IngressUnit && len(x.jobs) > 0 {
				state, pid = "inactive", 0
			}
			b := observationBytes(u, "loaded", state, "enabled", pid)
			if kind == "foreign-unit" {
				b = []byte(strings.ReplaceAll(string(b), "DropInPaths=\n", "DropInPaths=/foreign\n"))
			}
			return b, nil
		}
		if len(args) != 3 || args[0] != "--job-mode=ignore-dependencies" || args[1] != "stop" || (args[2] != MainUnit && args[2] != IngressUnit) {
			t.Errorf("unfixed manager mutation: %v", args)
			return nil, ErrPolicy
		}
		u := args[2]
		x.jobs = append(x.jobs, u)
		if kind == "stop-error" {
			return nil, interrupted
		}
		if kind == "false-manager-success" || kind == "lying-manager-zero" {
			return nil, nil
		}
		if x.alive[u] {
			if e := x.children[u].Process.Kill(); e != nil {
				return nil, e
			}
			if e := x.children[u].Wait(); e == nil {
				return nil, errors.New("test child unexpectedly exited normally")
			}
			x.alive[u] = false
		}
		return nil, nil
	}}
	x.proof = runtimeStopProofs{
		process: func(_ context.Context, _ transaction, unit string, id nodecontrol.ProcessIdentity) error {
			if kind == "wrong-image" {
				return ErrInventory
			}
			if x.children[unit].Process.Pid != id.PID || !x.alive[unit] {
				return ErrConflict
			}
			return nil
		},
		empty: func(unit string) error {
			if x.alive[unit] {
				return ErrInventory
			}
			if kind == "populated" {
				return parseIngressEmptyEvents([]byte("populated 1\nfrozen 0\n"))
			}
			if kind == "frozen" {
				return parseIngressEmptyEvents([]byte("populated 0\nfrozen 1\n"))
			}
			if kind == "fake-kernel" {
				return f.unitExecutionEmpty(unit)
			}
			return modelIngressProof(t, f.root.Name()+ingressCgroupParent+"/"+unit, func(int) error { return nil })
		},
	}
	return x
}
func (x *stopTestModel) scope(t *testing.T) *runtimeScope {
	t.Helper()
	s, e := x.f.beginRuntimeScope(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.close)
	return s
}
func (x *stopTestModel) drain(t *testing.T, s *runtimeScope) {
	t.Helper()
	r, e := s.drain(context.Background(), digest(encode(x.tx)), runtimeReq("b"), x.client)
	if e != nil || !r.AdmissionDrained {
		t.Fatal(r, e)
	}
}
func (x *stopTestModel) stop(ctx context.Context, s *runtimeScope, client *nodecontrol.PinnedClient) (runtimeStopResult, error) {
	return s.stopWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), client, x.manager, x.proof)
}
func TestRuntimeStopScopeDrainsThenStopsBothKnownProcessesWithoutReclaimClaim(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	x.drain(t, s)
	before := runtimeProtectedBytes(t, x.f, x.tx)
	r, e := x.stop(context.Background(), s, x.client)
	if e != nil || !r.ExecutionStopped || r.ResourcesReclaimed || r.AcceptedWorkComplete || r.ActivationAllowed {
		t.Fatal(r, e)
	}
	if strings.Join(x.jobs, ",") != IngressUnit+","+MainUnit {
		t.Fatal("wrong stop order", x.jobs)
	}
	for _, v := range runtimeSubset(x.tx) {
		if e = x.f.verify(context.Background(), v); e != nil {
			t.Fatal("Stop changed runtime files", e)
		}
	}
	unchangedRuntimeProtected(t, x.f, before)
	// Lost caller handles: fresh scope can recover stopped intent without any
	// live operator. It MUST reobserve manager/kernel, never just trust receipt.
	s.close()
	fresh, e := os.Open(x.f.root.Name())
	if e != nil {
		t.Fatal(e)
	}
	defer fresh.Close()
	x.f = &filesystem{root: fresh}
	x.manager.fs = x.f
	s = x.scope(t)
	r, e = x.stop(context.Background(), s, nil)
	if e != nil || !r.ExecutionStopped || len(x.jobs) != 2 {
		t.Fatal("offline exact retry", r, e)
	}
	if _, e = x.f.startupFilesLocked(context.Background()); e == nil {
		t.Fatal("stop receipt unfenced startup")
	}
}
func TestRuntimeStopRefusesUnprovenOwnershipAndNonemptyDomains(t *testing.T) {
	for _, kind := range []string{"replacement-main", "foreign-unit", "wrong-image", "stop-error", "false-manager-success", "lying-manager-zero", "replacement-after-ingress", "populated", "frozen", "fake-kernel"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, kind)
			s := x.scope(t)
			x.drain(t, s)
			if _, e := x.stop(context.Background(), s, x.client); e == nil {
				t.Fatal("uncertain stop certified")
			}
			if kind == "replacement-main" || kind == "foreign-unit" || kind == "wrong-image" {
				if len(x.jobs) != 0 {
					t.Fatal("unowned process reached stop", x.jobs)
				}
			}
			if kind == "populated" || kind == "frozen" || kind == "fake-kernel" || kind == "false-manager-success" || kind == "lying-manager-zero" || kind == "replacement-after-ingress" {
				if !x.alive[MainUnit] {
					t.Fatal("main stopped before ingress physical proof")
				}
			}
		})
	}
}

var stopCuts = []string{"runtime-stop-intent-written", "runtime-stop-intent-synced", "runtime-stop-intent-renamed", "runtime-stop-intent-durable", "runtime-stop-before-" + IngressUnit, "runtime-stop-after-" + IngressUnit, "runtime-stop-before-" + MainUnit, "runtime-stop-after-" + MainUnit, "runtime-stop-domains-empty", "runtime-stop-receipt-written", "runtime-stop-receipt-synced", "runtime-stop-receipt-renamed", "runtime-stop-receipt-durable"}

func TestRuntimeStopWriteAheadCutsResumeIncludingDeadOperator(t *testing.T) {
	for _, cut := range stopCuts {
		t.Run(cut, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			x.drain(t, s)
			hit := false
			x.f.hook = func(at string) error {
				if at == cut && !hit {
					hit = true
					return interrupted
				}
				return nil
			}
			if _, e := x.stop(context.Background(), s, x.client); !errors.Is(e, interrupted) || !hit {
				t.Fatal("stop cut not reached", e)
			}
			x.f.hook = nil
			s.close()
			s = x.scope(t)
			client := x.client
			if !x.alive[MainUnit] {
				client = nil
			}
			r, e := x.stop(context.Background(), s, client)
			if e != nil || !r.ExecutionStopped || r.ResourcesReclaimed || len(x.jobs) != 2 {
				t.Fatal("exact stopped recovery", r, e, x.jobs)
			}
		})
	}
}
func TestRuntimeStopProductionProofCannotStopShadowExecutables(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	x.drain(t, s)
	if _, e := s.stop(context.Background(), digest(encode(x.tx)), runtimeReq("b"), x.client, x.manager); e == nil {
		t.Fatal("model PID accepted as fixed service")
	}
	if len(x.jobs) != 0 {
		t.Fatal("kernel/source proof rejected after effect")
	}
}
func TestRuntimeStopProtectedDriftAfterIngressDoesNotStopMainOrRestoreAuthority(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	x.drain(t, s)
	x.f.hook = func(at string) error {
		if at == "runtime-stop-after-"+IngressUnit {
			return os.WriteFile(x.f.root.Name()+Root+"/auth.json", []byte("forward external authority"), 0600)
		}
		return nil
	}
	if _, e := x.stop(context.Background(), s, x.client); e == nil {
		t.Fatal("protected drift acknowledged")
	}
	if !x.alive[MainUnit] || len(x.jobs) != 1 {
		t.Fatal("main affected after drift")
	}
	b, e := os.ReadFile(x.f.root.Name() + Root + "/auth.json")
	if e != nil || string(b) != "forward external authority" {
		t.Fatal("authority rewound", e)
	}
}

func TestRuntimeStopForeignResumeBeforeFirstEffectIsNotSilentlyOverwritten(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	x.drain(t, s)
	x.f.hook = func(at string) error {
		if at != "runtime-stop-intent-durable" {
			return nil
		}
		c, e := nodecontrol.NewClient(x.f.root.Name() + stateDir)
		if e != nil {
			return e
		}
		defer c.Close()
		r, e := c.Status(context.Background())
		if e != nil {
			return e
		}
		_, e = c.Change(context.Background(), nodecontrol.ModeOpen, nodecontrol.Command{Version: 1, Epoch: r.Control.Committed.Epoch, ExpectedRevision: r.Control.Committed.Revision, RequestID: runtimeReq("e")})
		return e
	}
	if _, e := x.stop(context.Background(), s, x.client); !errors.Is(e, ErrConflict) {
		t.Fatal("foreign resume not detected", e)
	}
	if len(x.jobs) != 0 {
		t.Fatal("foreign resume reached stop", x.jobs)
	}
}

func TestRuntimeStopUncertainRecordsNeverAuthorizeProcessTermination(t *testing.T) {
	for _, kind := range []string{"unknown", "bad-receipt", "premature-receipt", "premature-prefix", "duplicate-intent-scratch", "missing-intent", "wrong-request"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			x.drain(t, s)
			x.f.hook = func(at string) error {
				if at == "runtime-stop-before-"+IngressUnit {
					return interrupted
				}
				return nil
			}
			if _, e := x.stop(context.Background(), s, x.client); !errors.Is(e, interrupted) {
				t.Fatal(e)
			}
			x.f.hook = nil
			p, e := x.f.readRuntimeStop()
			if e != nil {
				t.Fatal(e)
			}
			path := runtimeStopRoot + "/stopped.json"
			b := encode(runtimeStopReceipt{Version: 1, Input: digest(encode(p))})
			switch kind {
			case "unknown":
				path = runtimeStopRoot + "/foreign"
			case "bad-receipt":
				b = []byte("unknown receipt")
			case "premature-prefix":
				path = runtimeStopRoot + "/.stopped.json.next"
				b = b[:len(b)/2]
			case "duplicate-intent-scratch":
				path = runtimeStopRoot + "/.intent.json.next"
				b = encode(p)
			case "missing-intent":
				if e = os.Remove(x.f.root.Name() + runtimeStopRoot + "/intent.json"); e != nil {
					t.Fatal(e)
				}
			case "wrong-request":
				p.Request = runtimeReq("e")
				path = runtimeStopRoot + "/intent.json"
				b = encode(p)
			}
			if e = os.WriteFile(x.f.root.Name()+path, b, 0600); e != nil {
				t.Fatal(e)
			}
			before := runtimeShadowBytes(t, x.f)
			if _, e = x.stop(context.Background(), s, x.client); e == nil {
				t.Fatal("uncertain stop state accepted")
			}
			if len(x.jobs) != 0 || !x.alive[MainUnit] || !x.alive[IngressUnit] {
				t.Fatal("uncertain state reached process stop")
			}
			if !bytes.Equal(encode(before), encode(runtimeShadowBytes(t, x.f))) {
				t.Fatal("uncertain records repaired/overwritten")
			}
		})
	}
}

func TestRuntimeStopFixedUnitKernelSelectorRejectsOrdinaryFilesystem(t *testing.T) {
	f, _, _ := fixture(t)
	for _, unit := range []string{MainUnit, IngressUnit} {
		if e := f.unitExecutionEmpty(unit); !errors.Is(e, ErrPlatform) {
			t.Fatal("ordinary shadow accepted as kernel absence", unit, e)
		}
	}
	if e := f.unitExecutionEmpty("foreign.service"); !errors.Is(e, ErrPolicy) {
		t.Fatal("arbitrary unit selector accepted", e)
	}
}

func TestRuntimeStopEmptyNamespaceFencesAllInitialAdapters(t *testing.T) {
	f, tx, client, control := drainModel(t, nil)
	if _, e := f.startupFilesLocked(context.Background()); e != nil {
		t.Fatal("clean baseline", e)
	}
	if e := f.mkdir(runtimeStopRoot, 0700); e != nil {
		t.Fatal(e)
	}
	if e := f.verifyTransaction(context.Background(), tx); e != nil {
		t.Fatal("negative-control premise", e)
	}
	if _, e := f.startupFilesLocked(context.Background()); !errors.Is(e, ErrInventory) {
		t.Fatal("empty stop directory allowed startup", e)
	}
	if _, e := drainApply(context.Background(), f, tx, client); !errors.Is(e, ErrInventory) {
		t.Fatal("stop residue allowed fresh drain", e)
	}
	if control.Status().Committed.Revision != 1 {
		t.Fatal("residue sent node mutation")
	}
	if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", nil); !errors.Is(e, ErrInventory) {
		t.Fatal("stop residue allowed file selection", e)
	}
	p := UpdateInspectionPlan{InstallCommitSHA256: digest(encode(tx)), RetainedRelease: tx.Plan.Release, ReleaseRevision: tx.Plan.ReleaseRevision + 1}
	if _, e := f.inspectionBase(context.Background(), p); !errors.Is(e, ErrInventory) {
		t.Fatal("stop residue certified clean", e)
	}
}
