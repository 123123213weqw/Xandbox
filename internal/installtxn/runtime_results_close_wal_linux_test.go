//go:build linux

package installtxn

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"golang.org/x/sys/unix"
)

// Only actual owned TEST processes enter these roles. No daemon executable,
// systemctl, Firecracker/KVM, image or actual quota constructor is invoked.
func TestRuntimeResultsWALOwnedHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_RESULTS_WAL_TEST_ROOT")
	if root == "" {
		t.Skip("owned helper only")
	}
	if !filepath.IsAbs(root) {
		t.Fatal("absolute private test root required")
	}
	var st unix.Stat_t
	if unix.Lstat(root, &st) != nil || st.Mode != unix.S_IFDIR|0700 || st.Uid != uint32(os.Geteuid()) {
		t.Fatal("private owned test root required")
	}
	switch os.Getenv("XANDBOX_RESULTS_WAL_TEST_ROLE") {
	case "daemon":
		resultsWALDaemonHelper(t, root)
	case "coordinator":
		resultsWALCoordinatorHelper(t, root)
	default:
		t.Fatal("fixed owned role required")
	}
}
func resultsWALDaemonHelper(t *testing.T, root string) {
	t.Helper()
	lock, e := os.OpenFile(root+stateDir+"/controller.lock", os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	store, e := nodecontrol.OpenStore(root + stateDir)
	if e != nil {
		t.Fatal(e)
	}
	g := sandbox.NewAdmissionGate(false)
	c, e := nodecontrol.New(store, g)
	if e != nil {
		t.Fatal(e)
	}
	ledger, e := sandbox.NewFileStore(root + stateDir + "/ledger")
	if e != nil {
		t.Fatal(e)
	}
	mode := os.Getenv("XANDBOX_RESULTS_WAL_TEST_MODE")
	var results *sandbox.FileResultStore
	if mode != "nonretention" {
		results, e = sandbox.OpenResultStore(root+stateDir+"/results", sandbox.ResultLimits{Bytes: 1 << 20, TenantBytes: 1 << 19, Records: 100})
		if e != nil {
			t.Fatal(e)
		}
		defer results.Close()
	}
	mock, e := sandbox.NewMockDriver(root + "/TEST-MOCK-backend-outside-state")
	if e != nil {
		t.Fatal(e)
	}
	var driver sandbox.Driver = mock
	if mode == "cleanup-failed" {
		driver = &runtimeCloseFailedDriver{Driver: mock}
	}
	opts := sandbox.Options{AdmissionGate: g, RetryDelay: time.Millisecond, ReapInterval: time.Millisecond}
	if results != nil {
		opts.Results = results // A nil *FileResultStore must not become a nonnil interface.
	}
	core, e := sandbox.NewManager(ledger, driver, opts)
	if e != nil {
		t.Fatal(e)
	}
	journal, e := session.NewFileStore(root + stateDir + "/sessions")
	if e != nil {
		t.Fatal(e)
	}
	broker, e := session.New(core, journal, session.Options{RetryInterval: time.Millisecond})
	if e != nil || c.AttachRuntime(core, broker) != nil {
		t.Fatal("actual actors unavailable", e)
	}
	current, e := broker.Open(context.Background(), sandbox.Owner{TenantID: "alpha", MaxInstances: 4}, "original-results-wal", sandbox.CreateRequest{})
	if e != nil {
		t.Fatal(e)
	}
	job, e := broker.Exec("alpha", current.ID, current.Revision, sandbox.ExecRequest{Argv: []string{"echo", "retained-wal"}})
	if e != nil {
		t.Fatal(e)
	}
	end := time.Now().Add(2 * time.Second)
	for time.Now().Before(end) {
		job, e = core.GetJobScoped("alpha", current.Current.ID, job.ID)
		if e != nil {
			t.Fatal(e)
		}
		if job.Status == "EXITED" && g.AcceptedWorkStatus().Pending == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if job.Status != "EXITED" || g.AcceptedWorkStatus().Pending != 0 || results != nil && (!job.ResultRetained || job.ResultIntegrity != "checksum_v2") {
		t.Fatal("actual work not complete", job)
	}
	if mode == "unknown-result" {
		if e = os.WriteFile(root+stateDir+"/results/.unknown.next", []byte("UNKNOWN_TEST_RESULT_PREFIX"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = nodecontrol.Start(root+stateDir, c, func() sandbox.Stats { return sandbox.Stats{Active: 999, Capacity: 999} }); e != nil {
		t.Fatal(e)
	}
	fmt.Println("READY")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
func resultsWALDaemon(t *testing.T, root, mode string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRuntimeResultsWALOwnedHelper$")
	cmd.Env = []string{"GOMAXPROCS=2", "GOMEMLIMIT=512MiB", "XANDBOX_RESULTS_WAL_TEST_ROOT=" + root, "XANDBOX_RESULTS_WAL_TEST_ROLE=daemon", "XANDBOX_RESULTS_WAL_TEST_MODE=" + mode}
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
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		out.Close()
	})
	ready := make(chan string, 1)
	go func() {
		reader := bufio.NewReader(io.LimitReader(out, 1024))
		line, _ := reader.ReadString('\n')
		if line != "READY\n" {
			tail, _ := io.ReadAll(reader)
			line += string(tail)
		}
		ready <- line
	}()
	select {
	case line := <-ready:
		if line != "READY\n" {
			t.Fatalf("owned results actor not ready (bounded synthetic TEST output): %q", line)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("owned results actor readiness expired")
	}
	return cmd
}
func resultsWALModel(t *testing.T, mode string) (*stopTestModel, *runtimeScope) {
	t.Helper()
	x := stopModel(t, "")
	x.client.Close()
	old := x.children[MainUnit]
	_ = old.Process.Kill()
	_ = old.Wait()
	x.children[MainUnit] = resultsWALDaemon(t, x.f.root.Name(), mode)
	var e error
	x.client, e = nodecontrol.NewPinnedClient(x.f.root.Name()+stateDir, x.children[MainUnit].Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(x.client.Close)
	s := x.scope(t)
	x.maintain(t, s)
	return x, s
}
func finishResultsWAL(ctx context.Context, x *stopTestModel, s *runtimeScope) (*runtimeResultsClosedWorkProof, error) {
	return s.finishAndCloseResultsWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), x.client, x.manager, x.proof)
}
func resultsWALRecords(t *testing.T, x *stopTestModel) (runtimeResultsCloseIntent, runtimeResultsCloseCompletion) {
	t.Helper()
	var p runtimeResultsCloseIntent
	var r runtimeResultsCloseCompletion
	if ok, e := x.f.readResultsCloseRecord("intent.json", &p); e != nil || !ok {
		t.Fatal(ok, e)
	}
	if ok, e := x.f.readResultsCloseRecord("complete.json", &r); e != nil || !ok {
		t.Fatal(ok, e)
	}
	if e := x.f.resultsCloseLink(p, r); e != nil {
		t.Fatal(e)
	}
	return p, r
}
func TestRuntimeResultsWALActualActorIntentAndAnchorPrecedeOpaqueProofWithoutStop(t *testing.T) {
	x, s := resultsWALModel(t, "retained")
	ctx, cancel := workStopContext(t)
	defer cancel()
	protected := runtimeProtectedBytes(t, x.f, x.tx)
	originalTree := coreTree(t, x.f.root.Name())
	if p, e := s.finishAndCloseResults(ctx, digest(encode(x.tx)), runtimeReq("b"), x.client, x.manager); e == nil || p != nil || len(x.jobs) != 0 {
		t.Fatal("production image/placement proof accepted explicit TEST model", p, e)
	}
	if !reflect.DeepEqual(originalTree, coreTree(t, x.f.root.Name())) {
		t.Fatal("failed production proof mutated source")
	}
	before, terminal := 0, 0
	x.f.hook = func(at string) error {
		if at == "runtime-results-close-before-begin" {
			before++
			var p runtimeResultsCloseIntent
			if ok, e := x.f.readResultsCloseRecord("intent.json", &p); e != nil || !ok || x.f.exact(runtimeResultsCloseRoot+"/intent.json", encode(p), 0600) != nil {
				return ErrInventory
			}
			work, _, e := x.f.resultsCloseWorkLink(p)
			if e != nil {
				return e
			}
			r, e := x.client.RuntimeResultsClose(ctx, *work.Drain.Maintenance, false)
			if e != nil || r.Phase != "idle" || r.Core != nil || r.Sessions != nil {
				return ErrConflict
			}
			// RPC holds the original operation EX, never the file flock.
			unlock, e := x.f.existingLock(ctx, true)
			if e != nil {
				return e
			}
			unlock()
			bounded, done := context.WithTimeout(ctx, 10*time.Millisecond)
			defer done()
			if unlock, e := x.f.operationLock(bounded, false); e == nil {
				unlock()
				return ErrConflict
			} else if !errors.Is(e, context.DeadlineExceeded) {
				return e
			}
		}
		if at == "runtime-results-close-after-terminal" {
			terminal++
		}
		return nil
	}
	p, e := finishResultsWAL(ctx, x, s)
	if e != nil || p == nil || p.scope != s || before != 1 || terminal != 1 || len(x.jobs) != 0 || s.state != nil {
		t.Fatal(p, e, before, terminal, x.jobs)
	}
	x.f.hook = nil
	intent, r := resultsWALRecords(t, x)
	if intent.Version != 2 || intent.Stop.Version != 3 || r.Version != 2 || r.Core.Core.Records != 1 || r.Core.Results.Records != 1 || r.Sessions.Records != 1 || !r.Work.Complete() || p.observation != r {
		t.Fatal(intent, r, p)
	}
	if got, e := s.resultsClosedWorkReceipt(ctx, digest(encode(x.tx)), runtimeReq("b"), p); e != nil || got != r {
		t.Fatal(got, e)
	}
	if yes, e := x.f.exists(runtimeStopRoot); e != nil || yes {
		t.Fatal("results closure silently requested legacy physical Stop", e)
	}
	if _, e := x.client.RuntimeClose(ctx, *readWorkStopIntentTest(t, x.f).Drain.Maintenance, true); !errors.Is(e, nodecontrol.ErrRuntimeCloseUnsupported) {
		t.Fatal("legacy protocol dropped results", e)
	}
	unchangedRuntimeProtected(t, x.f, protected)
	beforeTree := coreTree(t, x.f.root.Name())
	if got, e := finishResultsWAL(ctx, x, s); e != nil || got == nil || got.closure != p.closure || len(x.jobs) != 0 {
		t.Fatal(got, e)
	}
	if !reflect.DeepEqual(beforeTree, coreTree(t, x.f.root.Name())) {
		t.Fatal("anchored repeat rewrote files")
	}
}

var resultsWALCuts = []string{
	"runtime-results-close-intent-written", "runtime-results-close-intent-synced", "runtime-results-close-intent-renamed", "runtime-results-close-intent-durable",
	"runtime-results-close-before-begin", "runtime-results-close-after-terminal",
	"runtime-results-close-complete-written", "runtime-results-close-complete-synced", "runtime-results-close-complete-renamed", "runtime-results-close-complete-durable",
	"runtime-results-close-anchor-written", "runtime-results-close-anchor-synced", "runtime-results-close-anchor-renamed", "runtime-results-close-anchor-durable",
}

func TestRuntimeResultsWALAllWriteCutsRecoverOnlySameOriginalWithoutSignals(t *testing.T) {
	for _, cut := range resultsWALCuts {
		t.Run(cut, func(t *testing.T) {
			x, s := resultsWALModel(t, "retained")
			ctx, cancel := workStopContext(t)
			defer cancel()
			hit := false
			x.f.hook = func(at string) error {
				if at == cut {
					hit = true
					return interrupted
				}
				return nil
			}
			if p, e := finishResultsWAL(ctx, x, s); p != nil || !errors.Is(e, interrupted) || !hit || len(x.jobs) != 0 || s.state != nil {
				t.Fatal(p, e, hit, x.jobs)
			}
			x.f.hook = nil
			protected := runtimeProtectedBytes(t, x.f, x.tx)
			if p, e := finishResultsWAL(ctx, x, s); e != nil || p == nil || len(x.jobs) != 0 || s.state != nil {
				t.Fatal(p, e, x.jobs)
			}
			_, r := resultsWALRecords(t, x)
			if r.Core.Results.Records != 1 {
				t.Fatal(r)
			}
			unchangedRuntimeProtected(t, x.f, protected)
		})
	}
}
func TestRuntimeResultsWALUnknownActorOutcomesAndUnsupportedModeNeverFallBack(t *testing.T) {
	for _, mode := range []string{"nonretention", "unknown-result", "cleanup-failed"} {
		t.Run(mode, func(t *testing.T) {
			x, s := resultsWALModel(t, mode)
			ctx, cancel := workStopContext(t)
			defer cancel()
			var before map[string]string
			if mode != "nonretention" {
				before = coreTree(t, x.f.root.Name()+stateDir+"/results")
			}
			p, e := finishResultsWAL(ctx, x, s)
			if p != nil || e == nil || len(x.jobs) != 0 || s.state != nil {
				t.Fatal(p, e, x.jobs)
			}
			for _, path := range []string{runtimeResultsCloseAnchor, runtimeResultsCloseRoot + "/complete.json", runtimeStopRoot} {
				if yes, e := x.f.exists(path); e != nil || yes {
					t.Fatal(path, e)
				}
			}
			if mode == "unknown-result" && !reflect.DeepEqual(before, coreTree(t, x.f.root.Name()+stateDir+"/results")) {
				t.Fatal("unknown result repaired")
			}
		})
	}
}
func TestRuntimeResultsWALCanceledCallerCannotPublishPartialButSamePeerCanResume(t *testing.T) {
	for _, phase := range []string{"before-begin", "after-terminal"} {
		t.Run(phase, func(t *testing.T) {
			x, s := resultsWALModel(t, "retained")
			originalResults := coreTree(t, x.f.root.Name()+stateDir+"/results")
			ctx, cancel := workStopContext(t)
			x.f.hook = func(at string) error {
				if at == "runtime-results-close-"+phase {
					cancel()
				}
				return nil
			}
			if p, e := finishResultsWAL(ctx, x, s); p != nil || !errors.Is(e, context.Canceled) || len(x.jobs) != 0 || s.state != nil {
				t.Fatal(p, e)
			}
			x.f.hook = nil
			for _, path := range []string{runtimeResultsCloseAnchor, runtimeResultsCloseRoot + "/complete.json"} {
				if yes, e := x.f.exists(path); e != nil || yes {
					t.Fatal("cancel published partial success", path, e)
				}
			}
			work := readWorkStopIntentTest(t, x.f)
			statusCtx, statusDone := context.WithTimeout(context.Background(), 2*time.Second)
			r, e := x.client.RuntimeResultsClose(statusCtx, *work.Drain.Maintenance, false)
			statusDone()
			want := "idle"
			if phase == "after-terminal" {
				want = "closed"
			}
			if e != nil || r.Phase != want {
				t.Fatal("accepted actor close was rolled back or invented", r, e)
			}
			ctx, done := workStopContext(t)
			defer done()
			if p, e := finishResultsWAL(ctx, x, s); e != nil || p == nil || len(x.jobs) != 0 {
				t.Fatal(p, e)
			}
			if !reflect.DeepEqual(originalResults, coreTree(t, x.f.root.Name()+stateDir+"/results")) {
				t.Fatal("cancel/retry rewrote or replayed outcome")
			}
		})
	}
}
func TestRuntimeResultsWALAnchoredOriginalDeathIsKnownReceiptNotStopOrReplacement(t *testing.T) {
	x, s := resultsWALModel(t, "retained")
	ctx, cancel := workStopContext(t)
	defer cancel()
	p, e := finishResultsWAL(ctx, x, s)
	if e != nil || p == nil {
		t.Fatal(p, e)
	}
	killCloseOriginalsTest(t, x)
	x.client.Close()
	x.client = nil
	if p, e = finishResultsWAL(ctx, x, s); e != nil || p == nil || len(x.jobs) != 0 || s.state != nil {
		t.Fatal(p, e, x.jobs)
	}
	if got, e := s.resultsClosedWorkReceipt(ctx, digest(encode(x.tx)), runtimeReq("b"), p); e != nil || got != p.observation {
		t.Fatal(got, e)
	}
	if yes, e := x.f.exists(runtimeStopRoot); e != nil || yes {
		t.Fatal("known receipt fabricated physical Stop", e)
	}
}
func TestRuntimeResultsWALDeadBeforeAnchorCannotInventClosure(t *testing.T) {
	for _, cut := range []string{"runtime-results-close-intent-durable", "runtime-results-close-after-terminal", "runtime-results-close-complete-durable"} {
		t.Run(cut, func(t *testing.T) {
			x, s := resultsWALModel(t, "retained")
			ctx, cancel := workStopContext(t)
			defer cancel()
			x.f.hook = func(at string) error {
				if at == cut {
					return interrupted
				}
				return nil
			}
			if p, e := finishResultsWAL(ctx, x, s); p != nil || !errors.Is(e, interrupted) {
				t.Fatal(p, e)
			}
			x.f.hook = nil
			killCloseOriginalsTest(t, x)
			x.client.Close()
			x.client = nil
			before := coreTree(t, x.f.root.Name())
			if p, e := finishResultsWAL(ctx, x, s); p != nil || e == nil || len(x.jobs) != 0 {
				t.Fatal(p, e, x.jobs)
			}
			if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("unknown death rewritten as closure")
			}
		})
	}
}

func TestRuntimeResultsWALOrphanNamespacesFenceOldStartupFilesAndInspection(t *testing.T) {
	for _, path := range []string{runtimeResultsCloseRoot, runtimeResultsCloseAnchor, runtimeResultsCloseAnchorScratch} {
		t.Run(strings.TrimPrefix(path, "/etc/"), func(t *testing.T) {
			f, tx, targets := runtimeModel(t)
			var e error
			if path == runtimeResultsCloseRoot {
				e = os.Mkdir(f.root.Name()+path, 0700)
			} else {
				e = os.WriteFile(f.root.Name()+path, []byte("UNKNOWN_RESULTS_CLOSURE"), 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			before := coreTree(t, f.root.Name())
			if _, e = f.startupFilesLocked(context.Background()); !errors.Is(e, ErrInventory) {
				t.Fatal(e)
			}
			if _, e = runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", targets); !errors.Is(e, ErrInventory) {
				t.Fatal(e)
			}
			if _, e = f.inspectionBase(context.Background(), UpdateInspectionPlan{InstallCommitSHA256: digest(encode(tx)), RetainedRelease: tx.Plan.Release, ReleaseRevision: tx.Plan.ReleaseRevision + 1}); !errors.Is(e, ErrInventory) {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(before, coreTree(t, f.root.Name())) {
				t.Fatal("orphan guard changed files")
			}
		})
	}
}
func TestRuntimeResultsWALLegacyClosureAndStopCannotBeAdoptedInEitherDirection(t *testing.T) {
	for _, path := range []string{runtimeCloseRoot, runtimeCloseAnchor, runtimeCloseAnchorScratch, runtimeStopRoot} {
		t.Run(strings.TrimPrefix(path, "/etc/"), func(t *testing.T) {
			x, s := resultsWALModel(t, "retained")
			ctx, cancel := workStopContext(t)
			defer cancel()
			if _, _, e := s.finishKnownAcceptedWork(ctx, digest(encode(x.tx)), runtimeReq("b"), x.client, x.manager, x.proof); e != nil {
				t.Fatal(e)
			}
			var e error
			if path == runtimeCloseRoot || path == runtimeStopRoot {
				e = os.Mkdir(x.f.root.Name()+path, 0700)
			} else {
				e = os.WriteFile(x.f.root.Name()+path, []byte("UNKNOWN_LEGACY_AUTHORITY"), 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			before := coreTree(t, x.f.root.Name())
			if p, e := finishResultsWAL(ctx, x, s); p != nil || e == nil || len(x.jobs) != 0 {
				t.Fatal(p, e, x.jobs)
			}
			if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("legacy sidecar rewritten/adopted")
			}
		})
	}
	x, s := resultsWALModel(t, "retained")
	ctx, cancel := workStopContext(t)
	defer cancel()
	p, e := finishResultsWAL(ctx, x, s)
	if e != nil || p == nil {
		t.Fatal(p, e)
	}
	work := readWorkStopIntentTest(t, x.f)
	w := runtimeWorkCompletionFromTest(t, x.f)
	before := coreTree(t, x.f.root.Name())
	if r, e := s.closeBoundRuntime(ctx, work, w, x.client, x.manager, x.proof); e == nil || r != (runtimeCloseCompletion{}) {
		t.Fatal("legacy close adopted new journal", r, e)
	}
	if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
		t.Fatal("legacy close changed new authority")
	}
}
func TestRuntimeResultsWALUnknownPartialAndForeignRecordsPreservedWithoutRepair(t *testing.T) {
	for _, kind := range []string{"empty", "partial-intent", "unknown-entry", "foreign-intent", "legacy-intent", "orphan-anchor", "partial-complete"} {
		t.Run(kind, func(t *testing.T) {
			x, s := resultsWALModel(t, "retained")
			ctx, cancel := workStopContext(t)
			defer cancel()
			work, w, e := s.finishKnownAcceptedWork(ctx, digest(encode(x.tx)), runtimeReq("b"), x.client, x.manager, x.proof)
			if e != nil {
				t.Fatal(e)
			}
			intent := resultsCloseIntent(work, w)
			root := x.f.root.Name() + runtimeResultsCloseRoot
			if e = os.Mkdir(root, 0700); e != nil {
				t.Fatal(e)
			}
			write := func(name string, b []byte) {
				t.Helper()
				if e := os.WriteFile(root+"/"+name, b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "partial-intent":
				write(".intent.json.next", []byte("{"))
			case "unknown-entry":
				write("unknown", []byte("UNKNOWN_PREFIX"))
			case "foreign-intent":
				intent.Input = strings.Repeat("0", 64)
				write("intent.json", encode(intent))
			case "legacy-intent":
				intent.Version = 1
				intent.Policy = "close-bound-runtime-v1"
				write("intent.json", encode(intent))
			case "orphan-anchor":
				if e = os.WriteFile(x.f.root.Name()+runtimeResultsCloseAnchor, []byte("UNKNOWN_ANCHOR"), 0600); e != nil {
					t.Fatal(e)
				}
			case "partial-complete":
				write("intent.json", encode(intent))
				write(".complete.json.next", []byte("{"))
			}
			before := coreTree(t, x.f.root.Name())
			if p, e := finishResultsWAL(ctx, x, s); p != nil || e == nil || len(x.jobs) != 0 {
				t.Fatal(p, e, x.jobs)
			}
			if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("unknown/foreign prefix repaired")
			}
			if r, e := x.client.RuntimeResultsClose(ctx, *work.Drain.Maintenance, false); e != nil || r.Phase != "idle" {
				t.Fatal("invalid journal actuated actor", r, e)
			}
		})
	}
}
func TestRuntimeResultsWALOpaqueProofNeverReplacesFreshSourceWALAndScope(t *testing.T) {
	x, s := resultsWALModel(t, "retained")
	ctx, cancel := workStopContext(t)
	defer cancel()
	p, e := finishResultsWAL(ctx, x, s)
	if e != nil || p == nil {
		t.Fatal(p, e)
	}
	for _, kind := range []string{"nil", "scope", "work", "intent", "closure", "state", "observation", "unbounded", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			q := *p
			callCtx := ctx
			var ptr *runtimeResultsClosedWorkProof = &q
			switch kind {
			case "nil":
				ptr = nil
			case "scope":
				q.scope = &runtimeScope{}
			case "work":
				q.work = strings.Repeat("0", 64)
			case "intent":
				q.intent = strings.Repeat("0", 64)
			case "closure":
				q.closure = strings.Repeat("0", 64)
			case "state":
				q.state.RootInode++
			case "observation":
				q.observation.Core.Results.Records++
			case "unbounded":
				callCtx = context.Background()
			case "cancelled":
				var done context.CancelFunc
				callCtx, done = context.WithCancel(ctx)
				done()
			}
			before := coreTree(t, x.f.root.Name())
			if r, e := s.resultsClosedWorkReceipt(callCtx, digest(encode(x.tx)), runtimeReq("b"), ptr); e == nil || r != (runtimeResultsCloseCompletion{}) {
				t.Fatal(r, e)
			}
			if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("bad opaque proof changed files")
			}
		})
	}
	for _, path := range []string{runtimeResultsCloseAnchor, runtimeResultsCloseRoot + "/complete.json", runtimeWorkStopAnchor, runtimeDrainRoot + "/drain.json"} {
		t.Run(strings.TrimPrefix(path, "/etc/"), func(t *testing.T) {
			file := x.f.root.Name() + path
			raw, e := os.ReadFile(file)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(file, []byte("UNKNOWN_DRIFT"), 0600); e != nil {
				t.Fatal(e)
			}
			before := coreTree(t, x.f.root.Name())
			if r, e := s.resultsClosedWorkReceipt(ctx, digest(encode(x.tx)), runtimeReq("b"), p); e == nil || r != (runtimeResultsCloseCompletion{}) {
				t.Fatal(r, e)
			}
			if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("fresh receipt repaired drift")
			}
			if e = os.WriteFile(file, raw, 0600); e != nil {
				t.Fatal(e)
			}
		})
	}
	s.close()
	if r, e := s.resultsClosedWorkReceipt(ctx, digest(encode(x.tx)), runtimeReq("b"), p); e == nil || r != (runtimeResultsCloseCompletion{}) {
		t.Fatal("released scope reused", r, e)
	}
	fresh := x.scope(t)
	if r, e := fresh.resultsClosedWorkReceipt(ctx, digest(encode(x.tx)), runtimeReq("b"), p); e == nil || r != (runtimeResultsCloseCompletion{}) {
		t.Fatal("new scope adopted cached proof", r, e)
	}
}

// Own coordinator only; the inherited bounded pipe exposes ONLY fixed manager
// observations to the parent. It cannot signal/reap a peer or call systemctl.
func resultsWALCoordinatorHelper(t *testing.T, root string) {
	t.Helper()
	mainPID, e := strconv.Atoi(os.Getenv("XANDBOX_RESULTS_WAL_MAIN"))
	if e != nil || mainPID <= 1 {
		t.Fatal("fixed main required")
	}
	ingressPID, e := strconv.Atoi(os.Getenv("XANDBOX_RESULTS_WAL_INGRESS"))
	if e != nil || ingressPID <= 1 {
		t.Fatal("fixed ingress required")
	}
	dir, e := os.Open(root)
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	cut := os.Getenv("XANDBOX_RESULTS_WAL_CUT")
	f := &filesystem{root: dir, hook: func(at string) error {
		if at == cut {
			_ = unix.Kill(os.Getpid(), unix.SIGKILL)
			select {}
		}
		return nil
	}}
	c, e := nodecontrol.NewPinnedClient(root+stateDir, mainPID)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 32768)
	m := systemManager{f, func(_ context.Context, args []string) ([]byte, error) {
		if json.NewEncoder(os.Stdout).Encode(args) != nil || !scan.Scan() {
			return nil, interrupted
		}
		var r stopManagerReply
		if json.Unmarshal(scan.Bytes(), &r) != nil || r.Failed {
			return nil, interrupted
		}
		return r.Data, nil
	}}
	proof := runtimeStopProofs{process: func(_ context.Context, _ transaction, unit string, id nodecontrol.ProcessIdentity) error {
		want := mainPID
		if unit == IngressUnit {
			want = ingressPID
		}
		if id.PID != want {
			return ErrConflict
		}
		return nil
	}, empty: func(string) error { return ErrPolicy }}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, e := f.beginRuntimeScope(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	if _, e = s.finishAndCloseResultsWithProofs(ctx, os.Getenv("XANDBOX_RESULTS_WAL_BASE"), runtimeReq("b"), c, m, proof); e != nil {
		t.Fatal(e)
	}
	t.Fatal("owned coordinator missed required SIGKILL cut")
}
func TestRuntimeResultsWALActualCoordinatorSIGKILLFreshScopeRecoversSameActuator(t *testing.T) {
	for _, cut := range []string{"runtime-results-close-intent-durable", "runtime-results-close-after-terminal", "runtime-results-close-complete-durable", "runtime-results-close-anchor-renamed"} {
		t.Run(cut, func(t *testing.T) {
			x, s := resultsWALModel(t, "retained")
			s.close()
			protected := runtimeProtectedBytes(t, x.f, x.tx)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRuntimeResultsWALOwnedHelper$")
			cmd.Env = []string{"GOMAXPROCS=2", "GOMEMLIMIT=512MiB", "XANDBOX_RESULTS_WAL_TEST_ROOT=" + x.f.root.Name(), "XANDBOX_RESULTS_WAL_TEST_ROLE=coordinator", "XANDBOX_RESULTS_WAL_MAIN=" + strconv.Itoa(x.children[MainUnit].Process.Pid), "XANDBOX_RESULTS_WAL_INGRESS=" + strconv.Itoa(x.children[IngressUnit].Process.Pid), "XANDBOX_RESULTS_WAL_BASE=" + digest(encode(x.tx)), "XANDBOX_RESULTS_WAL_CUT=" + cut}
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
				out.Close()
				if cmd.ProcessState == nil {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			})
			served := make(chan error, 1)
			go func() {
				scanner := bufio.NewScanner(out)
				scanner.Buffer(make([]byte, 4096), 32768)
				for scanner.Scan() {
					var args []string
					if json.Unmarshal(scanner.Bytes(), &args) != nil || len(args) < 1 || len(args) > 8 {
						served <- ErrPolicy
						return
					}
					// Closure stage may ONLY observe, never request a manager Stop.
					if args[0] != "show" {
						served <- ErrPolicy
						return
					}
					data, e := x.manager.command(ctx, args)
					if err := json.NewEncoder(in).Encode(stopManagerReply{Data: data, Failed: e != nil}); err != nil {
						served <- err
						return
					}
				}
				served <- scanner.Err()
			}()
			serveErr := <-served
			if serveErr != nil {
				_ = cmd.Process.Kill()
			}
			e = cmd.Wait()
			in.Close()
			out.Close()
			var exited *exec.ExitError
			if !errors.As(e, &exited) {
				t.Fatal("coordinator did not die", e, serveErr)
			}
			status, ok := exited.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL || serveErr != nil {
				t.Fatal("not actual clean-protocol self SIGKILL", e, serveErr)
			}
			fresh, e := os.Open(x.f.root.Name())
			if e != nil {
				t.Fatal(e)
			}
			defer fresh.Close()
			x.f = &filesystem{root: fresh}
			x.manager.fs = x.f
			s = x.scope(t)
			p, e := finishResultsWAL(ctx, x, s)
			if e != nil || p == nil || len(x.jobs) != 0 || s.state != nil {
				t.Fatal("fresh original-scope result recovery", p, e, x.jobs)
			}
			_, r := resultsWALRecords(t, x)
			if r.Core.Results.Records != 1 {
				t.Fatal(r)
			}
			unchangedRuntimeProtected(t, x.f, protected)
			if _, e = x.f.startupFilesLocked(ctx); !errors.Is(e, ErrInventory) {
				t.Fatal("recovery unfenced startup", e)
			}
		})
	}
}

func TestRuntimeResultsWALV2WireRefusesLegacyAndNoncanonicalWithoutFastPathWidening(t *testing.T) {
	x, s := resultsWALModel(t, "retained")
	ctx, cancel := workStopContext(t)
	defer cancel()
	proof, e := finishResultsWAL(ctx, x, s)
	if e != nil || proof == nil {
		t.Fatal(proof, e)
	}
	intent, complete := resultsWALRecords(t, x)
	work := readWorkStopIntentTest(t, x.f)
	w := runtimeWorkCompletionFromTest(t, x.f)
	for _, kind := range []string{"intent-version", "policy", "input", "stop-version", "stop-state", "completion-version", "core-version", "result-version", "result-digest", "pending-work", "sessions-version"} {
		t.Run(kind, func(t *testing.T) {
			p, r := intent, complete
			switch kind {
			case "intent-version":
				p.Version = 1
			case "policy":
				p.Policy = "close-bound-runtime-v1"
			case "input":
				p.Input = strings.Repeat("0", 64)
			case "stop-version":
				p.Stop.Version = 4
			case "stop-state":
				p.Stop.State = nil
			case "completion-version":
				r.Version = 1
			case "core-version":
				r.Core.Version = 1
			case "result-version":
				r.Core.Results.Version = 1
			case "result-digest":
				r.Core.Results.RecordsSHA256 = ""
			case "pending-work":
				r.Work.Pending++
			case "sessions-version":
				r.Sessions.Version = 0
			}
			if p.valid(work, w) && r.valid(p, w) {
				t.Fatal("bad V2 semantic authority accepted", kind)
			}
		})
	}
	for _, kind := range []string{"unknown", "duplicate", "folded", "whitespace", "trailing", "null", "legacy-completion"} {
		t.Run(kind, func(t *testing.T) {
			data := encode(complete)
			switch kind {
			case "unknown":
				data = append([]byte(`{"activation_allowed":true,`), data[1:]...)
			case "duplicate":
				data = append([]byte(`{"version":2,`), data[1:]...)
			case "folded":
				data = bytes.Replace(data, []byte(`"version"`), []byte(`"VERSION"`), 1)
			case "whitespace":
				data = append([]byte(" "), data...)
			case "trailing":
				data = append(data, data...)
			case "null":
				data = []byte("null\n")
			case "legacy-completion":
				data = encode(runtimeCloseCompletion{Version: 1, Input: complete.Input, Work: complete.Work, Core: complete.Core.Core, Sessions: complete.Sessions})
			}
			var out runtimeResultsCloseCompletion
			if decodeCanonicalRuntime(data, &out) {
				t.Fatal("noncanonical/legacy syntax accepted", kind)
			}
		})
	}
	var old runtimeCloseCompletion
	if decodeCanonicalRuntime(encode(complete), &old) {
		t.Fatal("legacy schema adopted nested result authority")
	}
}
func TestRuntimeResultsWALLateSourceAndPeerDriftCannotPublishClosure(t *testing.T) {
	for _, kind := range []string{"work-anchor", "source-config", "manager-zero", "mixed-before-begin"} {
		t.Run(kind, func(t *testing.T) {
			x, s := resultsWALModel(t, "retained")
			ctx, cancel := workStopContext(t)
			defer cancel()
			hit := false
			x.f.hook = func(at string) error {
				point := "runtime-results-close-after-terminal"
				if kind == "mixed-before-begin" {
					point = "runtime-results-close-before-begin"
				}
				if at != point {
					return nil
				}
				hit = true
				switch kind {
				case "work-anchor":
					return os.WriteFile(x.f.root.Name()+runtimeWorkStopAnchor, []byte("UNKNOWN_CHANGED_WORK"), 0600)
				case "source-config":
					return os.WriteFile(x.f.root.Name()+Root+"/launch.json", []byte("UNKNOWN_CHANGED_SOURCE"), 0600)
				case "manager-zero":
					x.alive[MainUnit] = false
				case "mixed-before-begin":
					return os.Mkdir(x.f.root.Name()+runtimeCloseRoot, 0700)
				}
				return nil
			}
			if p, e := finishResultsWAL(ctx, x, s); p != nil || e == nil || !hit || len(x.jobs) != 0 || s.state != nil {
				t.Fatal(p, e, hit, x.jobs)
			}
			for _, path := range []string{runtimeResultsCloseRoot + "/complete.json", runtimeResultsCloseAnchor, runtimeStopRoot} {
				if yes, e := x.f.exists(path); e != nil || yes {
					t.Fatal("late drift persisted success", path, e)
				}
			}
			if kind == "mixed-before-begin" {
				x.f.hook = nil
				work := readWorkStopIntentTest(t, x.f)
				if r, e := x.client.RuntimeResultsClose(ctx, *work.Drain.Maintenance, false); e != nil || r.Phase != "idle" {
					t.Fatal("mixed mode actuated original", r, e)
				}
			}
		})
	}
}
