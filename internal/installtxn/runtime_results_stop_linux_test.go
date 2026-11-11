//go:build linux

package installtxn

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"golang.org/x/sys/unix"
)

func stopResultsModel(ctx context.Context, x *stopTestModel, s *runtimeScope) (*runtimeResultsStoppedWorkProof, error) {
	return s.finishCloseAndStopResultsWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), x.client, x.manager, x.proof)
}
func resultsStopRecord(t *testing.T, x *stopTestModel) runtimeResultsStopIntent {
	t.Helper()
	var p runtimeResultsStopIntent
	if ok, e := x.f.readResultsStopRecord("intent.json", &p); e != nil || !ok || !p.valid() {
		t.Fatal(p, ok, e)
	}
	return p
}
func TestRuntimeResultsStopActualActorClosurePrecedesBothJobsAndOriginalLease(t *testing.T) {
	x, s := resultsWALModel(t, "retained")
	ctx, cancel := workStopContext(t)
	defer cancel()
	protected := runtimeProtectedBytes(t, x.f, x.tx)
	if p, e := s.finishCloseAndStopResults(ctx, digest(encode(x.tx)), runtimeReq("b"), x.client, x.manager); e == nil || p != nil || len(x.jobs) != 0 {
		t.Fatal("production proof accepted explicit MODEL", p, e)
	}
	stops := 0
	x.f.hook = func(at string) error {
		if at == "runtime-results-stop-before-"+IngressUnit || at == "runtime-results-stop-before-"+MainUnit {
			stops++
			p := resultsStopRecord(t, x)
			if _, e := x.f.resultsStopLink(ctx, p); e != nil {
				return e
			}
			if yes, e := x.f.exists(runtimeStopRoot); e != nil || yes {
				return ErrInventory
			}
			unlock, e := x.f.existingLock(ctx, true)
			if e != nil {
				return e
			}
			unlock()
		}
		return nil
	}
	p, e := stopResultsModel(ctx, x, s)
	x.f.hook = nil
	if e != nil || p == nil || s.state == nil || stops != 2 || !reflect.DeepEqual(x.jobs, []string{IngressUnit, MainUnit}) {
		t.Fatal(p, e, stops, x.jobs)
	}
	if p.scope != s || p.closed.scope != s || p.state != s.state.id {
		t.Fatal("opaque original identity lost")
	}
	fd := s.state.lock.Fd()
	r, e := s.resultsStoppedWorkReceiptWithProof(ctx, digest(encode(x.tx)), runtimeReq("b"), p, x.manager, x.proof.empty)
	if e != nil || r != p.closed.observation || r.Core.Results.Records != 1 || s.state.lock.Fd() != fd {
		t.Fatal(r, e)
	}
	other, e := x.f.openRuntimeState()
	if e != nil {
		t.Fatal(e)
	}
	e = acquireRuntimeState(other)
	other.close()
	if !errors.Is(e, unix.EWOULDBLOCK) {
		t.Fatal("original BSD lease not retained", e)
	}
	unchangedRuntimeProtected(t, x.f, protected)
	if _, e = x.f.startupFilesLocked(ctx); e == nil {
		t.Fatal("result-aware Stop enabled legacy file activation")
	}
	if _, e = s.inspectClosedTerminalWithProof(ctx, digest(encode(x.tx)), runtimeReq("b"), nil, x.manager, x.proof.empty); e == nil {
		t.Fatal("new proof converted to old v4 terminal authority")
	}
}
func TestRuntimeResultsStopEveryPersistenceAndJobCutResumesWithoutDuplicateJobs(t *testing.T) {
	cuts := []string{"runtime-results-stop-intent-written", "runtime-results-stop-intent-synced", "runtime-results-stop-intent-renamed", "runtime-results-stop-intent-durable", "runtime-results-stop-before-" + IngressUnit, "runtime-results-stop-after-" + IngressUnit, "runtime-results-stop-before-" + MainUnit, "runtime-results-stop-after-" + MainUnit, "runtime-results-stop-domains-empty", "runtime-results-stop-receipt-written", "runtime-results-stop-receipt-synced", "runtime-results-stop-receipt-renamed", "runtime-results-stop-receipt-durable", "runtime-results-state-locked"}
	for _, cut := range cuts {
		t.Run(cut, func(t *testing.T) {
			x, s := resultsWALModel(t, "retained")
			ctx, cancel := workStopContext(t)
			defer cancel()
			protected := runtimeProtectedBytes(t, x.f, x.tx)
			hit := false
			x.f.hook = func(at string) error {
				if at == cut {
					hit = true
					return interrupted
				}
				return nil
			}
			if p, e := stopResultsModel(ctx, x, s); e == nil || p != nil || !errors.Is(e, interrupted) || !hit || s.state != nil {
				t.Fatal(p, e, hit)
			}
			x.f.hook = nil
			p, e := stopResultsModel(ctx, x, s)
			if e != nil || p == nil || s.state == nil || !reflect.DeepEqual(x.jobs, []string{IngressUnit, MainUnit}) {
				t.Fatal(p, e, x.jobs)
			}
			p, e = stopResultsModel(ctx, x, s)
			if e != nil || p == nil || len(x.jobs) != 2 {
				t.Fatal("retry repeated jobs", p, e, x.jobs)
			}
			unchangedRuntimeProtected(t, x.f, protected)
		})
	}
}
func TestRuntimeResultsStopUnknownPrefixesRefuseBeforeAnyMutationOrJob(t *testing.T) {
	for _, kind := range []string{"empty", "partial-intent", "foreign-intent", "legacy-intent", "orphan-receipt", "unknown-entry", "partial-receipt", "duplicate-intent", "foreign-receipt"} {
		t.Run(kind, func(t *testing.T) {
			x, s := resultsWALModel(t, "retained")
			ctx, cancel := workStopContext(t)
			defer cancel()
			closed, e := finishResultsWAL(ctx, x, s)
			if e != nil {
				t.Fatal(e)
			}
			ci, cr := resultsWALRecords(t, x)
			work, w, e := x.f.resultsCloseWorkLink(ci)
			if e != nil {
				t.Fatal(e)
			}
			p := resultsStopIntent(work, w, ci, cr)
			root := x.f.root.Name() + runtimeResultsStopRoot
			if e = os.Mkdir(root, 0700); e != nil {
				t.Fatal(e)
			}
			write := func(n string, b []byte) {
				t.Helper()
				if e := os.WriteFile(root+"/"+n, b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "partial-intent":
				write(".intent.json.next", []byte("{"))
			case "foreign-intent":
				p.Work = strings.Repeat("0", 64)
				write("intent.json", encode(p))
			case "legacy-intent":
				write("intent.json", encode(ci.Stop))
			case "orphan-receipt":
				write("stopped.json", encode(runtimeResultsStopReceipt{Version: 1, Input: digest(encode(p))}))
			case "unknown-entry":
				write("unknown", []byte("UNKNOWN_RESULTS_STOP_PREFIX"))
			case "partial-receipt":
				write("intent.json", encode(p))
				write(".stopped.json.next", []byte("{"))
			case "duplicate-intent":
				write("intent.json", encode(p))
				write(".intent.json.next", encode(p))
			case "foreign-receipt":
				write("intent.json", encode(p))
				write("stopped.json", encode(runtimeResultsStopReceipt{Version: 1, Input: strings.Repeat("0", 64)}))
			}
			before := coreTree(t, x.f.root.Name())
			if q, e := s.stopClosedResultsWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), closed, x.client, x.manager, x.proof); e == nil || q != nil || len(x.jobs) != 0 {
				t.Fatal(q, e, x.jobs)
			}
			if q, e := stopResultsModel(ctx, x, s); e == nil || q != nil || len(x.jobs) != 0 {
				t.Fatal(q, e, x.jobs)
			}
			if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("unknown prefix repaired or mutated")
			}
		})
	}
}
func TestRuntimeResultsStopLateManagerAndProcessDriftNeverStopsWrongPeer(t *testing.T) {
	for _, kind := range []string{"wrong-image", "replacement-main", "foreign-unit", "replacement-after-ingress", "live-zero"} {
		t.Run(kind, func(t *testing.T) {
			x, s := resultsWALModel(t, "retained")
			ctx, cancel := workStopContext(t)
			defer cancel()
			closed, e := finishResultsWAL(ctx, x, s)
			if e != nil {
				t.Fatal(e)
			}
			manager, proof := x.manager, x.proof
			if kind == "wrong-image" {
				proof.process = func(context.Context, transaction, string, nodecontrol.ProcessIdentity) error { return ErrInventory }
			}
			manager.command = func(ctx context.Context, args []string) ([]byte, error) {
				b, e := x.manager.command(ctx, args)
				if e != nil || args[0] != "show" {
					return b, e
				}
				u := args[len(args)-1]
				if (kind == "replacement-main" || kind == "replacement-after-ingress" && len(x.jobs) > 0) && u == MainUnit {
					return observationBytes(u, "loaded", "active", "enabled", x.children[u].Process.Pid+1), nil
				}
				if kind == "foreign-unit" {
					return []byte(strings.ReplaceAll(string(b), "DropInPaths=\n", "DropInPaths=/foreign\n")), nil
				}
				if kind == "live-zero" && u == MainUnit {
					return observationBytes(u, "loaded", "inactive", "enabled", 0), nil
				}
				return b, nil
			}
			q, e := s.stopClosedResultsWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), closed, x.client, manager, proof)
			max := 0
			if kind == "replacement-after-ingress" {
				max = 1
			}
			if q != nil || e == nil || len(x.jobs) != max || !x.alive[MainUnit] {
				t.Fatal(q, e, x.jobs)
			}
		})
	}
}
func TestRuntimeResultsStopSourceAndClosureDriftNeverPublishPhysicalIntent(t *testing.T) {
	for _, path := range []string{runtimeWorkStopAnchor, runtimeResultsCloseAnchor, runtimeResultsCloseRoot + "/complete.json", runtimeDrainRoot + "/drain.json", stateDir + "/controller.lock"} {
		t.Run(strings.TrimPrefix(path, "/"), func(t *testing.T) {
			x, s := resultsWALModel(t, "retained")
			ctx, cancel := workStopContext(t)
			defer cancel()
			closed, e := finishResultsWAL(ctx, x, s)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(x.f.root.Name()+path, []byte("UNKNOWN_DRIFT"), 0600); e != nil {
				t.Fatal(e)
			}
			before := coreTree(t, x.f.root.Name())
			p, e := s.stopClosedResultsWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), closed, x.client, x.manager, x.proof)
			if e == nil || p != nil || len(x.jobs) != 0 {
				t.Fatal(p, e, x.jobs)
			}
			if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("fresh proof repaired drift")
			}
		})
	}
}
func TestRuntimeResultsStopOpaqueProofAndBSDLockMustRemainFresh(t *testing.T) {
	x, s := resultsWALModel(t, "retained")
	ctx, cancel := workStopContext(t)
	defer cancel()
	p, e := stopResultsModel(ctx, x, s)
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"nil", "scope", "closed-scope", "stop", "state", "closed-observation", "work", "unbounded", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			q := *p
			ptr := &q
			call := ctx
			switch kind {
			case "nil":
				ptr = nil
			case "scope":
				q.scope = &runtimeScope{}
			case "closed-scope":
				q.closed.scope = &runtimeScope{}
			case "stop":
				q.stop = strings.Repeat("0", 64)
			case "state":
				q.state.LockInode++
			case "closed-observation":
				q.closed.observation.Core.Results.Records++
			case "work":
				q.closed.work = strings.Repeat("0", 64)
			case "unbounded":
				call = context.Background()
			case "cancelled":
				var done context.CancelFunc
				call, done = context.WithCancel(ctx)
				done()
			}
			if r, e := s.resultsStoppedWorkReceiptWithProof(call, digest(encode(x.tx)), runtimeReq("b"), ptr, x.manager, x.proof.empty); e == nil || r != (runtimeResultsCloseCompletion{}) {
				t.Fatal(r, e)
			}
		})
	}
	for _, kind := range []string{"unlocked", "shared", "alias"} {
		t.Run(kind, func(t *testing.T) {
			fd := int(s.state.lock.Fd())
			alias := -1
			switch kind {
			case "unlocked":
				e = unix.Flock(fd, unix.LOCK_UN)
			case "shared":
				e = unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB)
			case "alias":
				alias, e = unix.Dup(fd)
			}
			if e != nil {
				t.Fatal(e)
			}
			before := coreTree(t, x.f.root.Name())
			if r, e := s.resultsStoppedWorkReceiptWithProof(ctx, digest(encode(x.tx)), runtimeReq("b"), p, x.manager, x.proof.empty); e == nil || r != (runtimeResultsCloseCompletion{}) {
				t.Fatal("cached/unowned FD accepted", r, e)
			}
			if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("lease check mutated files")
			}
			if alias >= 0 {
				unix.Close(alias)
			}
			if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
				t.Fatal(e)
			}
		})
	}
	s.close()
	if r, e := s.resultsStoppedWorkReceiptWithProof(ctx, digest(encode(x.tx)), runtimeReq("b"), p, x.manager, x.proof.empty); e == nil || r != (runtimeResultsCloseCompletion{}) {
		t.Fatal(r, e)
	}
	fresh := x.scope(t)
	if r, e := fresh.resultsStoppedWorkReceiptWithProof(ctx, digest(encode(x.tx)), runtimeReq("b"), p, x.manager, x.proof.empty); e == nil || r != (runtimeResultsCloseCompletion{}) {
		t.Fatal("new scope adopted opaque proof", r, e)
	}
}
func TestRuntimeResultsStopFinalCallbacksCannotHideSourceDrift(t *testing.T) {
	x, s := resultsWALModel(t, "retained")
	ctx, cancel := workStopContext(t)
	defer cancel()
	p, e := stopResultsModel(ctx, x, s)
	if e != nil {
		t.Fatal(e)
	}
	hit := false
	m := x.manager
	m.command = func(ctx context.Context, a []string) ([]byte, error) {
		b, e := x.manager.command(ctx, a)
		if e == nil && !hit && a[0] == "show" {
			hit = true
			e = os.WriteFile(x.f.root.Name()+runtimeResultsCloseAnchor, []byte("UNKNOWN_LATE_DRIFT"), 0600)
		}
		return b, e
	}
	if r, e := s.resultsStoppedWorkReceiptWithProof(ctx, digest(encode(x.tx)), runtimeReq("b"), p, m, x.proof.empty); e == nil || r != (runtimeResultsCloseCompletion{}) || !hit {
		t.Fatal(r, e, hit)
	}
}
func TestRuntimeResultsStopLegacyStopRefusesResultsModeWithoutJobs(t *testing.T) {
	x, s := resultsWALModel(t, "retained")
	ctx, cancel := workStopContext(t)
	defer cancel()
	if _, e := finishResultsWAL(ctx, x, s); e != nil {
		t.Fatal(e)
	}
	before := coreTree(t, x.f.root.Name())
	if r, e := x.stop(ctx, s, x.client); e == nil || r != (runtimeStopResult{}) || len(x.jobs) != 0 {
		t.Fatal(r, e, x.jobs)
	}
	if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
		t.Fatal("legacy path adopted V2 mode")
	}
}
func TestRuntimeResultsStopKernelAbsenceFailureNeverClaimsCompleteStopOrLease(t *testing.T) {
	for _, kind := range []string{"populated", "frozen", "not-cgroup2"} {
		t.Run(kind, func(t *testing.T) {
			x, s := resultsWALModel(t, "retained")
			ctx, cancel := workStopContext(t)
			defer cancel()
			closed, e := finishResultsWAL(ctx, x, s)
			if e != nil {
				t.Fatal(e)
			}
			proof := x.proof
			proof.empty = func(u string) error {
				switch kind {
				case "populated":
					return parseIngressEmptyEvents([]byte("populated 1\nfrozen 0\n"))
				case "frozen":
					return parseIngressEmptyEvents([]byte("populated 0\nfrozen 1\n"))
				default:
					return x.f.unitExecutionEmpty(u)
				}
			}
			p, e := s.stopClosedResultsWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), closed, x.client, x.manager, proof)
			if e == nil || p != nil || s.state != nil || !reflect.DeepEqual(x.jobs, []string{IngressUnit}) || !x.alive[MainUnit] {
				t.Fatal(p, e, x.jobs)
			}
		})
	}
}
func TestRuntimeResultsStopForeignStateOwnerIsNotBrokenAndFreshRetryRetainsOriginal(t *testing.T) {
	x, s := resultsWALModel(t, "retained")
	ctx, cancel := workStopContext(t)
	defer cancel()
	var foreign *runtimeStateLease
	x.f.hook = func(at string) error {
		if at == "runtime-results-stop-after-"+MainUnit {
			var e error
			foreign, e = x.f.openRuntimeState()
			if e != nil {
				return e
			}
			return acquireRuntimeState(foreign)
		}
		return nil
	}
	t.Cleanup(func() {
		if foreign != nil {
			foreign.close()
		}
	})
	p, e := stopResultsModel(ctx, x, s)
	if e == nil || p != nil || s.state != nil || foreign == nil || len(x.jobs) != 2 {
		t.Fatal(p, e, x.jobs)
	}
	if e = foreign.verify(x.f); e != nil {
		t.Fatal("foreign state changed", e)
	}
	foreign.close()
	x.f.hook = nil
	p, e = stopResultsModel(ctx, x, s)
	if e != nil || p == nil || s.state == nil || len(x.jobs) != 2 {
		t.Fatal(p, e, x.jobs)
	}
}
func TestRuntimeResultsStopOrphanRootFencesOldReadersAndRecordOnlyClose(t *testing.T) {
	f, tx, targets := runtimeModel(t)
	if e := os.Mkdir(f.root.Name()+runtimeResultsStopRoot, 0700); e != nil {
		t.Fatal(e)
	}
	before := coreTree(t, f.root.Name())
	if _, e := f.startupFilesLocked(context.Background()); !errors.Is(e, ErrInventory) {
		t.Fatal("orphan stop accepted by startup", e)
	}
	if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", targets); !errors.Is(e, ErrInventory) {
		t.Fatal("orphan stop accepted by raw files", e)
	}
	if _, e := f.inspectionBase(context.Background(), UpdateInspectionPlan{InstallCommitSHA256: digest(encode(tx)), RetainedRelease: tx.Plan.Release, ReleaseRevision: tx.Plan.ReleaseRevision + 1}); !errors.Is(e, ErrInventory) {
		t.Fatal("orphan stop accepted by inspection", e)
	}
	if !reflect.DeepEqual(before, coreTree(t, f.root.Name())) {
		t.Fatal("orphan root repaired")
	}
	x, scope := resultsWALModel(t, "retained")
	ctx, cancel := workStopContext(t)
	defer cancel()
	work, w, e := scope.finishKnownAcceptedWork(ctx, digest(encode(x.tx)), runtimeReq("b"), x.client, x.manager, x.proof)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(x.f.root.Name()+runtimeResultsStopRoot, 0700); e != nil {
		t.Fatal(e)
	}
	before = coreTree(t, x.f.root.Name())
	if p, e := stopResultsModel(ctx, x, scope); e == nil || p != nil || len(x.jobs) != 0 {
		t.Fatal(p, e)
	}
	if q, e := scope.closeBoundRuntime(ctx, work, w, x.client, x.manager, x.proof); e == nil || q != (runtimeCloseCompletion{}) {
		t.Fatal("record-only close adopted orphan results Stop", q, e)
	}
	if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
		t.Fatal("orphan Stop actuated closure or repaired source")
	}
}
func TestRuntimeResultsStopDistinctCanonicalWireCannotDowngradeToLegacy(t *testing.T) {
	x, s := resultsWALModel(t, "retained")
	ctx, cancel := workStopContext(t)
	defer cancel()
	if _, e := finishResultsWAL(ctx, x, s); e != nil {
		t.Fatal(e)
	}
	ci, cr := resultsWALRecords(t, x)
	work, w, e := x.f.resultsCloseWorkLink(ci)
	if e != nil {
		t.Fatal(e)
	}
	p := resultsStopIntent(work, w, ci, cr)
	raw := encode(p)
	var good runtimeResultsStopIntent
	if !decodeCanonicalRuntime(raw, &good) || !good.valid() {
		t.Fatal("new wire not canonical")
	}
	for _, kind := range []string{"version", "policy", "work-intent", "work", "close-intent", "closure", "legacy-plan", "missing-state", "unknown", "duplicate", "whitespace", "trailing", "legacy-receipt"} {
		t.Run(kind, func(t *testing.T) {
			q := p
			b := raw
			switch kind {
			case "version":
				q.Version = 4
			case "policy":
				q.Policy = "finish-only-v1"
			case "work-intent":
				q.WorkIntent = ""
			case "work":
				q.Work = ""
			case "close-intent":
				q.CloseIntent = ""
			case "closure":
				q.Closure = ""
			case "legacy-plan":
				q.Plan.Version = 4
				q.Plan.Work = p.Work
				q.Plan.Close = p.Closure
			case "missing-state":
				q.Plan.State = nil
			case "unknown":
				b = append([]byte(`{"unknown":1,`), raw[1:]...)
			case "duplicate":
				b = append([]byte(`{"version":1,`), raw[1:]...)
			case "whitespace":
				b = append([]byte(" "), raw...)
			case "trailing":
				b = append(append([]byte{}, raw...), []byte("{}\n")...)
			case "legacy-receipt":
				b = encode(runtimeStopReceipt{Version: 1, Input: digest(encode(p))})
			}
			if kind == "version" || kind == "policy" || kind == "work-intent" || kind == "work" || kind == "close-intent" || kind == "closure" || kind == "legacy-plan" || kind == "missing-state" {
				b = encode(q)
			}
			var out runtimeResultsStopIntent
			if decodeCanonicalRuntime(b, &out) && out.valid() {
				t.Fatal("invalid new intent accepted", kind)
			}
		})
	}
	var legacy runtimeStopIntent
	if canonicalRuntimeIntentValue(raw, &legacy) && validRuntimeStop(legacy) {
		t.Fatal("new wire adopted as old Stop")
	}
	var receipt runtimeResultsStopReceipt
	if decodeCanonicalRuntime(encode(runtimeStopReceipt{Version: 1, Input: digest(encode(p))}), &receipt) {
		t.Fatal("legacy stopped receipt adopted")
	}
}
func TestRuntimeResultsStopCanceledCallerNeverReturnsPartialAuthority(t *testing.T) {
	for _, kind := range []string{"before-intent", "after-ingress"} {
		t.Run(kind, func(t *testing.T) {
			x, s := resultsWALModel(t, "retained")
			ctx, cancel := workStopContext(t)
			defer cancel()
			closed, e := finishResultsWAL(ctx, x, s)
			if e != nil {
				t.Fatal(e)
			}
			call, abort := context.WithCancel(ctx)
			defer abort()
			before := coreTree(t, x.f.root.Name())
			if kind == "before-intent" {
				abort()
			} else {
				x.f.hook = func(at string) error {
					if at == "runtime-results-stop-after-"+IngressUnit {
						abort()
					}
					return nil
				}
			}
			p, e := s.stopClosedResultsWithProofs(call, digest(encode(x.tx)), runtimeReq("b"), closed, x.client, x.manager, x.proof)
			if p != nil || e == nil || s.state != nil {
				t.Fatal(p, e)
			}
			want := 0
			if kind == "after-ingress" {
				want = 1
			}
			if len(x.jobs) != want || !x.alive[MainUnit] {
				t.Fatal(x.jobs)
			}
			if kind == "before-intent" && !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("cancelled caller mutated files")
			}
			x.f.hook = nil
			p, e = stopResultsModel(ctx, x, s)
			if e != nil || p == nil || len(x.jobs) != 2 {
				t.Fatal(p, e, x.jobs)
			}
		})
	}
}
func TestRuntimeResultsStopLatePeerCallbacksReproveSourceBeforeFirstJob(t *testing.T) {
	for _, kind := range []string{"process", "manager"} {
		t.Run(kind, func(t *testing.T) {
			x, s := resultsWALModel(t, "retained")
			ctx, cancel := workStopContext(t)
			defer cancel()
			closed, e := finishResultsWAL(ctx, x, s)
			if e != nil {
				t.Fatal(e)
			}
			hit := false
			mutate := func() error {
				if hit {
					return nil
				}
				hit = true
				return os.WriteFile(x.f.root.Name()+runtimeResultsCloseAnchor, []byte("UNKNOWN_CALLBACK_DRIFT"), 0600)
			}
			m, proof := x.manager, x.proof
			if kind == "process" {
				proof.process = func(ctx context.Context, tx transaction, u string, id nodecontrol.ProcessIdentity) error {
					if e := x.proof.process(ctx, tx, u, id); e != nil {
						return e
					}
					return mutate()
				}
			} else {
				m.command = func(ctx context.Context, a []string) ([]byte, error) {
					b, e := x.manager.command(ctx, a)
					if e == nil && a[0] == "show" {
						e = mutate()
					}
					return b, e
				}
			}
			p, e := s.stopClosedResultsWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), closed, x.client, m, proof)
			if p != nil || e == nil || !hit || len(x.jobs) != 0 || s.state != nil {
				t.Fatal(p, e, hit, x.jobs)
			}
		})
	}
}
