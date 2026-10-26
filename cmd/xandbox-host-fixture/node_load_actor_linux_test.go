//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
)

func TestNodeLoadActorVirtualClockSeparatesCumulativeSetupFromSwitch(t *testing.T) {
	// Pure mechanism: virtual time is NOT an actual35s/KVM observation.
	base := time.Now()
	clock := base
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(35*time.Second))
	defer cancel()
	actors := &nodeLoadActors{}
	traced, trace := actors.begin(ctx, 1, 64, 0, 0, func() time.Time { return clock })
	deadline, _ := ctx.Deadline()
	if got, _ := traced.Deadline(); got != deadline || traced.Done() != ctx.Done() {
		t.Fatal("observer replaced the original actor context/deadline")
	}
	calls := 0
	for _, step := range []struct {
		phase   nodeLoadActorPhase
		elapsed time.Duration
		err     error
	}{
		{loadActorOpenHTTP, 20 * time.Second, nil}, {loadActorBusyPrepare, 4 * time.Second, nil}, {loadActorSwitch, 11 * time.Second, context.DeadlineExceeded},
	} {
		value, err := nodeLoadTraced(traced, step.phase, func() (int, error) { calls++; clock = clock.Add(step.elapsed); return 73, step.err })
		if value != 73 || err != step.err {
			t.Fatal("observer altered the call's value/error")
		}
	}
	row := nodeLoadRow{Kind: 1, Index: 64, Tenant: 0, Stage: "canary_switch", Outcome: "failed"}
	trace.finish(row, context.DeadlineExceeded)
	actors.freezeFailure(row, context.DeadlineExceeded)
	v := actors.snapshot()
	want := []nodeLoadActorPoint{{"canary_open_http", 0, 20000, true, "ok"}, {"busy_prepare", 20000, 24000, true, "ok"}, {"canary_switch_http", 24000, 35000, true, "deadline"}}
	if calls != 3 || v.Invalid || v.Failure == nil || v.Failure.Invalid || !v.Failure.Done || !v.Failure.BudgetKnown || v.Failure.BudgetMS != 35000 || v.Failure.ElapsedMS != 35000 || !reflect.DeepEqual(v.Failure.Phases, want) {
		t.Fatal("lost direct stage timings or invented an IO/capacity attribution", v)
	}
	if trace.now == nil || ctx.Err() != nil {
		t.Fatal("virtual observation clock changed the real execution deadline")
	}
}

func TestNodeLoadActorFirstFailureSnapshotSurvivesOtherActorsAndCancellation(t *testing.T) {
	s := &nodeLoadState{observe: func(context.Context, int, string) nodeLoadObservation { return nodeLoadObservation{} }}
	ctx, a := s.beginActor(context.Background(), 1, 64, 0, 0)
	cause := fmt.Errorf("private-key-path-diagnostic: %w", context.DeadlineExceeded)
	if err := nodeLoadTraceError(ctx, loadActorSwitch, func() error { return cause }); err != cause {
		t.Fatal("cause replaced")
	}
	row := nodeLoadRow{Kind: 1, Index: 64, Tenant: 0, Stage: "canary_switch", Outcome: "failed"}
	a.finish(row, cause)
	if !s.fail(row, cause) {
		t.Fatal("first failure not retained")
	}
	first := s.actors.snapshot().Failure
	laterCtx, later := s.beginActor(context.Background(), 1, 66, 0, 0)
	_ = nodeLoadTraceError(laterCtx, loadActorOpenHTTP, func() error { return context.Canceled })
	laterRow := nodeLoadRow{Kind: 1, Index: 66, Tenant: 0, Stage: "canary_open", Outcome: "failed"}
	later.finish(laterRow, context.Canceled)
	if s.fail(laterRow, context.Canceled) || s.first != cause {
		t.Fatal("later cancellation replaced first error")
	}
	if !reflect.DeepEqual(first, s.actors.snapshot().Failure) {
		t.Fatal("failure followed a mutable worker slot")
	}
	copy := s.actors.snapshot()
	copy.Failure.Phases[0].Phase = "mutated-private-copy"
	if s.actors.snapshot().Failure.Phases[0].Phase != "canary_switch_http" {
		t.Fatal("snapshot aliases retained evidence")
	}
	s.privateDiagnostics.Failure = &nodeLoadObservation{}
	out, err := s.summary()
	if err != nil || out["observed_result_rows"] != 0 {
		t.Fatal("observer invented measured rows", err)
	}
	capsule := out["private_load_diagnostics"].(nodeLoadPrivateDiagnostics)
	if capsule.Actors.Version != 1 || capsule.Actors.Failure == nil || capsule.Actors.Failure.Outcome != "deadline" {
		t.Fatal("private trace lost")
	}
	encoded, _ := json.Marshal(capsule.Actors)
	if strings.Contains(string(encoded), "private-key-path") || strings.Contains(string(encoded), cause.Error()) {
		t.Fatal("raw error/capability serialized")
	}
	delete(out, "private_load_diagnostics")
	encoded, _ = json.Marshal(out)
	if strings.Contains(string(encoded), "budget_known") || strings.Contains(string(encoded), "canary_switch_http") {
		t.Fatal("actor shadow escaped its private channel")
	}
}

func TestNodeLoadActorFixedSlotsInvalidStagesAndUnknownBudgets(t *testing.T) {
	if nodeLoadActorSlots != 10 || nodeLoadActorPhaseLimit != 16 {
		t.Fatal("trace allocation silently enlarged")
	}
	for _, args := range [][4]int{{2, 0, 0, 0}, {1, 0, 1, 0}, {0, 0, 0, 4}, {1, 240, 0, 0}, {0, 6360, 0, 0}, {1, 1, 1, 1}} {
		actors := &nodeLoadActors{}
		ctx := context.Background()
		got, a := actors.begin(ctx, args[0], args[1], args[2], args[3], nil)
		if got != ctx || a != nil || !actors.snapshot().Invalid || len(actors.snapshot().Latest) != 0 {
			t.Fatal("invalid actor selector allocated a slot", args)
		}
	}
	for _, mode := range []string{"invalid-phase", "duplicate", "nested", "backward", "after-finish", "replaced-live", "out-of-order", "wrong-kind", "release-before-switch"} {
		t.Run(mode, func(t *testing.T) {
			actors := &nodeLoadActors{}
			now := time.Now()
			ctx, a := actors.begin(context.Background(), 0, 0, 0, 0, func() time.Time { return now })
			row := nodeLoadRow{Kind: 0, Index: 0, Tenant: 0, Stage: "raw_create"}
			switch mode {
			case "invalid-phase":
				_ = a.beginPhase(nodeLoadActorPhase(255))
			case "duplicate":
				n := a.beginPhase(loadActorRawCreate)
				a.endPhase(n, nil)
				_ = a.beginPhase(loadActorRawCreate)
			case "nested":
				n := a.beginPhase(loadActorRawCreate)
				_ = a.beginPhase(loadActorBusyStart)
				a.endPhase(n, nil)
			case "backward":
				now = now.Add(-time.Second)
				_ = a.beginPhase(loadActorRawCreate)
			case "after-finish":
				a.finish(row, nil)
				_ = a.beginPhase(loadActorRawCreate)
			case "replaced-live":
				_, _ = actors.begin(ctx, 0, 2, 0, 0, nil)
			case "out-of-order":
				n := a.beginPhase(loadActorBusyVerify)
				a.endPhase(n, nil)
				_ = a.beginPhase(loadActorRawCreate)
			case "wrong-kind":
				_ = a.beginPhase(loadActorSwitch)
			case "release-before-switch":
				_ = a.beginPhase(loadActorRelease)
			}
			v := actors.snapshot()
			if !v.Invalid && !a.snapshot().Invalid {
				t.Fatal("invalid timing/ownership was accepted", mode)
			}
		})
	}
	ctx := context.Background()
	s := &nodeLoadState{}
	got, a := s.beginActor(ctx, 0, 0, 0, 0)
	if got != ctx || a != nil || len(s.actors.snapshot().Latest) != 0 {
		t.Fatal("disabled diagnostics allocated or replaced context")
	}
	calls := 0
	original := errors.New("original")
	if err := nodeLoadTraceError(ctx, loadActorRawCreate, func() error { calls++; return original }); err != original || calls != 1 {
		t.Fatal("disabled observer suppressed/retried operation")
	}
	actors := &nodeLoadActors{}
	_, a = actors.begin(ctx, 0, 0, 0, 0, nil)
	v := a.snapshot()
	if v.BudgetKnown || v.BudgetMS != 0 || v.Done || v.Outcome != "pending" {
		t.Fatal("invented deadline or completion")
	}
}

func TestNodeLoadActorPrecancelAndPostCallValidationKeepActualCause(t *testing.T) {
	s := &nodeLoadState{observe: func(context.Context, int, string) nodeLoadObservation { return nodeLoadObservation{} }}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	ctx, a := s.beginActor(cancelled, 0, 0, 0, 0)
	// Execute the original real helper's pre-cancel path: no API or host reads.
	row, e := nodeLoadRaw(ctx, nil, s, time.Now(), nodeLoadArrival{Index: 0, Tenant: 0}, 0, false)
	a.finish(row, e)
	s.fail(row, e)
	first := s.actors.snapshot().Failure
	if !errors.Is(e, context.Canceled) || first == nil || first.Outcome != "cancelled" || len(first.Phases) != 0 {
		t.Fatal("pre-cancel invented HTTP work or lost cause")
	}
	s = &nodeLoadState{observe: func(context.Context, int, string) nodeLoadObservation { return nodeLoadObservation{} }}
	ctx, a = s.beginActor(context.Background(), 0, 0, 0, 0)
	_ = nodeLoadTraceError(ctx, loadActorRawCreate, func() error { return nil })
	row = nodeLoadRow{Kind: 0, Index: 0, Tenant: 0, Stage: "raw_replay", Outcome: "failed"}
	a.finish(row, nil)
	validation := errors.New("private result-validation failure")
	s.fail(row, validation)
	first = s.actors.snapshot().Failure
	if first == nil || first.Outcome != "other" || first.Phases[0].Outcome != "ok" || s.first != validation {
		t.Fatal("row-validation failure was lost or relabeled an HTTP failure")
	}
}

func TestNodeLoadActorRegistryRemainsBoundedUnderConcurrentSnapshots(t *testing.T) {
	actors := &nodeLoadActors{}
	var wg sync.WaitGroup
	for tenant := 0; tenant < 2; tenant++ {
		for worker := 0; worker < nodeLoadWorkers; worker++ {
			wg.Add(1)
			go func(tenant, worker int) {
				defer wg.Done()
				for n := 0; n < 30; n++ {
					index := 2*(n*nodeLoadWorkers+worker) + tenant
					ctx, a := actors.begin(context.Background(), 0, index, tenant, worker, nil)
					_ = nodeLoadTraceError(ctx, loadActorRawCreate, func() error { return nil })
					a.finish(nodeLoadRow{Kind: 0, Index: index, Tenant: tenant, Stage: "raw_replay"}, nil)
				}
			}(tenant, worker)
		}
		wg.Add(1)
		go func(tenant int) {
			defer wg.Done()
			for n := 0; n < 30; n++ {
				index := 2*n + tenant
				ctx, a := actors.begin(context.Background(), 1, index, tenant, 0, nil)
				_ = nodeLoadTraceError(ctx, loadActorSwitch, func() error { return nil })
				a.finish(nodeLoadRow{Kind: 1, Index: index, Tenant: tenant, Stage: "canary_replay"}, nil)
			}
		}(tenant)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	for {
		v := actors.snapshot()
		if len(v.Latest) > 10 || v.Invalid {
			t.Fatal("unbounded or overwritten active actor")
		}
		select {
		case <-done:
			if len(actors.snapshot().Latest) != 10 {
				t.Fatal("missing independent fixed slots")
			}
			return
		default:
		}
	}
}

type nodeLoadActorTransport func(*http.Request) (*http.Response, error)

func (f nodeLoadActorTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func nodeLoadActorReply(status int, value any) *http.Response {
	b, _ := json.Marshal(value)
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(b)))}
}

func TestNodeLoadActorActualCanaryOpenRefusalAndBusySwitchCallSites(t *testing.T) {
	// Synthetic HTTP transport tests the real helper wiring. No guest/KVM,
	// physical stop or35s hardware outcome is claimed by these responses.
	actors := &nodeLoadActors{}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	traced, a := actors.begin(ctx, 1, 0, 0, 0, nil)
	calls := 0
	api := &switchAPI{http: &http.Client{Transport: nodeLoadActorTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/v1/sessions" {
			t.Fatal("unexpected actual open route")
		}
		if got, _ := r.Context().Deadline(); got != func() time.Time { d, _ := ctx.Deadline(); return d }() {
			t.Fatal("request deadline changed")
		}
		return nodeLoadActorReply(503, map[string]any{"error": map[string]string{"code": "UNAVAILABLE"}}), nil
	})}}
	c := &nodeLoadCanary{}
	row, err := c.tick(traced, api, &nodeLoadState{}, time.Now(), nodeLoadArrival{Index: 0, Tenant: 0})
	a.finish(row, err)
	if err != nil || row.Outcome != "service_unavailable503" || calls != 1 || len(a.snapshot().Phases) != 1 || a.snapshot().Phases[0].Phase != "canary_open_http" {
		t.Fatal("actual open refusal bypassed trace", row, err)
	}

	traced, a = actors.begin(ctx, 1, 2, 0, 0, nil)
	ref := sandbox.Ref{ID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}
	binding := session.Result{ID: strings.Repeat("c", 32), Revision: 1, Current: ref}
	jobs := []string{strings.Repeat("d", 32), strings.Repeat("e", 32), strings.Repeat("f", 32)}
	request := 0
	api.http.Transport = nodeLoadActorTransport(func(r *http.Request) (*http.Response, error) {
		request++
		switch request {
		case 1, 3, 4:
			if r.Method != "POST" || r.URL.Path != "/v1/sessions/"+binding.ID+"/exec" {
				t.Fatal("unexpected busy operation")
			}
			index := 0
			if request == 3 {
				index = 1
			}
			if request == 4 {
				index = 2
			}
			return nodeLoadActorReply(202, map[string]any{"revision": uint64(1), "sandbox": ref, "job": sandbox.Job{ID: jobs[index], Ref: ref}}), nil
		case 2, 5, 6:
			index := 0
			if request == 5 {
				index = 2
			}
			if request == 6 {
				index = 1
			}
			if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/executions/"+jobs[index]) {
				t.Fatal("unexpected busy lookup")
			}
			status := "EXITED"
			if request == 6 {
				status = "RUNNING"
			}
			return nodeLoadActorReply(200, sandbox.Job{ID: jobs[index], Ref: ref, Status: status}), nil
		case 7:
			if r.Method != "POST" || r.URL.Path != "/v1/sessions/"+binding.ID+"/switch" {
				t.Fatal("unexpected switch")
			}
			return nil, context.DeadlineExceeded
		default:
			t.Fatal("observer retried or added HTTP operations")
			return nil, errors.New("unexpected")
		}
	})
	c = &nodeLoadCanary{binding: binding, born: time.Now()}
	row, err = c.tick(traced, api, &nodeLoadState{}, time.Now(), nodeLoadArrival{Index: 2, Tenant: 0})
	a.finish(row, err)
	v := a.snapshot()
	var names []string
	for _, p := range v.Phases {
		names = append(names, p.Phase)
	}
	want := []string{"busy_prepare", "busy_start", "busy_progress", "busy_verify", "canary_switch_http"}
	if !errors.Is(err, context.DeadlineExceeded) || request != 7 || row.Stage != "canary_switch" || v.Outcome != "deadline" || !reflect.DeepEqual(names, want) {
		t.Fatal("real call path lost causal stages or changed request sequence", request, row, err, v)
	}
}

func TestNodeLoadCapacityReadsOnlyExactExistingFixedGauges(t *testing.T) {
	good := "xandbox_create_queued 3\nxandbox_create_queue_capacity 8\nxandbox_create_queue_capacity_per_class 4\n"
	v, e := nodeLoadCapacityMetrics([]byte(good))
	if e != nil || !reflect.DeepEqual(v, map[string]uint64{"queued": 3, "capacity": 8, "class_capacity": 4}) {
		t.Fatal(v, e)
	}
	for _, raw := range []string{strings.Replace(good, "queued 3", "queued -1", 1), strings.Replace(good, "queued 3", "queued 9", 1), strings.Replace(good, "queued 3", "queued NaN", 1), strings.Replace(good, "queued 3", "queued 3 4", 1), strings.Replace(good, "capacity 8", "capacity 9", 1), strings.Replace(good, "class 4", "class 5", 1), strings.Replace(good, "xandbox_create_queued 3\n", "", 1), good + "xandbox_create_queued 3\n", strings.Replace(good, "queued 3", "queued 18446744073709551616", 1)} {
		if _, e := nodeLoadCapacityMetrics([]byte(raw)); e == nil {
			t.Fatal("missing/duplicate/malformed/changed-policy gauge accepted", raw)
		}
	}
}

func TestNodeLoadActorHooksAreWiredToActualCallsAndOriginalContext(t *testing.T) {
	type hook struct{ phase, target string }
	want := map[string][]hook{
		"nodeLoadRaw":  {{"loadActorRawCreate", "nodeLoadCall"}},
		"open":         {{"loadActorOpenHTTP", "nodeLoadCall"}, {"loadActorOpenVerify", "budgetVM"}, {"loadActorOpenFresh", "sessionExec"}, {"loadActorOpenWork", "sessionExec"}},
		"tick":         {{"loadActorRotateClose", "close"}, {"loadActorSwitch", "nodeLoadCall"}, {"loadActorRelease", "nodeLoadReleaseBusy"}, {"loadActorNewFresh", "sessionExec"}, {"loadActorNewWork", "sessionExec"}},
		"nodeLoadBusy": {{"loadActorBusyPrepare", "nodeLoadHeartbeatExec"}, {"loadActorBusyStart", "sessionJob"}, {"loadActorBusyStart", "call"}, {"loadActorBusyProgress", "nodeLoadHeartbeatExec"}, {"loadActorBusyVerify", "job"}},
	}
	for _, file := range []string{"node_load_worker_linux.go", "node_load_api_linux.go"} {
		f, e := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			expected, needed := want[fn.Name.Name]
			if !needed {
				continue
			}
			var got []hook
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				id, ok := call.Fun.(*ast.Ident)
				if !ok || id.Name != "nodeLoadTraced" && id.Name != "nodeLoadTraceError" {
					return true
				}
				if len(call.Args) != 3 {
					t.Fatal("hook signature changed")
				}
				ctx, ok := call.Args[0].(*ast.Ident)
				if !ok || ctx.Name != "ctx" {
					t.Fatal("not original context")
				}
				phase, ok := call.Args[1].(*ast.Ident)
				if !ok {
					t.Fatal("arbitrary phase selector")
				}
				body, ok := call.Args[2].(*ast.FuncLit)
				if !ok {
					t.Fatal("hook not attached to actual call")
				}
				var targets []string
				ast.Inspect(body.Body, func(n ast.Node) bool {
					c, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					switch x := c.Fun.(type) {
					case *ast.Ident:
						targets = append(targets, x.Name)
					case *ast.SelectorExpr:
						targets = append(targets, x.Sel.Name)
					}
					return true
				})
				if len(targets) == 0 {
					t.Fatal("empty trace callback")
				}
				got = append(got, hook{phase.Name, targets[0]})
				return false
			})
			if !reflect.DeepEqual(got, expected) {
				t.Fatal("missing/reordered/wrong actual hook", fn.Name.Name, got)
			}
			delete(want, fn.Name.Name)
		}
	}
	if len(want) != 0 {
		t.Fatal("missing actual functions", want)
	}
	f, e := parser.ParseFile(token.NewFileSet(), "node_load_linux.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	var begins, finishes int
	ast.Inspect(f, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		s, ok := c.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if s.Sel.Name == "beginActor" {
			begins++
			if len(c.Args) != 5 {
				t.Fatal("unbound actor")
			}
			x, ok := c.Args[0].(*ast.Ident)
			if !ok || x.Name != "actor" {
				t.Fatal("actor deadline replaced")
			}
		}
		if s.Sel.Name == "finish" {
			if x, ok := s.X.(*ast.Ident); ok && x.Name == "trace" {
				finishes++
			}
		}
		return true
	})
	if begins != 2 || finishes != 2 {
		t.Fatal("real fixed worker paths bypass actor capture", begins, finishes)
	}
}
