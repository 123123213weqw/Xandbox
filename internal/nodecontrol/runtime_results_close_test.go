package nodecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
)

type runtimeResultsFixture struct {
	root    string
	c       *Controller
	g       *sandbox.AdmissionGate
	core    *sandbox.Manager
	broker  *session.Broker
	results *sandbox.FileResultStore
	current session.Result
	record  MaintenanceRecord
	job     sandbox.Job
}

func runtimeResultsModel(t *testing.T) *runtimeResultsFixture {
	t.Helper()
	root, _, c, g := maintenanceController(t)
	ledger, e := sandbox.NewFileStore(filepath.Join(root, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	results, e := sandbox.OpenResultStore(filepath.Join(root, "results"), sandbox.ResultLimits{Bytes: 1 << 20, TenantBytes: 1 << 19, Records: 100})
	if e != nil {
		t.Fatal(e)
	}
	mock, e := sandbox.NewMockDriver(filepath.Join(root, "instances"))
	if e != nil {
		t.Fatal(e)
	}
	core, e := sandbox.NewManager(ledger, mock, sandbox.Options{Results: results, AdmissionGate: g, MaxInstances: 4, ReapInterval: time.Millisecond, RetryDelay: time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	store, e := session.NewFileStore(filepath.Join(root, "sessions"))
	if e != nil {
		t.Fatal(e)
	}
	broker, e := session.New(core, store, session.Options{RetryInterval: time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	if e = c.attachRuntime(core, broker, time.Second, time.Second); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if e := broker.Close(ctx); e != nil {
			t.Error(e)
		}
		if e := core.Close(ctx); e != nil {
			t.Error(e)
		}
		if e := c.Close(ctx); e != nil {
			t.Error(e)
		}
		results.Close()
	})
	current, e := broker.Open(context.Background(), sandbox.Owner{TenantID: "alpha", MaxInstances: 4}, "original", sandbox.CreateRequest{})
	if e != nil {
		t.Fatal(e)
	}
	job, e := broker.Exec("alpha", current.ID, current.Revision, sandbox.ExecRequest{Argv: []string{"echo", "bound-result"}})
	if e != nil {
		t.Fatal(e)
	}
	end := time.Now().Add(2 * time.Second)
	for time.Now().Before(end) {
		job, e = core.GetJobScoped("alpha", current.Current.ID, job.ID)
		if e != nil {
			t.Fatal(e)
		}
		if job.Status != "RUNNING" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if job.Status != "EXITED" || !job.ResultRetained || job.ResultIntegrity != "checksum_v2" {
		t.Fatal(job)
	}
	end = time.Now().Add(2 * time.Second)
	for time.Now().Before(end) && g.AcceptedWorkStatus().Pending != 0 {
		time.Sleep(time.Millisecond)
	}
	if g.AcceptedWorkStatus().Pending != 0 {
		t.Fatal("actual execution obligation unfinished")
	}
	r, e := c.BeginMaintenance(context.Background(), maintenanceRequest(c.Status().Committed))
	if e != nil {
		t.Fatal(e)
	}
	return &runtimeResultsFixture{root: root, c: c, g: g, core: core, broker: broker, results: results, current: current, record: *r.Record, job: job}
}
func (x *runtimeResultsFixture) req(op string) RuntimeResultsCloseRequest {
	return RuntimeResultsCloseRequest{Version: 2, Operation: op, Maintenance: x.record.Request}
}
func (x *runtimeResultsFixture) quiesce(t *testing.T) {
	t.Helper()
	r, e := x.c.QuiesceMaintenance(context.Background(), x.record.Request)
	if e != nil || !r.Work.Complete() {
		t.Fatal(r, e)
	}
}
func (x *runtimeResultsFixture) await(t *testing.T) RuntimeResultsCloseReply {
	t.Helper()
	end := time.Now().Add(2 * time.Second)
	for time.Now().Before(end) {
		r, e := x.c.RuntimeResultsClose(context.Background(), x.req("status"))
		if e != nil {
			t.Fatal(e)
		}
		if r.Phase == "closed" || r.Phase == "fenced" {
			return r
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("result close did not finish")
	return RuntimeResultsCloseReply{}
}
func TestRuntimeResultsCloseActualActorsJoinDurableOutputAndRefuseLegacyProtocol(t *testing.T) {
	x := runtimeResultsModel(t)
	if _, e := x.c.RuntimeClose(context.Background(), RuntimeCloseRequest{Version: 1, Operation: "begin", Maintenance: x.record.Request}); !errors.Is(e, ErrRuntimeCloseUnsupported) {
		t.Fatal("legacy protocol dropped results", e)
	}
	if _, e := x.c.RuntimeResultsClose(context.Background(), x.req("begin")); !errors.Is(e, ErrFenced) {
		t.Fatal("idle counts bypassed quiescence", e)
	}
	x.quiesce(t)
	if _, e := x.c.RuntimeResultsClose(context.Background(), x.req("begin")); e != nil {
		t.Fatal(e)
	}
	r := x.await(t)
	if !r.valid() || r.Phase != "closed" || r.Core.Core.Records != 1 || r.Core.Results.Records != 1 || r.Sessions.Records != 1 {
		t.Fatal(r)
	}
	got, e := x.core.GetJobScoped("alpha", x.current.Current.ID, x.job.ID)
	if e != nil || got.Output != x.job.Output || got.ResultIntegrity != "checksum_v2" {
		t.Fatal("close lost output", got, e)
	}
	if _, e = x.core.ClosedProof(context.Background()); !errors.Is(e, sandbox.ErrNotReady) {
		t.Fatal("record-only closure accepted results mode", e)
	}
	for n := 0; n < 3; n++ {
		again, e := x.c.RuntimeResultsClose(context.Background(), x.req("begin"))
		if e != nil || again.Phase != "closed" || *again.Core != *r.Core {
			t.Fatal(again, e)
		}
	}
	x.results.Close()
	again, e := x.c.RuntimeResultsClose(context.Background(), x.req("status"))
	if e != nil || again.Phase != "fenced" || again.Core != nil {
		t.Fatal("closed result FD reused proof", again, e)
	}
}
func TestRuntimeResultsCloseUnknownResultNamespaceFencesWithoutPartialProof(t *testing.T) {
	x := runtimeResultsModel(t)
	unknown := filepath.Join(x.root, "results", "unknown")
	raw := []byte("SYNTHETIC_UNKNOWN_RESULT_NAMESPACE")
	if e := os.WriteFile(unknown, raw, 0600); e != nil {
		t.Fatal(e)
	}
	x.quiesce(t)
	if _, e := x.c.RuntimeResultsClose(context.Background(), x.req("begin")); e != nil {
		t.Fatal(e)
	}
	r := x.await(t)
	if r.Phase != "fenced" || !r.valid() || r.Core != nil || r.Sessions != nil {
		t.Fatal(r)
	}
	after, _ := os.ReadFile(unknown)
	if string(after) != string(raw) {
		t.Fatal("unknown bytes removed")
	}
	if stats := x.core.Stats(); stats.Active != 0 {
		t.Fatal("failed inspection suppressed independent core cleanup", stats)
	}
}
func TestRuntimeResultsCloseOwnerCancellationAndWrongVersionRefuseBeforeEffects(t *testing.T) {
	x := runtimeResultsModel(t)
	x.quiesce(t)
	for _, kind := range []string{"version", "owner", "operation", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			q := x.req("begin")
			ctx := context.Background()
			switch kind {
			case "version":
				q.Version = 1
			case "owner":
				q.Maintenance.Owner.OperationID = strings.Repeat("e", 32)
			case "operation":
				q.Operation = "force"
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			if r, e := x.c.RuntimeResultsClose(ctx, q); e == nil || r.Core != nil {
				t.Fatal(r, e)
			}
			if x.c.runtime.phase != "idle" || x.core.Stats().Active != 1 {
				t.Fatal("refusal performed close")
			}
		})
	}
}
func TestRuntimeResultsCloseHTTPStrictNewSchemaKeepsOldEndpointAndBounds(t *testing.T) {
	x := runtimeResultsModel(t)
	body, _ := json.Marshal(x.req("begin"))
	cases := []struct {
		method, path, body, ctype string
		status                    int
	}{
		{"GET", runtimeResultsClosePath, "", "", 405}, {"POST", runtimeResultsClosePath + "?force=1", string(body), "application/json", 400}, {"POST", runtimeResultsClosePath, string(body), "text/plain", 415},
		{"POST", runtimeResultsClosePath, strings.Replace(string(body), `"version":2`, `"version":1`, 1), "application/json", 400},
		{"POST", runtimeResultsClosePath, strings.Replace(string(body), `"version":2`, `"version":2,"force":true`, 1), "application/json", 400},
		{"POST", runtimeResultsClosePath, string(body) + string(body), "application/json", 400}, {"POST", runtimeResultsClosePath, strings.Repeat("x", MaxCommandBytes+1), "application/json", 413},
	}
	for n, q := range cases {
		req := httptest.NewRequest(q.method, q.path, strings.NewReader(q.body))
		if q.ctype != "" {
			req.Header.Set("Content-Type", q.ctype)
		}
		w := httptest.NewRecorder()
		controlHandler(x.c, func() sandbox.Stats { return sandbox.Stats{} }).ServeHTTP(w, req)
		if w.Code != q.status {
			t.Fatal(n, w.Code)
		}
		if x.c.runtime.phase != "idle" {
			t.Fatal("invalid request closed actors")
		}
	}
	old, _ := json.Marshal(RuntimeCloseRequest{Version: 1, Operation: "begin", Maintenance: x.record.Request})
	req := httptest.NewRequest("POST", runtimeClosePath, strings.NewReader(string(old)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	controlHandler(x.c, func() sandbox.Stats { return sandbox.Stats{} }).ServeHTTP(w, req)
	if w.Code != 501 {
		t.Fatal(w.Code)
	}
}
func TestRuntimeResultsCloseNeverAdoptsLegacyModeOrOldReplyAsV2(t *testing.T) {
	old := runtimeCloseModel(t, nil, nil, nil, time.Second, time.Second)
	if _, e := old.c.RuntimeResultsClose(context.Background(), RuntimeResultsCloseRequest{Version: 2, Operation: "begin", Maintenance: old.record.Request}); !errors.Is(e, ErrRuntimeCloseUnsupported) {
		t.Fatal(e)
	}
	if (RuntimeCloseRequest{Version: 2, Operation: "begin", Maintenance: old.record.Request}).Valid() {
		t.Fatal("legacy version validator widened")
	}
	r := RuntimeResultsCloseReply{Version: 1}
	if r.valid() {
		t.Fatal("legacy reply relabeled")
	}
}
