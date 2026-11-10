package nodecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
)

type runtimeCloseFixture struct {
	root    string
	c       *Controller
	g       *sandbox.AdmissionGate
	core    *sandbox.Manager
	broker  *session.Broker
	record  MaintenanceRecord
	current session.Result
}

func runtimeCloseModel(t *testing.T, ld func(sandbox.Store) sandbox.Store, sd func(session.Store) session.Store, dd func(sandbox.Driver) sandbox.Driver, sb, cb time.Duration) *runtimeCloseFixture {
	t.Helper()
	root, f, c, g := maintenanceController(t)
	_ = f
	ledger, e := sandbox.NewFileStore(filepath.Join(root, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	var l sandbox.Store = ledger
	if ld != nil {
		l = ld(l)
	}
	mock, e := sandbox.NewMockDriver(filepath.Join(root, "instances"))
	if e != nil {
		t.Fatal(e)
	}
	var d sandbox.Driver = mock
	if dd != nil {
		d = dd(d)
	}
	core, e := sandbox.NewManager(l, d, sandbox.Options{AdmissionGate: g, MaxInstances: 4, ReapInterval: time.Millisecond, RetryDelay: time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	store, e := session.NewFileStore(filepath.Join(root, "sessions"))
	if e != nil {
		t.Fatal(e)
	}
	var ss session.Store = store
	if sd != nil {
		ss = sd(ss)
	}
	broker, e := session.New(core, ss, session.Options{RetryInterval: time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	if e = c.attachRuntime(core, broker, sb, cb); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if e := broker.Close(ctx); e != nil {
			t.Error(e)
		}
		select {
		case <-core.LifecycleDone():
		default:
			if e := core.Close(ctx); e != nil {
				t.Error(e)
			}
		}
		if e := c.Close(ctx); e != nil {
			t.Error(e)
		}
	})
	current, e := broker.Open(context.Background(), sandbox.Owner{TenantID: "alpha", MaxInstances: 4}, "original", sandbox.CreateRequest{})
	if e != nil {
		t.Fatal(e)
	}
	r, e := c.BeginMaintenance(context.Background(), maintenanceRequest(c.Status().Committed))
	if e != nil {
		t.Fatal(e)
	}
	return &runtimeCloseFixture{root: root, c: c, g: g, core: core, broker: broker, record: *r.Record, current: current}
}
func (x *runtimeCloseFixture) request(op string) RuntimeCloseRequest {
	return RuntimeCloseRequest{Version: 1, Operation: op, Maintenance: x.record.Request}
}
func (x *runtimeCloseFixture) quiesce(t *testing.T) {
	t.Helper()
	r, e := x.c.QuiesceMaintenance(context.Background(), x.record.Request)
	if e != nil || !r.Work.Complete() {
		t.Fatal(r, e)
	}
}
func (x *runtimeCloseFixture) await(t *testing.T, want string) RuntimeCloseReply {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r, e := x.c.RuntimeClose(context.Background(), x.request("status"))
		if e != nil {
			t.Fatal(e)
		}
		if r.Phase == want {
			return r
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("runtime close phase deadline", want)
	return RuntimeCloseReply{}
}

type runtimeCleanupHold struct {
	sandbox.Driver
	entered, release chan struct{}
	once             sync.Once
	calls            atomic.Int32
}

func (d *runtimeCleanupHold) Cleanup(ctx context.Context, ref sandbox.Ref) error {
	d.calls.Add(1)
	d.once.Do(func() { close(d.entered) })
	<-d.release
	return d.Driver.Cleanup(ctx, ref)
}

type runtimeLedgerHold struct {
	sandbox.Store
	entered, release chan struct{}
	once             sync.Once
}

func (s *runtimeLedgerHold) Save(r sandbox.Record) error {
	if r.State == sandbox.Destroyed {
		s.once.Do(func() { close(s.entered) })
		<-s.release
	}
	return s.Store.Save(r)
}

type runtimeSessionHold struct {
	session.Store
	entered, release chan struct{}
	once             sync.Once
}

func (s *runtimeSessionHold) Save(r session.Record) error {
	if r.State == session.Closed {
		s.once.Do(func() { close(s.entered) })
		<-s.release
	}
	return s.Store.Save(r)
}

func TestMaintenanceRuntimeCloseUsesRealJournalCleanupAndBoundOpaqueProofs(t *testing.T) {
	x := runtimeCloseModel(t, nil, nil, nil, time.Second, time.Second)
	if p, e := x.core.ClosedProof(context.Background()); p != nil || !errors.Is(e, sandbox.ErrNotReady) {
		t.Fatal(p, e)
	}
	if p, e := x.broker.ClosedProof(context.Background()); p != nil || !errors.Is(e, sandbox.ErrNotReady) {
		t.Fatal(p, e)
	}
	if r, e := x.c.RuntimeClose(context.Background(), x.request("begin")); !errors.Is(e, ErrFenced) || r.Core != nil || x.core.Stats().Active != 1 {
		t.Fatal("unfrozen work bypassed", r, e)
	}
	x.quiesce(t)
	r, e := x.c.RuntimeClose(context.Background(), x.request("begin"))
	if e != nil || !r.valid() || r.Phase != "closing-sessions" {
		t.Fatal(r, e)
	}
	r = x.await(t, "closed")
	if !r.valid() || r.Core.Records != 1 || r.Sessions.Records != 1 || r.Core.RecordsSHA256 == r.Sessions.RecordsSHA256 {
		t.Fatal(r)
	}
	core, e := x.core.ClosedProof(context.Background())
	if e != nil || !core.For(x.core) || core.For(nil) || core.Observation() != *r.Core {
		t.Fatal(core, e)
	}
	broker, e := x.broker.ClosedProof(context.Background())
	if e != nil || !broker.For(x.broker, x.core) || broker.For(x.broker, nil) || broker.Observation() != *r.Sessions {
		t.Fatal(broker, e)
	}
	if _, e = os.Lstat(filepath.Join(x.root, "instances", x.current.Current.ID+"-"+x.current.Current.Generation)); !os.IsNotExist(e) {
		t.Fatal("actual mock generation not removed", e)
	}
	ledger, e := sandbox.NewFileStore(filepath.Join(x.root, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	rows, e := ledger.Load()
	if e != nil || len(rows) != 1 || rows[0].State != sandbox.Destroyed {
		t.Fatal(rows, e)
	}
	store, e := session.NewFileStore(filepath.Join(x.root, "sessions"))
	if e != nil {
		t.Fatal(e)
	}
	sessions, e := store.Load()
	if e != nil || len(sessions) != 1 || sessions[0].State != session.Closed {
		t.Fatal(sessions, e)
	}
	for n := 0; n < 3; n++ {
		again, e := x.c.RuntimeClose(context.Background(), x.request("begin"))
		if e != nil || again.Phase != "closed" || *again.Core != *r.Core || *again.Sessions != *r.Sessions {
			t.Fatal(again, e)
		}
	}
	if x.c.Status().AdmissionOpen {
		t.Fatal("runtime close reopened admission")
	}
}

func TestMaintenanceRuntimeClosePendingCleanupAndDestroyedSaveNeverBecomeIdleProof(t *testing.T) {
	for _, kind := range []string{"cleanup", "destroyed-save", "work-drift"} {
		t.Run(kind, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			journalEntered, journalRelease := make(chan struct{}), make(chan struct{})
			var once, journalOnce sync.Once
			defer once.Do(func() { close(release) })
			defer journalOnce.Do(func() { close(journalRelease) })
			var d *runtimeCleanupHold
			var ld func(sandbox.Store) sandbox.Store
			var dd func(sandbox.Driver) sandbox.Driver
			if kind == "cleanup" || kind == "work-drift" {
				dd = func(inner sandbox.Driver) sandbox.Driver {
					d = &runtimeCleanupHold{Driver: inner, entered: entered, release: release}
					return d
				}
			} else {
				ld = func(inner sandbox.Store) sandbox.Store {
					return &runtimeLedgerHold{Store: inner, entered: entered, release: release}
				}
			}
			x := runtimeCloseModel(t, ld, func(inner session.Store) session.Store {
				return &runtimeSessionHold{Store: inner, entered: journalEntered, release: journalRelease}
			}, dd, time.Second, time.Second)
			x.quiesce(t)
			if _, e := x.c.RuntimeClose(context.Background(), x.request("begin")); e != nil {
				t.Fatal(e)
			}
			<-journalEntered
			<-entered
			// A held Destroyed save or cleanup can start during session revocation.
			// Force and check that earlier phase before releasing only the journal;
			// neither a zero Stats count nor entry into IO publishes closing-core.
			if r, e := x.c.RuntimeClose(context.Background(), x.request("status")); e != nil || r.Phase != "closing-sessions" || !r.valid() || !r.Work.Complete() {
				t.Fatal("held session journal lost accepted close")
			}
			journalOnce.Do(func() { close(journalRelease) })
			if r := x.await(t, "closing-core"); !r.valid() || !r.Work.Complete() {
				t.Fatal("held lifecycle IO did not retain closing-core")
			}
			// The ordinary observation can LIE idle; the closure path never uses it.
			h := controlHandler(x.c, func() sandbox.Stats { return sandbox.Stats{Active: 0} })
			data, _ := json.Marshal(x.request("status"))
			req := httptest.NewRequest("POST", runtimeClosePath, strings.NewReader(string(data)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			start := time.Now()
			h.ServeHTTP(w, req)
			if time.Since(start) > 250*time.Millisecond || w.Code != 200 {
				t.Fatal("status blocked behind lifecycle IO", w.Code)
			}
			var r RuntimeCloseReply
			if json.Unmarshal(w.Body.Bytes(), &r) != nil || r.Phase != "closing-core" || r.Core != nil || r.Sessions != nil {
				t.Fatal(w.Body.String())
			}
			if p, e := x.core.ClosedProof(context.Background()); p != nil || !errors.Is(e, sandbox.ErrNotReady) {
				t.Fatal("unfinished metadata became proof", p, e)
			}
			for n := 0; n < 2; n++ {
				r, e := x.c.RuntimeClose(context.Background(), x.request("begin"))
				if e != nil || r.Phase != "closing-core" {
					t.Fatal(r, e)
				}
			}
			if kind == "work-drift" {
				x.g.MarkAcceptedWorkUncertain()
			}
			once.Do(func() { close(release) })
			if kind == "work-drift" {
				r := x.await(t, "fenced")
				if !r.valid() || r.Core != nil || r.Sessions != nil {
					t.Fatal("uncertain work became closure", r)
				}
			} else {
				x.await(t, "closed")
			}
			if d != nil && d.calls.Load() != 1 {
				t.Fatal("same operation spawned duplicate cleanup", d.calls.Load())
			}
		})
	}
}

func TestMaintenanceRuntimeCloseSessionFailureStillTriesCoreAndRetainsWriterWait(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	x := runtimeCloseModel(t, nil, func(inner session.Store) session.Store {
		return &runtimeSessionHold{Store: inner, entered: entered, release: release}
	}, nil, 20*time.Millisecond, time.Second)
	x.quiesce(t)
	if _, e := x.c.RuntimeClose(context.Background(), x.request("begin")); e != nil {
		t.Fatal(e)
	}
	<-entered
	r := x.await(t, "fenced")
	if r.Core != nil || r.Sessions != nil {
		t.Fatal("failed session journal was certified", r)
	}
	if x.core.Stats().Active != 0 {
		t.Fatal("session failure suppressed independent Core cleanup")
	}
	if p, e := x.broker.ClosedProof(context.Background()); p != nil || !errors.Is(e, sandbox.ErrNotReady) {
		t.Fatal(p, e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if e := x.c.Close(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("controller abandoned live journal writer", e)
	}
	cancel()
	once.Do(func() { close(release) })
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := x.c.Close(ctx); e != nil {
		t.Fatal(e)
	}
}

func TestMaintenanceRuntimeCloseCallerCancellationCannotUndoAcceptedClose(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	journalEntered, journalRelease := make(chan struct{}), make(chan struct{})
	var once, journalOnce sync.Once
	defer once.Do(func() { close(release) })
	defer journalOnce.Do(func() { close(journalRelease) })
	x := runtimeCloseModel(t, nil, func(inner session.Store) session.Store {
		return &runtimeSessionHold{Store: inner, entered: journalEntered, release: journalRelease}
	}, func(inner sandbox.Driver) sandbox.Driver {
		return &runtimeCleanupHold{Driver: inner, entered: entered, release: release}
	}, time.Second, time.Second)
	x.quiesce(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, e := x.c.RuntimeClose(ctx, x.request("begin")); e != nil {
		t.Fatal(e)
	}
	cancel()
	<-journalEntered
	<-entered
	// Session revocation can enqueue Core cleanup BEFORE the coordinator leaves
	// closing-sessions. Force that ordering; cleanup entry alone is not a phase
	// publication barrier, and caller cancellation must not undo either stage.
	if r, e := x.c.RuntimeClose(context.Background(), x.request("status")); e != nil || r.Phase != "closing-sessions" || !r.valid() || !r.Work.Complete() {
		t.Fatal("accepted close did not retain the held session stage")
	}
	journalOnce.Do(func() { close(journalRelease) })
	// Retain the original exact closing-core requirement under the EXISTING
	// bounded phase wait, while real cleanup remains held and no proof is ready.
	r := x.await(t, "closing-core")
	if !r.valid() || !r.Work.Complete() {
		t.Fatal("accepted close did not advance to the held Core stage")
	}
	once.Do(func() { close(release) })
	if r = x.await(t, "closed"); !r.valid() {
		t.Fatal("accepted close lacks terminal proofs")
	}
}

func TestMaintenanceRuntimeCloseBindingOwnerAndStrictHTTPRefuseWithoutEffects(t *testing.T) {
	x := runtimeCloseModel(t, nil, nil, nil, time.Second, time.Second)
	if e := x.c.AttachRuntime(x.core, x.broker); !errors.Is(e, ErrConflict) {
		t.Fatal("binding overwritten", e)
	}
	if e := x.c.AttachRuntime(nil, x.broker); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if e := x.c.AttachRuntime(&sandbox.Manager{}, x.broker); !errors.Is(e, ErrInvalid) {
		t.Fatal("foreign gate/core accepted", e)
	}
	if e := x.c.AttachRuntime(x.core, &session.Broker{}); !errors.Is(e, ErrInvalid) {
		t.Fatal("foreign broker accepted", e)
	}

	bad := x.request("begin")
	bad.Maintenance.Owner.OperationID = strings.Repeat("e", 32)
	if _, e := x.c.RuntimeClose(context.Background(), bad); !errors.Is(e, ErrMaintenance) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := x.c.RuntimeClose(ctx, x.request("begin")); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	h := controlHandler(x.c, func() sandbox.Stats { return sandbox.Stats{} })
	data, _ := json.Marshal(x.request("begin"))
	body := string(data)
	for _, tc := range []struct {
		method, path, body, ctype string
		code                      int
	}{
		{"GET", runtimeClosePath, "", "", 405},
		{"POST", runtimeClosePath + "?force=1", body, "application/json", 400},
		{"POST", runtimeClosePath, body, "text/plain", 415},
		{"POST", runtimeClosePath, strings.Replace(body, `"version":1`, `"force":true,"version":1`, 1), "application/json", 400},
		{"POST", runtimeClosePath, strings.Replace(body, `"operation":"begin"`, `"operation":"force"`, 1), "application/json", 400},
		{"POST", runtimeClosePath, body + body, "application/json", 400},
		{"POST", runtimeClosePath, strings.Repeat("x", MaxCommandBytes+1), "application/json", 413},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.ctype)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if r, e := x.c.RuntimeClose(context.Background(), x.request("status")); e != nil || r.Phase != "idle" || x.core.Stats().Active != 1 {
		t.Fatal("invalid request started close", r, e)
	}
}

func TestMaintenanceRuntimeCloseUnboundRuntimeAndRestartUnknownNeverCertify(t *testing.T) {
	root, f, c, g := maintenanceController(t)
	_ = g
	r, e := c.BeginMaintenance(context.Background(), maintenanceRequest(c.Status().Committed))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.RuntimeClose(context.Background(), RuntimeCloseRequest{Version: 1, Operation: "status", Maintenance: r.Record.Request}); !errors.Is(e, ErrRuntimeCloseUnsupported) {
		t.Fatal(e)
	}
	if e = c.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	f, e = OpenStore(root)
	if e != nil {
		t.Fatal(e)
	}
	ng := sandbox.NewAdmissionGate(true)
	next, e := New(f, ng)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close(context.Background())
	core := quiescenceCore(t, root, ng)
	store, e := session.NewFileStore(filepath.Join(root, "sessions"))
	if e != nil {
		t.Fatal(e)
	}
	broker, e := session.New(core, store, session.Options{})
	if e != nil {
		t.Fatal(e)
	}
	defer broker.Close(context.Background())
	if e = next.AttachRuntime(core, broker); e != nil {
		t.Fatal(e)
	}
	if _, e = next.RuntimeClose(context.Background(), RuntimeCloseRequest{Version: 1, Operation: "begin", Maintenance: r.Record.Request}); !errors.Is(e, ErrFenced) {
		t.Fatal("restart unknown became successful close", e)
	}
}
