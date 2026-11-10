package nodecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func quiescenceCore(t *testing.T, root string, g *sandbox.AdmissionGate) *sandbox.Manager {
	t.Helper()
	f, e := sandbox.NewFileStore(filepath.Join(root, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	d, e := sandbox.NewMockDriver(filepath.Join(root, "instances"))
	if e != nil {
		t.Fatal(e)
	}
	m, e := sandbox.NewManager(f, d, sandbox.Options{AdmissionGate: g})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if e := m.Close(ctx); e != nil {
			t.Error(e)
		}
	})
	return m
}
func TestMaintenanceQuiescenceExactReadyOwnerAndAcceptedTicketCompletion(t *testing.T) {
	root, _, c, g := maintenanceController(t)
	m := quiescenceCore(t, root, g)
	var ticket *sandbox.CreationTicket
	if e := m.ReserveSessionAttempt(func(v *sandbox.CreationTicket) { ticket = v }); e != nil {
		t.Fatal(e)
	}
	defer ticket.Release()
	req := maintenanceRequest(c.Status().Committed)
	if _, e := c.QuiesceMaintenance(context.Background(), req); !errors.Is(e, ErrMaintenance) || g.AcceptedWorkStatus().Frozen {
		t.Fatal(e)
	}
	if _, e := c.BeginMaintenance(context.Background(), req); e != nil {
		t.Fatal(e)
	}
	wrong := req
	wrong.Owner.OperationID = strings.Repeat("e", 32)
	if _, e := c.QuiesceMaintenance(context.Background(), wrong); !errors.Is(e, ErrMaintenance) || g.AcceptedWorkStatus().Frozen {
		t.Fatal(e)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.QuiesceMaintenance(cancelled, req); !errors.Is(e, context.Canceled) || g.AcceptedWorkStatus().Frozen {
		t.Fatal(e)
	}
	r, e := c.QuiesceMaintenance(context.Background(), req)
	if e != nil || !r.valid() || r.Work.Pending != 1 || r.Work.Complete() {
		t.Fatal(r, e)
	}
	ticket.Complete(nil)
	r, e = c.QuiesceMaintenance(context.Background(), req)
	if e != nil || !r.Work.Complete() || r.Work.Succeeded != 1 {
		t.Fatal(r, e)
	}
	if _, e = c.Change(context.Background(), ModeOpen, command(r.Maintenance.Control.Committed, "f")); !errors.Is(e, ErrMaintenance) {
		t.Fatal(e)
	}
}
func TestMaintenanceQuiescenceRestartCannotCertifyLostWorkFromEmptyCounts(t *testing.T) {
	root, f, c, g := maintenanceController(t)
	before := c.Status().Committed
	req := maintenanceRequest(before)
	if _, e := c.BeginMaintenance(context.Background(), req); e != nil {
		t.Fatal(e)
	}
	if r, e := c.QuiesceMaintenance(context.Background(), req); e != nil || !r.Work.Complete() {
		t.Fatal(r, e)
	}
	if e := c.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	f, e := OpenStore(root)
	if e != nil {
		t.Fatal(e)
	}
	nextGate := sandbox.NewAdmissionGate(true)
	next, e := New(f, nextGate)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close(context.Background())
	if _, e = next.BeginMaintenance(context.Background(), req); e != nil {
		t.Fatal(e)
	}
	r, e := next.QuiesceMaintenance(context.Background(), req)
	if e != nil || !r.valid() || !r.Work.Uncertain || r.Work.Pending != 0 || r.Work.Complete() {
		t.Fatal("restart manufactured completion", r, e)
	}
	if nextGate.Open() || !nextGate.AcceptedWorkStatus().Frozen || g.Open() {
		t.Fatal("restart reopened")
	}
}
func TestMaintenanceQuiescencePendingPersistenceCannotFreezeOrCertify(t *testing.T) {
	_, f, c, g := maintenanceController(t)
	req := maintenanceRequest(c.Status().Committed)
	f.maintenanceHook = func(string) error { return errors.New("disk failed") }
	if _, e := c.BeginMaintenance(context.Background(), req); !errors.Is(e, ErrFenced) {
		t.Fatal(e)
	}
	if _, e := c.QuiesceMaintenance(context.Background(), req); !errors.Is(e, ErrFenced) || g.AcceptedWorkStatus().Frozen {
		t.Fatal(e)
	}
}
func TestMaintenanceQuiescenceStrictHTTPAndNoFinishOrForceShortcut(t *testing.T) {
	_, _, c, g := maintenanceController(t)
	req := maintenanceRequest(c.Status().Committed)
	if _, e := c.BeginMaintenance(context.Background(), req); e != nil {
		t.Fatal(e)
	}
	data, _ := json.Marshal(req)
	body := string(data)
	h := controlHandler(c, func() sandbox.Stats { return sandbox.Stats{Active: 0} })
	for _, tc := range []struct {
		method, path, body, ctype string
		code                      int
	}{
		{"GET", quiescencePath, "", "", 405},
		{"POST", quiescencePath + "?force=1", body, "application/json", 400},
		{"POST", quiescencePath, body, "text/plain", 415},
		{"POST", quiescencePath, strings.Replace(body, `"version":1`, `"force":true,"version":1`, 1), "application/json", 400},
		{"POST", quiescencePath, body + body, "application/json", 400},
		{"POST", quiescencePath, strings.Repeat("x", MaxCommandBytes+1), "application/json", 413},
		{"POST", quiescencePath + "/finish", body, "application/json", 404},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.ctype)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.code || g.AcceptedWorkStatus().Frozen {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	r := httptest.NewRequest("POST", quiescencePath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var reply MaintenanceWorkReply
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || !reply.valid() || !reply.Work.Complete() {
		t.Fatal(w.Code, w.Body.String())
	}
}
