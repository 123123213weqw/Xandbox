package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

type stopWriteErrorStore struct {
	sandbox.Store
	fail atomic.Bool
}

func (s *stopWriteErrorStore) Save(r sandbox.Record) error {
	if r.State == sandbox.Stopping && s.fail.Load() {
		return errors.New("private-store-path/do-not-project")
	}
	return s.Store.Save(r)
}

type observedStopDriver struct {
	sandbox.Driver
	stops atomic.Int64
}

func (d *observedStopDriver) Stop(ctx context.Context, ref sandbox.Ref) error {
	d.stops.Add(1)
	return d.Driver.Stop(ctx, ref)
}

func TestHTTPStopWriteErrorStillStopsWithoutSuccessProjection(t *testing.T) {
	base := t.TempDir()
	files, err := sandbox.NewFileStore(filepath.Join(base, "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	mock, err := sandbox.NewMockDriver(filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	store, driver := &stopWriteErrorStore{Store: files}, &observedStopDriver{Driver: mock}
	m, err := sandbox.NewManager(store, driver, sandbox.Options{MaxInstances: 1, ReapInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(New(m))
	t.Cleanup(func() {
		s.Close()
		store.fail.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	status, raw := call(t, s, http.MethodPost, "/v1/sandboxes", `{}`)
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, raw)
	}
	var r sandbox.Record
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	store.fail.Store(true)
	body, _ := json.Marshal(map[string]string{"generation": r.Generation})
	status, raw = call(t, s, http.MethodPost, "/v1/sandboxes/"+r.ID+"/stop", string(body))
	if status != http.StatusInternalServerError || bytes.Contains(raw, []byte("do-not-project")) || driver.stops.Load() == 0 {
		t.Fatalf("stop error lost physical attempt or projected false success/private detail: %d %s", status, raw)
	}
	current, err := m.Get(r.ID)
	if err != nil || current.State != sandbox.Stopping || !current.StoppedAt.IsZero() || m.Stats().Active != 1 {
		t.Fatalf("HTTP error released admission/durability/capacity boundary: %+v %v", current, err)
	}
	request, _ := json.Marshal(sandbox.ExecRequest{Generation: r.Generation, Argv: []string{"echo"}})
	if status, _ := call(t, s, http.MethodPost, "/v1/sandboxes/"+r.ID+"/exec", string(request)); status != http.StatusConflict {
		t.Fatal("failed durable Stop reopened execution admission")
	}
}
