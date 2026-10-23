package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func TestDrainReadinessAndNoTenantOperatorRoutes(t *testing.T) {
	root := t.TempDir()
	store, e := sandbox.NewFileStore(filepath.Join(root, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	driver, e := sandbox.NewMockDriver(filepath.Join(root, "runtime"))
	if e != nil {
		t.Fatal(e)
	}
	g := sandbox.NewAdmissionGate(true)
	m, e := sandbox.NewManager(store, driver, sandbox.Options{AdmissionGate: g})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		m.Close(ctx)
	})
	s := httptest.NewServer(New(m))
	defer s.Close()
	check := func(path string, want int) {
		t.Helper()
		r, e := http.Get(s.URL + path)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		if r.StatusCode != want {
			t.Fatal(path, r.StatusCode)
		}
	}
	check("/readyz", 200)
	g.SetOpen(false)
	check("/readyz", 503)
	check("/healthz", 200)
	check("/v1/node", 404)
	for _, path := range []string{"/v1/sandboxes", "/v1/node/resume", "/v1/node/drain"} {
		r, e := http.Post(s.URL+path, "application/json", bytes.NewBufferString(`{}`))
		if e != nil {
			t.Fatal(e)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		r.Body.Close()
		if path == "/v1/sandboxes" {
			if r.StatusCode != 503 || !strings.Contains(stringMustJSON(body), "NODE_DRAINING") {
				t.Fatal(r.StatusCode, body)
			}
		} else if r.StatusCode != 404 {
			t.Fatal("tenant API exposed operator route", path, r.StatusCode)
		}
	}
	if m.Stats().Records != 0 {
		t.Fatal("drained create consumed durable budget")
	}
	g.SetOpen(true)
	check("/readyz", 200)
}
func stringMustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
