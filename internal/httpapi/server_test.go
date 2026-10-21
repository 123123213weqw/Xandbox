package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func setupAPI(t *testing.T) (*httptest.Server, *sandbox.Manager) {
	t.Helper()
	base := t.TempDir()
	store, err := sandbox.NewFileStore(filepath.Join(base, "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	driver, err := sandbox.NewMockDriver(filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := sandbox.NewManager(store, driver, sandbox.Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(New(m))
	t.Cleanup(func() {
		s.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return s, m
}

func call(t *testing.T, s *httptest.Server, method, path, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, s.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

func TestAPIWorkflowAndGenerationError(t *testing.T) {
	s, _ := setupAPI(t)
	status, data := call(t, s, http.MethodGet, "/healthz", "")
	if status != 200 || !bytes.Contains(data, []byte(`"isolation":false`)) {
		t.Fatalf("health concealed mock boundary: %d %s", status, data)
	}
	status, data = call(t, s, http.MethodPost, "/v1/sandboxes", `{}`)
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, data)
	}
	var r sandbox.Record
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	status, data = call(t, s, http.MethodPost, "/v1/sandboxes/"+r.ID+"/exec", `{"generation":"stale","argv":["echo"]}`)
	if status != http.StatusConflict || !bytes.Contains(data, []byte("STALE_GENERATION")) {
		t.Fatalf("stale request accepted: %d %s", status, data)
	}
	body, _ := json.Marshal(map[string]string{"generation": r.Generation})
	status, data = call(t, s, http.MethodPost, "/v1/sandboxes/"+r.ID+"/stop", string(body))
	if status != 200 || !bytes.Contains(data, []byte(`"state":"STOPPED"`)) {
		t.Fatalf("stop: %d %s", status, data)
	}
	status, data = call(t, s, http.MethodDelete, "/v1/sandboxes/"+r.ID, string(body))
	if status != http.StatusAccepted {
		t.Fatalf("destroy is not explicit async acceptance: %d %s", status, data)
	}
}

func TestRejectInvalidBodies(t *testing.T) {
	s, _ := setupAPI(t)
	for _, test := range []struct {
		name   string
		body   string
		status int
	}{
		{"empty", "", 400},
		{"unknown field", `{"shell":"/bin/sh"}`, 400},
		{"trailing object", `{} {}`, 400},
		{"null", `null`, 400},
		{"array", `[]`, 400},
		{"negative TTL", `{"ttl_ms":-1}`, 400},
		{"oversized", `{"padding":"` + strings.Repeat("x", 70_000) + `"}`, 413},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, data := call(t, s, http.MethodPost, "/v1/sandboxes", test.body)
			if status != test.status {
				t.Fatalf("got %d, want %d: %s", status, test.status, data)
			}
		})
	}
}

func TestMissingRecord(t *testing.T) {
	s, _ := setupAPI(t)
	status, data := call(t, s, http.MethodGet, "/v1/sandboxes/missing", "")
	if status != 404 || !bytes.Contains(data, []byte("NOT_FOUND")) {
		t.Fatalf("got %d %s", status, data)
	}
}
