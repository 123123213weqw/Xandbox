package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestCreationTimingHTTPIsClosedResponseOnlyAndDoesNotChangeBody(t *testing.T) {
	s, _ := setupAPI(t)
	req, err := http.NewRequest(http.MethodPost, s.URL+"/v1/sandboxes", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	secret := "incoming-tenant-secret"
	req.Header.Set("Server-Timing", secret)
	req.Header.Set("Traceparent", secret)
	response, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	header := response.Header.Get("Server-Timing")
	if response.StatusCode != 201 || strings.Contains(header, secret) || len(response.Header.Values("Server-Timing")) != 1 {
		t.Fatal("invalid creation response", response.StatusCode, header)
	}
	for _, phase := range []string{"xa_core_admission", "xa_core_owner_commit", "xa_core_driver", "xa_core_ready_commit"} {
		if !strings.Contains(header, phase+";") {
			t.Fatal("actual core observation absent", header)
		}
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(data, &body) != nil || body["id"] == nil || body["state"] == nil || body["server_timing"] != nil || body["timings"] != nil {
		t.Fatal("timing observation changed public body")
	}
	for _, test := range []struct{ method, path, body string }{{"GET", "/healthz", ""}, {"GET", "/readyz", ""}, {"POST", "/v1/sandboxes", `{"unknown":true}`}} {
		req, err := http.NewRequest(test.method, s.URL+test.path, strings.NewReader(test.body))
		if err != nil {
			t.Fatal(err)
		}
		r, err := s.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.Header.Get("Server-Timing") != "" {
			t.Fatal("fabricated lifecycle trace on unrelated/rejected operation")
		}
	}
}
