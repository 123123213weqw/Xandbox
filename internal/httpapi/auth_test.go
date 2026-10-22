package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func authenticatedAPI(t *testing.T) (*httptest.Server, string, string) {
	t.Helper()
	_, m := setupAPI(t)
	aToken, bToken := strings.Repeat("a", 40), strings.Repeat("b", 40)
	keys := []access.Key{}
	for i, token := range []string{aToken, bToken} {
		sum := sha256.Sum256([]byte(token))
		keys = append(keys, access.Key{TokenSHA256: hex.EncodeToString(sum[:]), TenantID: []string{"alpha", "beta"}[i], MaxInstances: 1})
	}
	auth, err := access.New(access.Config{Version: 1, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewConfigured(m, Options{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s, aToken, bToken
}

func authorizedCall(t *testing.T, s *httptest.Server, token, method, path, body, key string, extra http.Header) (int, []byte) {
	t.Helper()
	r, err := http.NewRequest(method, s.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	for k, values := range extra {
		for _, v := range values {
			r.Header.Add(k, v)
		}
	}
	resp, err := s.Client().Do(r)
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

func TestAuthenticationAndHealthBoundary(t *testing.T) {
	s, a, _ := authenticatedAPI(t)
	status, body := authorizedCall(t, s, "", "GET", "/healthz", "", "", nil)
	if status != 200 || bytes.Contains(body, []byte(`"stats"`)) || !bytes.Contains(body, []byte(`"authentication":true`)) {
		t.Fatalf("public health: %d %s", status, body)
	}
	for _, token := range []string{"", strings.Repeat("c", 40)} {
		status, body := authorizedCall(t, s, token, "POST", "/v1/sandboxes", "{}", "key", nil)
		if status != 401 || (token != "" && bytes.Contains(body, []byte(token))) {
			t.Fatalf("authentication: %d %s", status, body)
		}
	}
	status, _ = authorizedCall(t, s, a, "POST", "/v1/sandboxes", "{}", "key", http.Header{"Authorization": []string{"Bearer " + a}})
	if status != 401 {
		t.Fatalf("duplicate credential headers accepted: %d", status)
	}
	status, _ = authorizedCall(t, s, a, "POST", "/v1/sandboxes", "{}", "", nil)
	if status != 400 {
		t.Fatalf("missing create key accepted: %d", status)
	}
	status, _ = authorizedCall(t, s, a, "POST", "/v1/sandboxes", "{}", "key", http.Header{"Idempotency-Key": []string{"second"}})
	if status != 400 {
		t.Fatalf("duplicate create keys accepted: %d", status)
	}
}

func TestTenantEndpointsAndCreationReplay(t *testing.T) {
	s, a, b := authenticatedAPI(t)
	status, data := authorizedCall(t, s, a, "POST", "/v1/sandboxes", "{}", "one", http.Header{"X-Tenant-ID": []string{"beta"}})
	if status != 201 {
		t.Fatalf("create: %d %s", status, data)
	}
	var r sandbox.Record
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	if r.TenantID != "alpha" || bytes.Contains(data, []byte("create_key_hash")) || bytes.Contains(data, []byte("create_spec_hash")) {
		t.Fatalf("unsafe view or forged identity: %s", data)
	}
	status, replay := authorizedCall(t, s, a, "POST", "/v1/sandboxes", "{}", "one", nil)
	if status != 201 || !bytes.Equal(data, replay) {
		t.Fatalf("quota-blocked or changed replay: %d %s", status, replay)
	}
	status, _ = authorizedCall(t, s, a, "POST", "/v1/sandboxes", `{"ttl_ms":10000}`, "one", nil)
	if status != 409 {
		t.Fatalf("conflicting parameters accepted: %d", status)
	}
	status, _ = authorizedCall(t, s, a, "POST", "/v1/sandboxes", "{}", "two", nil)
	if status != 429 {
		t.Fatalf("quota bypass: %d", status)
	}
	status, _ = authorizedCall(t, s, a, "POST", "/v1/sandboxes", `{"tenant_id":"beta"}`, "forged", nil)
	if status != 400 {
		t.Fatalf("body tenant accepted: %d", status)
	}
	path := "/v1/sandboxes/" + r.ID
	execBody := fmt.Sprintf(`{"generation":%q,"argv":["echo","private-alpha"]}`, r.Generation)
	status, data = authorizedCall(t, s, a, "POST", path+"/exec", execBody, "", nil)
	if status != 202 {
		t.Fatalf("execution: %d %s", status, data)
	}
	var job sandbox.Job
	if err := json.Unmarshal(data, &job); err != nil {
		t.Fatal(err)
	}
	refBody := fmt.Sprintf(`{"generation":%q}`, r.Generation)
	for _, request := range []struct{ method, path, body string }{
		{"GET", path, ""}, {"POST", path + "/exec", execBody},
		{"GET", path + "/executions/" + job.ID, ""}, {"POST", path + "/stop", refBody}, {"DELETE", path, refBody},
	} {
		status, data := authorizedCall(t, s, b, request.method, request.path, request.body, "", nil)
		if status != 404 || bytes.Contains(data, []byte("private-alpha")) {
			t.Errorf("cross-tenant %s %s: %d %s", request.method, request.path, status, data)
		}
	}
	status, data = authorizedCall(t, s, b, "POST", "/v1/sandboxes", "{}", "one", nil)
	if status != 201 || bytes.Contains(data, []byte(r.ID)) {
		t.Fatalf("tenant key namespace mixed: %d %s", status, data)
	}
	status, _ = authorizedCall(t, s, a, "DELETE", path, refBody, "", nil)
	if status != 202 {
		t.Fatal(status)
	}
	status, _ = authorizedCall(t, s, a, "POST", "/v1/sandboxes", "{}", "one", nil)
	if status != 410 {
		t.Fatalf("deleted key reused: %d", status)
	}
}

func TestPublicErrorsDoNotExposeOperatorDetails(t *testing.T) {
	secret := "/operator/private/credentials-do-not-echo"
	r := sandbox.Record{LastError: secret, CreateKeyHash: "private-key-hash", CreateSpecHash: "private-spec-hash"}
	data, _ := json.Marshal(publicRecord(r))
	if bytes.Contains(data, []byte(secret)) || bytes.Contains(data, []byte("private-key-hash")) || bytes.Contains(data, []byte("private-spec-hash")) {
		t.Fatalf("ledger leaked: %s", data)
	}
	for _, status := range []string{"FAILED", "TIMED_OUT", "CANCELLED"} {
		data, _ := json.Marshal(publicJob(sandbox.Job{Status: status, Error: secret}))
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("driver error leaked: %s", data)
		}
	}
	w := httptest.NewRecorder()
	failure(w, errors.New(secret))
	if w.Code != 500 || strings.Contains(w.Body.String(), secret) {
		t.Fatalf("internal error leaked: %s", w.Body.String())
	}
	_, m := setupAPI(t)
	if _, err := NewConfigured(m, Options{}); err == nil {
		t.Fatal("authentication silently disabled")
	}
}

func TestMetadataCapacityErrorProjection(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{sandbox.ErrMetadataCapacity, 503, "METADATA_CAPACITY"},
		{sandbox.ErrTenantMetadataCapacity, 429, "TENANT_METADATA_QUOTA"},
	} {
		w := httptest.NewRecorder()
		failure(w, fmt.Errorf("%w: private-host-diagnostic", tc.err))
		var body struct {
			Error struct {
				Code string `json:"code"`
			}
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if w.Code != tc.status || body.Error.Code != tc.code || bytes.Contains(w.Body.Bytes(), []byte("private-host-diagnostic")) {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}
