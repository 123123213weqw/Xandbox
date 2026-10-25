package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func goodRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, "https://gateway.test"+path, strings.NewReader(body))
	r.URL.Scheme = ""
	r.URL.Host = ""
	r.RequestURI = path
	r.Host = "gateway.test"
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, ServerName: "gateway.test"}
	r.Header.Set("Authorization", "Bearer "+testExternal)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}
func TestTenantRouteAllowlistAndAmbiguousRequestsNeverDial(t *testing.T) {
	s, a := testSnapshot(t)
	p, e := NewPolicy(s, a, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	store := &Store{}
	store.Publish(p)
	var dials atomic.Int64
	front := NewFrontend(store, func(context.Context, string, string) (net.Conn, error) { dials.Add(1); return nil, net.ErrClosed })
	defer front.CloseIdle()
	id := strings.Repeat("1", 32)
	for _, path := range []string{"/metrics", "/v1/node", "/v1/node/resume", "/v1/admin", "/healthz/", "//healthz", "/v1/../healthz", "/v1/sandboxes/other", "/v1/sandboxes/" + id + "/exec/other", "/v1/sessions/" + id + "/unknown"} {
		w := httptest.NewRecorder()
		front.ServeHTTP(w, goodRequest("GET", path, ""))
		if w.Code != 400 {
			t.Fatal("unknown route", path, w.Code)
		}
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Method = "CONNECT" }, func(r *http.Request) { r.ProtoMajor = 2 }, func(r *http.Request) { r.TLS = nil }, func(r *http.Request) { r.TLS.Version = tls.VersionTLS12 }, func(r *http.Request) { r.TLS.ServerName = "other.test" }, func(r *http.Request) { r.Host = "attacker.test" },
		func(r *http.Request) { r.URL.RawQuery = "x=1" }, func(r *http.Request) { r.URL.ForceQuery = true }, func(r *http.Request) { r.URL.Scheme = "http"; r.URL.Host = "operator.local" }, func(r *http.Request) { r.URL.RawPath = "/%68ealthz"; r.RequestURI = r.URL.RawPath },
		func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, func(r *http.Request) { r.Trailer = http.Header{"Foo": []string{"bar"}} }, func(r *http.Request) { r.ContentLength = -1 }, func(r *http.Request) { r.Header.Set("Connection", "Authorization") }, func(r *http.Request) { r.Header.Set("X-Tenant-ID", "other") }, func(r *http.Request) { r.Header.Set("Forwarded", "host=other") }, func(r *http.Request) { r.Header.Set("X-Forwarded-For", "127.0.0.1") }, func(r *http.Request) { r.Header.Set("Upgrade", "websocket") }, func(r *http.Request) { r.Header.Set("Cookie", "private") }, func(r *http.Request) { r.Header.Set("Origin", "https://other.test") }, func(r *http.Request) { r.Header.Set("Expect", "100-continue") }, func(r *http.Request) { r.Header.Add("Authorization", "Bearer "+testExternal) }, func(r *http.Request) { r.Header.Set("Content-Length", "00") },
	} {
		r := goodRequest("GET", "/healthz", "")
		mutate(r)
		w := httptest.NewRecorder()
		front.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("ambiguous request accepted", w.Code)
		}
	}
	if dials.Load() != 0 {
		t.Fatal("rejected request reached connector")
	}
	for _, row := range []struct{ method, path string }{{"POST", "/v1/sandboxes"}, {"GET", "/v1/sandboxes/" + id}, {"DELETE", "/v1/sandboxes/" + id}, {"POST", "/v1/sandboxes/" + id + "/exec"}, {"GET", "/v1/sandboxes/" + id + "/executions/" + id}, {"POST", "/v1/sessions"}, {"GET", "/v1/sessions/" + id}, {"POST", "/v1/sessions/" + id + "/switch"}, {"POST", "/v1/sessions/" + id + "/exec"}, {"POST", "/v1/sessions/" + id + "/revoke"}} {
		if _, ok := route(row.method, row.path); !ok {
			t.Fatal("tenant route absent")
		}
	}
	// An idempotency header must not turn non-idempotent exec into a transport retry.
	r := goodRequest("POST", "/v1/sandboxes/"+id+"/exec", `{}`)
	r.Header.Set("Idempotency-Key", "retry-exec")
	if _, e := requestShape(r, p); e == nil {
		t.Fatal("exec retry semantics widened")
	}
}
func TestFrontendReconstructsPrivateCredentialNoHeaderLeak(t *testing.T) {
	s, a := testSnapshot(t)
	p, e := NewPolicy(s, a, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	store := &Store{}
	store.Publish(p)
	var hits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Host != "tenant.local" || r.URL.Path != "/v1/sandboxes" || r.Header.Get("Authorization") != "Bearer "+testBackend || r.Header.Get("Idempotency-Key") != "request-1" || r.Header.Get("Accept-Encoding") != "" || r.Header.Get("X-Forwarded-For") != "" {
			t.Error("upstream request not rebuilt")
		}
		data, _ := io.ReadAll(r.Body)
		if string(data) != `{}` {
			t.Error("body changed")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "not-forwarded")
		w.WriteHeader(201)
		io.WriteString(w, `{"ok":true}`)
	}))
	defer backend.Close()
	front := NewFrontend(store, func(ctx context.Context, n, addr string) (net.Conn, error) {
		if n != "tcp" || addr != "tenant.local:80" {
			t.Fatal("client selected upstream")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", backend.Listener.Addr().String())
	})
	defer front.CloseIdle()
	r := goodRequest("POST", "/v1/sandboxes", `{}`)
	r.Header.Set("Idempotency-Key", "request-1")
	r.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	front.ServeHTTP(w, r)
	if w.Code != 201 || w.Body.String() != `{"ok":true}` || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Cache-Control") != "no-store" || hits.Load() != 1 {
		t.Fatal("response/projection")
	}
	for _, header := range []string{"", "Bearer " + testBackend, "Bearer " + strings.Repeat("z", 40)} {
		r := goodRequest("POST", "/v1/sandboxes", `{}`)
		r.Header.Del("Authorization")
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		w := httptest.NewRecorder()
		front.ServeHTTP(w, r)
		if w.Code != 401 || strings.Contains(w.Body.String(), testBackend) || hits.Load() != 1 {
			t.Fatal("unauthorized token reached upstream or leaked")
		}
	}
}
func TestTLS13IdentityAndNewPolicyPerRequestEvenOnExistingConnection(t *testing.T) {
	s, a := testSnapshot(t)
	p, e := NewPolicy(s, a, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	store := &Store{}
	store.Publish(p)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testBackend {
			t.Error("external credential forwarded")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"production_ready":false}`)
	}))
	defer backend.Close()
	front := NewFrontend(store, func(ctx context.Context, n, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", backend.Listener.Addr().String())
	})
	defer front.CloseIdle()
	server := httptest.NewUnstartedServer(front)
	server.EnableHTTP2 = false
	server.TLS = store.TLSConfig()
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(s.CertificatePEM))
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "gateway.test", MinVersion: tls.VersionTLS13}, DisableCompression: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	call := func(token string, want int) {
		r, _ := http.NewRequest("GET", server.URL+"/healthz", nil)
		r.Host = "gateway.test"
		r.Header.Set("Authorization", "Bearer "+token)
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != want || response.TLS.Version != tls.VersionTLS13 {
			t.Fatal("TLS/authorization", response.StatusCode)
		}
	}
	call(testExternal, 200)
	next := s
	next.Epoch = 2
	next.Keys = append([]ClientKey(nil), s.Keys...)
	newToken := strings.Repeat("d", 40)
	next.Keys[0].TokenSHA256 = tokenHash(newToken)
	q, e := NewPolicy(next, a, time.Now())
	if e != nil || store.Publish(q) != nil {
		t.Fatal("rotate")
	}
	call(testExternal, 401)
	call(newToken, 200)
	bad := tr.Clone()
	bad.TLSClientConfig = bad.TLSClientConfig.Clone()
	bad.TLSClientConfig.MaxVersion = tls.VersionTLS12
	bad.TLSClientConfig.MinVersion = tls.VersionTLS12
	defer bad.CloseIdleConnections()
	if _, e := (&http.Client{Transport: bad, Timeout: time.Second}).Get(server.URL); e == nil {
		t.Fatal("TLS1.2 accepted")
	}
	bad = tr.Clone()
	bad.TLSClientConfig = bad.TLSClientConfig.Clone()
	bad.TLSClientConfig.ServerName = "other.test"
	defer bad.CloseIdleConnections()
	if _, e := (&http.Client{Transport: bad, Timeout: time.Second}).Get(server.URL); e == nil {
		t.Fatal("wrong SNI accepted")
	}
}
func TestResponseBudgetRedirectAndMalformedUpstreamFailClosed(t *testing.T) {
	s, a := testSnapshot(t)
	p, e := NewPolicy(s, a, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	store := &Store{}
	store.Publish(p)
	for _, row := range []struct {
		status            int
		body, contentType string
	}{{302, `{}`, "application/json"}, {401, `{}`, "application/json"}, {200, "not JSON", "application/json"}, {200, `{}`, "text/html"}, {200, strings.Repeat("x", MaxResponseBytes+1), "application/json"}} {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", row.contentType)
			w.Header().Set("Location", "https://other.test/")
			w.WriteHeader(row.status)
			io.Copy(w, bytes.NewBufferString(row.body))
		}))
		front := NewFrontend(store, func(ctx context.Context, n, a string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", backend.Listener.Addr().String())
		})
		w := httptest.NewRecorder()
		front.ServeHTTP(w, goodRequest("GET", "/healthz", ""))
		front.CloseIdle()
		backend.Close()
		if w.Code != 502 || w.Header().Get("Location") != "" || w.Body.Len() > 256 {
			t.Fatal("unsafe upstream response forwarded")
		}
	}
}
