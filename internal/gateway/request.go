package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

func hexID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'f' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// Only ordinary tenant routes. No prefix proxy, CONNECT, upgrade, admin,
// metrics, operator, redirect or path normalization is ever used.
func route(method, path string) (body bool, ok bool) {
	if method == "GET" && (path == "/healthz" || path == "/readyz") {
		return false, true
	}
	v := strings.Split(path, "/")
	if len(v) < 3 || v[0] != "" || v[1] != "v1" {
		return false, false
	}
	if v[2] == "sandboxes" {
		if len(v) == 3 {
			return true, method == "POST"
		}
		if !hexID(v[3]) {
			return false, false
		}
		if len(v) == 4 {
			return method == "DELETE", method == "GET" || method == "DELETE"
		}
		if len(v) == 5 && (v[4] == "exec" || v[4] == "stop") {
			return true, method == "POST"
		}
		if len(v) == 6 && v[4] == "executions" && hexID(v[5]) {
			return false, method == "GET"
		}
	}
	if v[2] == "sessions" {
		if len(v) == 3 {
			return true, method == "POST"
		}
		if !hexID(v[3]) {
			return false, false
		}
		if len(v) == 4 {
			return false, method == "GET"
		}
		if len(v) == 5 && (v[4] == "switch" || v[4] == "exec" || v[4] == "revoke") {
			return true, method == "POST"
		}
	}
	return false, false
}
func requestShape(r *http.Request, p *Policy) (bool, error) {
	bad := errors.New("invalid gateway request")
	body, ok := route(r.Method, r.URL.Path)
	keyRoute := r.Method == "POST" && (r.URL.Path == "/v1/sandboxes" || r.URL.Path == "/v1/sessions" || (strings.HasPrefix(r.URL.Path, "/v1/sessions/") && strings.HasSuffix(r.URL.Path, "/switch")))
	if r.Header.Get("Idempotency-Key") != "" && !keyRoute {
		return false, bad
	}
	if !ok || r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.TLS == nil || r.TLS.Version != 0x0304 || r.TLS.ServerName != p.snapshot.ServerName || !p.hostValid(r.Host) || r.URL.Scheme != "" || r.URL.Host != "" || r.URL.Opaque != "" || r.URL.User != nil || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.RequestURI != r.URL.Path || len(r.RequestURI) > 256 || strings.ContainsAny(r.RequestURI, "%\\") || len(r.TransferEncoding) > 0 || len(r.Trailer) > 0 || r.ContentLength < 0 || r.ContentLength > MaxBodyBytes {
		return false, bad
	}
	for k, vals := range r.Header {
		if len(vals) != 1 || len(vals[0]) > 1024 {
			return false, bad
		}
		switch strings.ToLower(k) {
		case "authorization":
			if len(vals[0]) > 520 {
				return false, bad
			}
		case "idempotency-key":
			if len(vals[0]) < 1 || len(vals[0]) > 128 {
				return false, bad
			}
			for _, c := range vals[0] {
				if c < 33 || c > 126 {
					return false, bad
				}
			}
		case "content-type":
			if vals[0] != "application/json" {
				return false, bad
			}
		case "content-length":
			n, e := strconv.ParseInt(vals[0], 10, 64)
			if e != nil || n != r.ContentLength || strconv.FormatInt(n, 10) != vals[0] {
				return false, bad
			}
		case "user-agent", "accept", "accept-encoding": // Never forwarded.
		default:
			return false, bad
		}
	}
	if body {
		if len(r.Header.Values("Content-Type")) != 1 || r.ContentLength == 0 {
			return false, bad
		}
	} else if r.ContentLength != 0 || r.Header.Get("Content-Type") != "" || r.Header.Get("Idempotency-Key") != "" {
		return false, bad
	}
	return body, nil
}

type Frontend struct {
	policies  *Store
	transport *http.Transport
	inflight  chan struct{}
	rateMu    sync.Mutex
	rate      bucket
}

func NewFrontend(p *Store, dial func(context.Context, string, string) (net.Conn, error)) *Frontend {
	return &Frontend{policies: p, inflight: make(chan struct{}, MaxInflight), rate: bucket{tokens: 128, last: time.Now()}, transport: &http.Transport{Proxy: nil, DialContext: dial, DisableCompression: true, ForceAttemptHTTP2: false, MaxIdleConns: MaxInflight, MaxIdleConnsPerHost: MaxInflight, MaxConnsPerHost: MaxInflight, IdleConnTimeout: 5 * time.Second, ResponseHeaderTimeout: RequestTimeout, MaxResponseHeaderBytes: 8192}}
}
func (f *Frontend) CloseIdle() { f.transport.CloseIdleConnections() }
func gatewayError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Connection", "close")
	if status == 429 {
		w.Header().Set("Retry-After", "1")
	}
	if status == 401 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="xandbox"`)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code}})
}
func (f *Frontend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case f.inflight <- struct{}{}:
		defer func() { <-f.inflight }()
	default:
		gatewayError(w, 503, "GATEWAY_BUSY")
		return
	}
	p := f.policies.Current()
	now := time.Now()
	if p == nil || !p.validAt(now) {
		gatewayError(w, 503, "GATEWAY_UNAVAILABLE")
		return
	}
	if _, e := requestShape(r, p); e != nil {
		gatewayError(w, 400, "INVALID_REQUEST")
		return
	}
	vals := r.Header.Values("Authorization")
	if len(vals) != 1 {
		gatewayError(w, 401, "UNAUTHORIZED")
		return
	}
	cred, ok := p.authenticate(vals[0], now)
	if !ok {
		gatewayError(w, 401, "UNAUTHORIZED")
		return
	}
	select {
	case p.tenants[cred.tenant] <- struct{}{}:
		defer func() { <-p.tenants[cred.tenant] }()
	default:
		gatewayError(w, 429, "TENANT_BUSY")
		return
	}
	f.rateMu.Lock()
	global := f.rate.allow(now, 128, 128)
	f.rateMu.Unlock()
	if !global || !p.tenantRate(cred.tenant, now) {
		gatewayError(w, 429, "RATE_LIMITED")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), RequestTimeout)
	defer cancel()
	var data []byte
	var e error
	if r.ContentLength > 0 {
		data, e = io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
		if e != nil || int64(len(data)) != r.ContentLength {
			gatewayError(w, 400, "INVALID_REQUEST")
			return
		}
	}
	out, e := http.NewRequestWithContext(ctx, r.Method, "http://tenant.local"+r.URL.Path, bytes.NewReader(data))
	if e != nil {
		gatewayError(w, 400, "INVALID_REQUEST")
		return
	}
	out.Header = make(http.Header)
	out.Header.Set("Authorization", "Bearer "+cred.backend)
	out.Header.Set("Accept", "application/json")
	if len(data) > 0 {
		out.Header.Set("Content-Type", "application/json")
	}
	if key := r.Header.Get("Idempotency-Key"); key != "" {
		out.Header.Set("Idempotency-Key", key)
	}
	// This URL is constructed here, never from client authority/forwarded headers.
	out.URL = &url.URL{Scheme: "http", Host: "tenant.local", Path: r.URL.Path}
	out.Host = "tenant.local"
	response, e := f.transport.RoundTrip(out)
	if e != nil {
		gatewayError(w, 502, "UPSTREAM_UNAVAILABLE")
		return
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case 200, 201, 202, 400, 404, 409, 410, 413, 429, 500, 503:
	default:
		gatewayError(w, 502, "UPSTREAM_UNAVAILABLE")
		return
	}
	if response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Content-Encoding") != "" || len(response.TransferEncoding) > 1 || len(response.Trailer) > 0 || response.ContentLength > MaxResponseBytes {
		gatewayError(w, 502, "UPSTREAM_UNAVAILABLE")
		return
	}
	data, e = io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if e != nil || len(data) > MaxResponseBytes || !json.Valid(data) {
		gatewayError(w, 502, "UPSTREAM_UNAVAILABLE")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(data)
}
