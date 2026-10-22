package client

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestTokenKeyAndNoRedirect(t *testing.T) {
	// Use a short path: sockaddr_un has a small platform-dependent bound.
	dir, err := os.MkdirTemp("", "xbc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("t", 40)
	var calls atomic.Int32
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("missing bearer token")
		}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://elsewhere.invalid/stolen", http.StatusTemporaryRedirect)
			return
		}
		if r.Method != "POST" || r.URL.Path != "/v1/sandboxes" || r.Header.Get("Idempotency-Key") != "retry-key" {
			t.Errorf("incorrect creation request: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]string{"ok": "yes"})
	}))
	s.Listener.Close()
	s.Listener = listener
	s.Start()
	defer s.Close()
	c := NewWithToken(socket, token)
	defer c.Close()
	var result map[string]string
	if err := c.Create(context.Background(), "retry-key", map[string]any{}, &result); err != nil || result["ok"] != "yes" {
		t.Fatalf("create: %+v %v", result, err)
	}
	if err := c.Do(context.Background(), "GET", "/redirect", nil, &result); err == nil {
		t.Fatal("redirect silently followed")
	}
	if calls.Load() != 2 {
		t.Fatalf("token redirected to another request: %d calls", calls.Load())
	}
}
