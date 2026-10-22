//go:build linux

package firecracker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRetryHonorsContextAndExitedSupervisor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := retry(ctx, nil, func() error { return errors.New("not ready") }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline not propagated: %v", err)
	}
	done := make(chan struct{})
	close(done)
	called := false
	if err := retry(context.Background(), done, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("readiness succeeded after supervisor exit")
	}
}

func TestFirecrackerAPIOnlyUsesUnixSocketAndRefusesRedirect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	mode := make(chan bool, 2)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || r.URL.Path != "/test" {
			t.Error("unexpected API operation")
		}
		if <-mode {
			w.WriteHeader(204)
		} else {
			w.Header().Set("Location", "http://127.0.0.1:1/escape")
			w.WriteHeader(307)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	mode <- true
	if err := apiPut(context.Background(), path, "/test", map[string]bool{"test": true}); err != nil {
		t.Fatal(err)
	}
	mode <- false
	if err := apiPut(context.Background(), path, "/test", map[string]bool{}); err == nil {
		t.Fatal("accepted redirected API")
	}
}

func TestOwnedCgroupProofRequiresExplicitEmpty(t *testing.T) {
	group := t.TempDir()
	events := filepath.Join(group, "cgroup.events")
	for _, text := range []string{"", "populated 1\n", "populated 01\n", "unknown 0\n"} {
		if err := os.WriteFile(events, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if emptyGroup(group) == nil {
			t.Fatal("accepted missing stop proof")
		}
	}
	if err := os.WriteFile(events, []byte("populated 0\nfrozen 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := emptyGroup(group); err != nil {
		t.Fatal(err)
	}
	if err := emptyGroup(filepath.Join(group, "absent")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(group, "missing", nil); err == nil {
		t.Fatal("driver initialized without required root policy")
	}
}
