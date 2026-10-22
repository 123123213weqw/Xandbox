//go:build linux || darwin

package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

type catalogChildFixture struct {
	Backend string
	Config  Config
	ABI     string
}

// Helper modes exist only in a trusted test executable, never in sandboxd or the
// operator CLI. They cannot execute task argv or initialize a guest on the host.
func TestCatalogProcessHelper(t *testing.T) {
	mode := os.Getenv("XANDBOX_CATALOG_TEST_HELPER")
	if mode == "" {
		t.Skip("child process only")
	}
	switch mode {
	case "lock-blocked", "lock-free":
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		defer cancel()
		unlock, e := catalogLock(ctx, os.Getenv("XANDBOX_CATALOG_TEST_PATH"))
		if mode == "lock-blocked" {
			if !errors.Is(e, context.DeadlineExceeded) {
				t.Fatal("parent lock not observed", e)
			}
		} else {
			if e != nil {
				t.Fatal(e)
			}
			unlock()
		}
	case "kill-after-pin":
		b, e := privatefile.Read(os.Getenv("XANDBOX_CATALOG_TEST_PATH"), 16384)
		if e != nil {
			t.Fatal(e)
		}
		var f catalogChildFixture
		if e = json.Unmarshal(b, &f); e != nil {
			t.Fatal(e)
		}
		r, e := newRegistry(f.Backend, f.Config, nil)
		if e != nil {
			t.Fatal(e)
		}
		r.hostABI = f.ABI
		persist := r.persist
		r.persist = func(path string, value any) error {
			if e := persist(path, value); e != nil {
				return e
			}
			if e := syscall.Kill(os.Getpid(), syscall.SIGKILL); e != nil {
				t.Fatal(e)
			}
			select {}
		}
		if _, e = r.reserve(reference("1")); e != nil {
			t.Fatal(e)
		}
		t.Fatal("expected test-only SIGKILL did not happen")
	default:
		t.Fatal("unknown test helper mode")
	}
}
func catalogChild(t *testing.T, mode, path string) error {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestCatalogProcessHelper$", "-test.count=1")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "XANDBOX_CATALOG_TEST_HELPER=" + mode, "XANDBOX_CATALOG_TEST_PATH=" + path}
	output, e := cmd.CombinedOutput()
	if e != nil && mode != "kill-after-pin" {
		t.Fatalf("catalog child failed: %v %s", e, output)
	}
	return e
}
func TestCatalogLockAndDurablePinSurviveActualChildSIGKILL(t *testing.T) {
	r, m, mem, state := catalogFixture(t)
	id := publishActive(t, r, m, mem, state)
	lock := filepath.Join(r.catalog.root, ".lock")
	unlock, e := catalogLock(context.Background(), lock)
	if e != nil {
		t.Fatal(e)
	}
	_ = catalogChild(t, "lock-blocked", lock)
	unlock()
	_ = catalogChild(t, "lock-free", lock)
	p := filepath.Join(t.TempDir(), "fixture.json")
	raw, _ := json.Marshal(catalogChildFixture{r.dir, r.cfg, r.hostABI})
	if e = os.WriteFile(p, raw, 0600); e != nil {
		t.Fatal(e)
	}
	e = catalogChild(t, "kill-after-pin", p)
	var exited *exec.ExitError
	if !errors.As(e, &exited) {
		t.Fatal("child was not terminated by SIGKILL", e)
	}
	status, ok := exited.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("wrong terminal child state", status)
	}
	recovered, e := newRegistry(r.dir, r.cfg, []sandbox.Record{ledger(reference("1"))})
	if e != nil {
		t.Fatal(e)
	}
	if e = recovered.catalog.retire(context.Background(), id); e != nil {
		t.Fatal(e)
	}
	if removed, e := recovered.catalog.collect(context.Background()); e != nil || len(removed) != 0 {
		t.Fatal("dead controller lost durable pin", e, removed)
	}
	k, _ := key(reference("1"))
	if !recovered.owns(k) {
		t.Fatal("ownership not reconstructed")
	}
}
