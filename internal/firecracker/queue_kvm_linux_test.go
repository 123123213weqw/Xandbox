//go:build linux

package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

// This test is compiled by normal Linux CI but explicitly skipped unless a
// dedicated root KVM fixture is supplied. The only executed workload goes
// through the real Driver's guest vsock path, never a host command fallback.
func TestKVMQueueIsolation(t *testing.T) {
	if os.Getenv("XANDBOX_KVM_QUEUE_ACCEPTANCE") != "1" {
		t.Skip("requires explicitly provisioned root KVM fixture")
	}
	var fixture struct {
		StateDir       string `json:"state_dir"`
		ConfigPath     string `json:"config_path"`
		ReportPath     string `json:"report_path"`
		SourceRevision string `json:"source_revision"`
	}
	if os.Geteuid() != 0 {
		t.Fatal("KVM fixture must run as root")
	}
	data, err := privatefile.Read(os.Getenv("XANDBOX_KVM_QUEUE_FIXTURE"), 8192)
	if err != nil {
		t.Fatal(err)
	}
	if err := strictjson.Decode(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !cleanAbsolute(fixture.StateDir) || !cleanAbsolute(fixture.ReportPath) || len(fixture.SourceRevision) != 40 {
		t.Fatal("invalid fixture")
	}
	if err := os.Mkdir(fixture.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(fixture.StateDir, "controller.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	store, err := sandbox.NewFileStore(filepath.Join(fixture.StateDir, "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := New(fixture.StateDir, fixture.ConfigPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	real := raw.(*driver)
	opts := sandbox.Options{MaxInstances: 2, StopWorkers: 1, CleanupWorkers: 1, WorkQueueSize: 1, PrepareTimeout: 30 * time.Second, StopTimeout: 5 * time.Second, CleanupTimeout: 60 * time.Second, ReapInterval: 10 * time.Millisecond}
	manager, err := sandbox.NewManager(store, real, opts)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce, enterOnce sync.Once
	oldStopped := false
	// Block exactly where a physical directory fsync could stall after unlink.
	// No Manager/driver memory lock may remain held here. The UID stays leased.
	real.registry.syncDirectory = func(path string) error { enterOnce.Do(func() { close(entered) }); <-release; return syncDir(path) }
	defer func() {
		releaseOnce.Do(func() { close(release) })
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if !oldStopped {
			_ = manager.Close(ctx)
		}
	}()
	create := func(ttl int) sandbox.Record {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		r, err := manager.Create(ctx, sandbox.CreateRequest{TTLMS: ttl, Limits: sandbox.Limits{MaxExecMS: 60000}})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	wait := func(name string, predicate func() bool) {
		deadline := time.Now().Add(35 * time.Second)
		for time.Now().Before(deadline) {
			if predicate() {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("timeout: " + name)
	}
	a, b := create(60000), create(20000)
	job, err := manager.Exec(b.ID, sandbox.ExecRequest{Generation: b.Generation, Argv: []string{"sleep", "55"}, TimeoutMS: 60000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Destroy(a.Ref); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("ownership fsync barrier not reached")
	}
	akey, _ := key(a.Ref)
	if !real.registry.owns(akey) {
		t.Fatal("UID released before deletion fsync")
	}
	wait("TTL host stop despite unrelated fsync", func() bool {
		r, err := manager.Get(b.ID)
		return err == nil && r.State == sandbox.Stopped && r.DeleteRequested
	})
	afterExpiryMS := float64(time.Now().Sub(b.ExpiresAt)) / float64(time.Millisecond)
	bkey, _ := key(b.Ref)
	group, _ := real.paths(bkey)
	if err := emptyGroup(group); err != nil {
		t.Fatal("VM still executing: ", err)
	}
	j, err := manager.GetJob(b.ID, job.ID)
	if err != nil || j.Status != "CANCELLED" {
		t.Fatalf("TTL did not drain execution: %+v %v", j, err)
	}
	wait("cleanup backlog retained", func() bool {
		s := manager.Stats()
		return s.Active == 2 && s.CleanupRunning == 1 && s.CleanupQueued == 1
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	stopped, err := manager.Stop(ctx, a.Ref)
	cancel()
	if err != nil || stopped.State != sandbox.Reclaiming {
		t.Fatalf("confirmed Stop waited on blocked GC: %+v %v", stopped, err)
	}
	if _, err := manager.Create(context.Background(), sandbox.CreateRequest{}); !errors.Is(err, sandbox.ErrCapacity) {
		t.Fatalf("early capacity return: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	err = manager.Close(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close falsely succeeded during blocked fsync: %v", err)
	}
	select {
	case <-manager.LifecycleDone():
		t.Fatal("worker termination falsely reported")
	default:
	}
	if manager.Stats().Active != 2 {
		t.Fatal("Close dropped owned capacity")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-manager.LifecycleDone():
	case <-time.After(10 * time.Second):
		t.Fatal("workers didn't drain after I/O resumed")
	}
	oldStopped = true
	rows, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	nextDriver, err := New(fixture.StateDir, fixture.ConfigPath, rows)
	if err != nil {
		t.Fatal(err)
	}
	next, err := sandbox.NewManager(store, nextDriver, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := next.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	for _, r := range []sandbox.Record{a, b} {
		if _, err := next.Exec(r.ID, sandbox.ExecRequest{Generation: r.Generation, Argv: []string{"true"}}); !errors.Is(err, sandbox.ErrNotReady) {
			t.Fatal("recovery resurrected generation: ", err)
		}
		wait("durable recovery", func() bool { v, err := next.Get(r.ID); return err == nil && v.State == sandbox.Destroyed })
		k, _ := key(r.Ref)
		cg, jail := real.paths(k)
		for _, p := range []string{cg, jail} {
			if _, err := os.Lstat(p); !os.IsNotExist(err) {
				t.Fatal("owned resources remain")
			}
		}
	}
	wait("capacity after durable destruction", func() bool { return next.Stats().Active == 0 })
	report := map[string]any{
		"test": "real_kvm_controlled_ownership_fsync_stall", "production_ready": false,
		"source_revision": fixture.SourceRevision, "toolchain": runtime.Version(), "stop_workers": 1, "cleanup_workers": 1, "queue_capacity_per_pool": 1,
		"ttl_expiry_to_stopped_observed_ms": afterExpiryMS,
		"fault_model":                       "test-only ownership-directory fsync barrier after private unlink, not an actual failing disk or a production runtime flag",
		"checks":                            []string{"real VMM workload stopped at TTL while unrelated ownership deletion fsync was blocked", "kernel host cgroup empty and guest execution drained", "already-confirmed Stop bypasses its own blocked GC", "cleanup queue bounded with one queued generation", "UID and node capacity retained until durable cleanup", "Close deadline returns without claiming worker termination", "exclusive fixture lock retained until old workers quiesced", "new controller/driver recovers unfinished ledger without resurrecting generations", "all private resources and capacity reclaimed after recovery"},
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(fixture.ReportPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(encoded, '\n')); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
