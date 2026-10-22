package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func setup(t *testing.T, opts Options, wrap func(Driver) Driver) (*Manager, string, *FileStore) {
	t.Helper()
	base := t.TempDir()
	store, err := NewFileStore(filepath.Join(base, "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	driver, err := NewMockDriver(filepath.Join(base, "instances"))
	if err != nil {
		t.Fatal(err)
	}
	var backend Driver = driver
	if wrap != nil {
		backend = wrap(driver)
	}
	if opts.ReapInterval == 0 {
		opts.ReapInterval = 5 * time.Millisecond
	}
	if opts.RetryDelay == 0 {
		opts.RetryDelay = 10 * time.Millisecond
	}
	m, err := NewManager(store, backend, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return m, base, store
}

func create(t *testing.T, m *Manager, req CreateRequest) Record {
	t.Helper()
	r, err := m.Create(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func eventually(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not become true")
}

func waitState(t *testing.T, m *Manager, id string, state State) Record {
	t.Helper()
	var r Record
	eventually(t, func() bool {
		var err error
		r, err = m.Get(id)
		return err == nil && r.State == state
	})
	return r
}

func execDone(t *testing.T, m *Manager, r Record, argv ...string) Job {
	t.Helper()
	j, err := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: argv})
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		var err error
		j, err = m.GetJob(r.ID, j.ID)
		return err == nil && j.Status != "RUNNING"
	})
	return j
}

func TestLifecycleAndIdempotentDeletion(t *testing.T) {
	m, base, store := setup(t, Options{}, nil)
	r := create(t, m, CreateRequest{})
	if r.State != Ready || r.Backend != "mock" {
		t.Fatalf("unexpected instance: %+v", r)
	}
	if j := execDone(t, m, r, "write", "hello.txt", "hello"); j.Status != "EXITED" || j.Output.ExitCode != 0 {
		t.Fatalf("write: %+v", j)
	}
	if j := execDone(t, m, r, "read", "hello.txt"); j.Output.Stdout != "hello" {
		t.Fatalf("read: %+v", j)
	}
	job, err := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"sleep", "2s"}})
	if err != nil {
		t.Fatal(err)
	}
	stopped, err := m.Stop(context.Background(), r.Ref)
	if err != nil || stopped.State != Stopped || stopped.StoppedAt.IsZero() {
		t.Fatalf("stop: %+v, %v", stopped, err)
	}
	job, err = m.GetJob(r.ID, job.ID)
	if err != nil || job.Status != "CANCELLED" {
		t.Fatalf("stop did not drain running execution: %+v, %v", job, err)
	}
	if _, err := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo", "late"}}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("stopped instance accepted work: %v", err)
	}
	for range 3 {
		if _, err := m.Destroy(r.Ref); err != nil {
			t.Fatal(err)
		}
	}
	final := waitState(t, m, r.ID, Destroyed)
	if final.DestroyedAt.Before(final.StoppedAt) {
		t.Fatal("destroyed timestamp precedes stopped timestamp")
	}
	eventually(t, func() bool { return m.Stats().Active == 0 })
	entries, err := os.ReadDir(filepath.Join(base, "instances"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("runtime resources leaked: %v %v", entries, err)
	}
	ledger, err := store.Load()
	if err != nil || len(ledger) != 1 || ledger[0].State != Destroyed {
		t.Fatalf("destroyed state not durable: %+v, %v", ledger, err)
	}
	if _, err := m.Destroy(r.Ref); err != nil {
		t.Fatal(err)
	}
}

func TestGenerationFence(t *testing.T) {
	m, _, _ := setup(t, Options{}, nil)
	r := create(t, m, CreateRequest{})
	bad := Ref{ID: r.ID, Generation: strings.Repeat("0", 32)}
	if _, err := m.Exec(r.ID, ExecRequest{Generation: bad.Generation, Argv: []string{"echo"}}); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	if _, err := m.Stop(context.Background(), bad); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	if _, err := m.Destroy(bad); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	current, _ := m.Get(r.ID)
	if current.State != Ready {
		t.Fatal("stale mutation changed current generation")
	}
}

func TestTimeoutOutputBoundAndHistoryLimit(t *testing.T) {
	m, _, _ := setup(t, Options{}, nil)
	r := create(t, m, CreateRequest{Limits: Limits{MaxExecMS: 20, MaxOutputBytes: 4, MaxJobs: 2}})
	j := execDone(t, m, r, "echo", "123456789")
	if j.Output.Stdout != "1234" || !j.Output.Truncated {
		t.Fatalf("unbounded output: %+v", j)
	}
	j = execDone(t, m, r, "sleep", "1s")
	if j.Status != "TIMED_OUT" {
		t.Fatalf("timeout not enforced: %+v", j)
	}
	if _, err := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo"}}); !errors.Is(err, ErrJobLimit) {
		t.Fatalf("unbounded history: %v", err)
	}
}

func TestMockHasNoHostShell(t *testing.T) {
	m, _, _ := setup(t, Options{}, nil)
	r := create(t, m, CreateRequest{})
	if j := execDone(t, m, r, "/bin/sh", "-c", "echo unexpected"); j.Status != "FAILED" || !strings.Contains(j.Error, "no host shell") {
		t.Fatalf("unexpected mock execution: %+v", j)
	}
	if j := execDone(t, m, r, "echo", "$(whoami); touch file"); j.Output.Stdout != "$(whoami); touch file\n" {
		t.Fatalf("shell syntax was interpreted: %+v", j)
	}
	if j := execDone(t, m, r, "fail"); j.Status != "EXITED" || j.Output.ExitCode != 1 {
		t.Fatalf("exit status was lost: %+v", j)
	}
}

func TestWorkspacesAndPathContainment(t *testing.T) {
	m, base, _ := setup(t, Options{}, nil)
	a, b := create(t, m, CreateRequest{}), create(t, m, CreateRequest{})
	execDone(t, m, a, "write", "secret", "private-a")
	if j := execDone(t, m, b, "read", "secret"); j.Status != "FAILED" {
		t.Fatalf("cross-workspace read: %+v", j)
	}
	outside := filepath.Join(base, "outside")
	if err := os.WriteFile(outside, []byte("host marker"), 0600); err != nil {
		t.Fatal(err)
	}
	instanceDir := filepath.Join(base, "instances", a.ID+"-"+a.Generation)
	if err := os.Symlink(outside, filepath.Join(instanceDir, "escape")); err != nil {
		t.Fatal(err)
	}
	for _, argv := range [][]string{{"read", "../../outside"}, {"read", outside}, {"read", "escape"}, {"write", "escape", "overwrite"}} {
		if j := execDone(t, m, a, argv...); j.Status != "FAILED" {
			t.Fatalf("path escape accepted: %v -> %+v", argv, j)
		}
	}
	data, _ := os.ReadFile(outside)
	if string(data) != "host marker" {
		t.Fatal("outside file changed")
	}
}

type gateDriver struct {
	Driver
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
	gateStop bool
}

func (d *gateDriver) gate(ctx context.Context) error {
	d.once.Do(func() { close(d.entered) })
	select {
	case <-d.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *gateDriver) Stop(ctx context.Context, ref Ref) error {
	if d.gateStop {
		if err := d.gate(ctx); err != nil {
			return err
		}
	}
	return d.Driver.Stop(ctx, ref)
}

func (d *gateDriver) Cleanup(ctx context.Context, ref Ref) error {
	if !d.gateStop {
		if err := d.gate(ctx); err != nil {
			return err
		}
	}
	return d.Driver.Cleanup(ctx, ref)
}

func TestCapacityNotReturnedBeforeCleanup(t *testing.T) {
	d := &gateDriver{entered: make(chan struct{}), release: make(chan struct{})}
	m, _, _ := setup(t, Options{MaxInstances: 1}, func(base Driver) Driver { d.Driver = base; return d })
	defer close(d.release)
	r := create(t, m, CreateRequest{})
	if _, err := m.Destroy(r.Ref); err != nil {
		t.Fatal(err)
	}
	select {
	case <-d.entered:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not start")
	}
	current, _ := m.Get(r.ID)
	if current.State != Reclaiming {
		t.Fatalf("premature completed state: %s", current.State)
	}
	if _, err := m.Create(context.Background(), CreateRequest{}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("unreclaimed capacity was reused: %v", err)
	}
}

func TestDestroyAcceptedIsNotStopped(t *testing.T) {
	d := &gateDriver{entered: make(chan struct{}), release: make(chan struct{}), gateStop: true}
	m, _, _ := setup(t, Options{}, func(base Driver) Driver { d.Driver = base; return d })
	defer close(d.release)
	r := create(t, m, CreateRequest{})
	accepted, err := m.Destroy(r.Ref)
	if err != nil || accepted.State != Stopping {
		t.Fatalf("invalid acceptance: %+v, %v", accepted, err)
	}
	select {
	case <-d.entered:
	case <-time.After(time.Second):
		t.Fatal("stop did not start")
	}
	current, _ := m.Get(r.ID)
	if current.State != Stopping || !current.StoppedAt.IsZero() {
		t.Fatalf("stop was reported before driver confirmation: %+v", current)
	}
	if _, err := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo"}}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("destroy accepted new work: %v", err)
	}
}

type retryDriver struct {
	Driver
	failures atomic.Int32
}

func (d *retryDriver) Cleanup(ctx context.Context, ref Ref) error {
	if d.failures.Add(-1) >= 0 {
		return fmt.Errorf("injected transient cleanup failure")
	}
	return d.Driver.Cleanup(ctx, ref)
}

func TestCleanupRetriesAndTTL(t *testing.T) {
	d := &retryDriver{}
	d.failures.Store(2)
	m, _, _ := setup(t, Options{}, func(base Driver) Driver { d.Driver = base; return d })
	r := create(t, m, CreateRequest{})
	// Expire only after READY. A 30 ms creation TTL races fsync/scheduling on
	// shared CI and correctly fails creation instead of testing cleanup retries.
	i, err := m.lookup(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	i.mu.Lock()
	next := i.record
	next.ExpiresAt = time.Now().Add(-time.Nanosecond)
	err = m.saveLocked(i, next)
	i.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	m.notify()
	final := waitState(t, m, r.ID, Destroyed)
	if d.failures.Load() >= 0 || final.LastError != "" {
		t.Fatalf("cleanup was not retried successfully: %+v", final)
	}
}

type partialPrepareDriver struct{ Driver }

func (d partialPrepareDriver) Prepare(ctx context.Context, ref Ref, limits Limits) error {
	if err := d.Driver.Prepare(ctx, ref, limits); err != nil {
		return err
	}
	return fmt.Errorf("injected failure after allocating a workspace")
}

func TestPartialCreationIsReclaimed(t *testing.T) {
	m, base, _ := setup(t, Options{}, func(d Driver) Driver { return partialPrepareDriver{d} })
	r, err := m.Create(context.Background(), CreateRequest{})
	if err == nil || r.State == Ready {
		t.Fatalf("partial creation reported ready: %+v, %v", r, err)
	}
	waitState(t, m, r.ID, Destroyed)
	entries, _ := os.ReadDir(filepath.Join(base, "instances"))
	if len(entries) != 0 {
		t.Fatal("partial creation leaked resources")
	}
}

func TestRestartFencesPreviousGenerationAndReclaims(t *testing.T) {
	m, base, store := setup(t, Options{}, nil)
	r := create(t, m, CreateRequest{})
	execDone(t, m, r, "write", "state", "old state")
	// Simulate losing the controller without running its graceful Close path.
	m.cancel()
	<-m.workerDone
	driver, err := NewMockDriver(filepath.Join(base, "instances"))
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewManager(store, driver, Options{ReapInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := next.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	if _, err := next.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo"}}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("recovered generation was resurrected: %v", err)
	}
	waitState(t, next, r.ID, Destroyed)
	// Update the old in-memory instance so setup's cleanup does not use a dead worker.
	i, _ := m.lookup(r.ID)
	i.mu.Lock()
	i.record.State = Destroyed
	i.mu.Unlock()
	m.mu.Lock()
	delete(m.active, r.ID)
	m.mu.Unlock()
}

func TestConcurrentExecutionAndDestroy(t *testing.T) {
	m, _, _ := setup(t, Options{}, nil)
	r := create(t, m, CreateRequest{})
	var wg sync.WaitGroup
	for n := range 40 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo", fmt.Sprint(n)}})
			if err != nil && !errors.Is(err, ErrNotReady) {
				t.Errorf("exec: %v", err)
			}
		}(n)
	}
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Destroy(r.Ref); err != nil {
				t.Errorf("destroy: %v", err)
			}
		}()
	}
	wg.Wait()
	waitState(t, m, r.ID, Destroyed)
}

func TestInvalidRequests(t *testing.T) {
	m, _, _ := setup(t, Options{}, nil)
	for _, req := range []CreateRequest{{TTLMS: -1}, {Limits: Limits{MaxJobs: 257}}, {Limits: Limits{MaxExecMS: 60_001}}} {
		if _, err := m.Create(context.Background(), req); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid create accepted: %+v, %v", req, err)
		}
	}
	r := create(t, m, CreateRequest{})
	for _, req := range []ExecRequest{
		{Generation: r.Generation},
		{Generation: r.Generation, Argv: []string{"echo"}, TimeoutMS: 60_001},
		{Generation: r.Generation, Argv: []string{"echo", strings.Repeat("x", 32_769)}},
	} {
		if _, err := m.Exec(r.ID, req); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid exec accepted: %v", err)
		}
	}
}

func TestFileStoreRejectsCorruptionAndUnsafeIdentity(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(Record{Ref: Ref{ID: "../escape"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsafe identity accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(store.dir, "bad.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("corrupt ledger was silently ignored")
	}
}
