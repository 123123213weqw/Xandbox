package sandbox

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type cleanupBarrier struct {
	Driver
	mu        sync.Mutex
	blockedID string
	entered   chan struct{}
	release   chan struct{}
	once      sync.Once
	active    atomic.Int32
	maximum   atomic.Int32
}

func (d *cleanupBarrier) Cleanup(ctx context.Context, ref Ref) error {
	n := d.active.Add(1)
	defer d.active.Add(-1)
	for old := d.maximum.Load(); n > old && !d.maximum.CompareAndSwap(old, n); old = d.maximum.Load() {
	}
	d.mu.Lock()
	blocked := ref.ID == d.blockedID
	d.mu.Unlock()
	if blocked {
		d.once.Do(func() { close(d.entered) })
		<-d.release
	} // Model uninterruptible filesystem I/O.
	return d.Driver.Cleanup(ctx, ref)
}
func (d *cleanupBarrier) block(id string) { d.mu.Lock(); d.blockedID = id; d.mu.Unlock() }
func waitSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("barrier not reached")
	}
}
func expireReady(t *testing.T, m *Manager, r Record) {
	t.Helper()
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
}

func TestStopPoolProgressesWhenCleanupQueueIsSaturated(t *testing.T) {
	var d *cleanupBarrier
	m, _, _ := setup(t, Options{MaxInstances: 5, StopWorkers: 1, CleanupWorkers: 1, WorkQueueSize: 1}, func(base Driver) Driver {
		d = &cleanupBarrier{Driver: base, entered: make(chan struct{}), release: make(chan struct{})}
		return d
	})
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(d.release) }) })
	a := create(t, m, CreateRequest{})
	b := create(t, m, CreateRequest{})
	c := create(t, m, CreateRequest{})
	ttl := create(t, m, CreateRequest{Limits: Limits{MaxExecMS: 60000}})
	explicit := create(t, m, CreateRequest{})
	d.block(a.ID)
	if _, err := m.Destroy(a.Ref); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, d.entered)
	for _, r := range []Record{b, c} {
		if _, err := m.Destroy(r.Ref); err != nil {
			t.Fatal(err)
		}
	}
	waitState(t, m, b.ID, Stopped)
	waitState(t, m, c.ID, Stopped)
	job, err := m.Exec(ttl.ID, ExecRequest{Generation: ttl.Generation, Argv: []string{"sleep", "50s"}})
	if err != nil {
		t.Fatal(err)
	}
	expireReady(t, m, ttl)
	waitState(t, m, ttl.ID, Stopped)
	j, err := m.GetJob(ttl.ID, job.ID)
	if err != nil || j.Status != "CANCELLED" {
		t.Fatalf("TTL didn't drain task: %+v %v", j, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if r, err := m.Stop(ctx, explicit.Ref); err != nil || r.State != Stopped || r.DeleteRequested {
		t.Fatalf("explicit stop blocked/changed: %+v %v", r, err)
	}
	if r, err := m.Stop(ctx, a.Ref); err != nil || !stoppedState(r.State) {
		t.Fatalf("confirmed stop waited behind its own GC: %+v %v", r, err)
	}
	stats := m.Stats()
	if stats.Active != 5 || stats.CleanupRunning != 1 || stats.CleanupQueued != 1 || stats.StopRunning > 1 || stats.StopQueued > 1 {
		t.Fatalf("bad bounded/backpressure state: %+v", stats)
	}
	if _, err := m.Create(context.Background(), CreateRequest{}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity returned before reclamation: %v", err)
	}
	release.Do(func() { close(d.release) })
	for _, r := range []Record{a, b, c, ttl} {
		waitState(t, m, r.ID, Destroyed)
	}
	if d.maximum.Load() != 1 {
		t.Fatalf("cleanup concurrency unbounded: %d", d.maximum.Load())
	}
}

func TestReconcilerAndStatsSkipUnrelatedLockedRecord(t *testing.T) {
	m, _, _ := setup(t, Options{MaxInstances: 2, StopWorkers: 1, CleanupWorkers: 1, WorkQueueSize: 1}, nil)
	a := create(t, m, CreateRequest{})
	b := create(t, m, CreateRequest{})
	i, _ := m.lookup(a.ID)
	i.mu.Lock()
	var once sync.Once
	defer once.Do(func() { i.mu.Unlock() })
	// Simulate a record fsync stalled with that generation's mutex held.
	if _, err := m.Destroy(b.Ref); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, b.ID, Destroyed)
	returned := make(chan Stats, 1)
	go func() { returned <- m.Stats() }()
	select {
	case s := <-returned:
		if s.Active != 1 {
			t.Fatalf("bad stats: %+v", s)
		}
	case <-time.After(time.Second):
		t.Fatal("stats waited on unrelated record I/O")
	}
	once.Do(func() { i.mu.Unlock() })
}

func TestCloseDeadlineDoesNotReleaseBlockedCleanupCapacity(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(filepath.Join(dir, "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	base, err := NewMockDriver(filepath.Join(dir, "instances"))
	if err != nil {
		t.Fatal(err)
	}
	d := &cleanupBarrier{Driver: base, entered: make(chan struct{}), release: make(chan struct{})}
	m, err := NewManager(store, d, Options{MaxInstances: 2, StopWorkers: 1, CleanupWorkers: 1, WorkQueueSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	var released sync.Once
	defer released.Do(func() { close(d.release) })
	defer m.cancel()
	a := create(t, m, CreateRequest{})
	b := create(t, m, CreateRequest{})
	d.block(a.ID)
	if _, err := m.Destroy(a.Ref); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, d.entered)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := m.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close falsely succeeded: %v", err)
	}
	if m.Stats().Active != 2 {
		t.Fatal("unreclaimed capacity was dropped")
	}
	select {
	case <-m.workerDone:
		t.Fatal("reported workers terminated during blocked I/O")
	default:
	}
	released.Do(func() { close(d.release) })
	waitSignal(t, m.workerDone)
	next, err := NewManager(store, base, Options{MaxInstances: 2, StopWorkers: 1, CleanupWorkers: 1, WorkQueueSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer next.cancel()
	for _, r := range []Record{a, b} {
		waitState(t, next, r.ID, Destroyed)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := next.Close(ctx2); err != nil {
		t.Fatal(err)
	}
}

type prepareBarrier struct {
	Driver
	entered chan Ref
	release chan struct{}
}

func (d *prepareBarrier) Prepare(ctx context.Context, ref Ref, l Limits) error {
	if err := d.Driver.Prepare(ctx, ref, l); err != nil {
		return err
	}
	d.entered <- ref
	<-d.release // Deliberately does not honor cancellation until operator unblocks it.
	return ctx.Err()
}
func TestStopCancelsPreparationAndContextBoundsGateWait(t *testing.T) {
	var d *prepareBarrier
	m, _, _ := setup(t, Options{MaxInstances: 1, StopWorkers: 1, CleanupWorkers: 1, WorkQueueSize: 1}, func(base Driver) Driver {
		d = &prepareBarrier{Driver: base, entered: make(chan Ref, 1), release: make(chan struct{})}
		return d
	})
	var released sync.Once
	t.Cleanup(func() { released.Do(func() { close(d.release) }) })
	result := make(chan error, 1)
	go func() { _, err := m.Create(context.Background(), CreateRequest{}); result <- err }()
	var ref Ref
	select {
	case ref = <-d.entered:
	case <-time.After(time.Second):
		t.Fatal("prepare didn't start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := m.Stop(ctx, ref); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("gate wait ignored deadline: %v", err)
	}
	if r, _ := m.Get(ref.ID); r.State != Stopping || r.DeleteRequested {
		t.Fatalf("stop intent lost: %+v", r)
	}
	released.Do(func() { close(d.release) })
	if err := <-result; err == nil {
		t.Fatal("cancelled preparation became ready")
	}
	r := waitState(t, m, ref.ID, Stopped)
	if r.DeleteRequested {
		t.Fatal("explicit stop silently became deletion")
	}
}

func TestLifecycleWorkerBounds(t *testing.T) {
	_, _, s := setup(t, Options{}, nil)
	d, _ := NewMockDriver(filepath.Join(t.TempDir(), "mock"))
	for _, o := range []Options{{StopWorkers: -1}, {StopWorkers: 65}, {CleanupWorkers: 65}, {WorkQueueSize: 10001}} {
		if m, err := NewManager(s, d, o); err == nil {
			m.cancel()
			<-m.workerDone
			t.Fatal("unbounded worker option accepted")
		}
	}
}
