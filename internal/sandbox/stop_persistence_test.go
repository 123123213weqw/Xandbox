package sandbox

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

var errStopFenceStore = errors.New("injected stop-fence durability failure")
var errEmergencyDriverStop = errors.New("injected physical stop failure")

type stopFenceFailureStore struct {
	Store
	fail          atomic.Bool
	afterReplace  bool
	cancelCaller  context.CancelFunc
	stoppedWrites atomic.Int64
	stoppingSaves atomic.Int64
}

func (s *stopFenceFailureStore) Save(r Record) error {
	if r.State == Stopped {
		s.stoppedWrites.Add(1)
	}
	if r.State == Stopping && s.fail.Load() {
		if s.cancelCaller != nil {
			s.cancelCaller()
		}
		if s.afterReplace {
			if err := s.Store.Save(r); err != nil {
				return err
			}
		}
		return errStopFenceStore
	}
	err := s.Store.Save(r)
	if err == nil && r.State == Stopping {
		s.stoppingSaves.Add(1)
	}
	return err
}

type stopObservation struct {
	ref         Ref
	contextErr  error
	hasDeadline bool
	remaining   time.Duration
}

type stopFenceDriver struct {
	Driver
	observations chan stopObservation
	failStop     atomic.Bool
	waitDeadline atomic.Bool
	cleanups     atomic.Int64
	execStarted  chan struct{}
	execRelease  chan struct{}
}

func (d *stopFenceDriver) Exec(ctx context.Context, ref Ref, req ExecRequest, limit int) (Output, error) {
	if d.execRelease != nil {
		close(d.execStarted)
		<-d.execRelease // A controlled in-process call, never a host tenant command.
		return Output{}, nil
	}
	return d.Driver.Exec(ctx, ref, req, limit)
}

func (d *stopFenceDriver) Stop(ctx context.Context, ref Ref) error {
	deadline, ok := ctx.Deadline()
	select {
	case d.observations <- stopObservation{ref, ctx.Err(), ok, time.Until(deadline)}:
	default:
	}
	if d.failStop.Load() {
		return errEmergencyDriverStop
	}
	if d.waitDeadline.Load() {
		<-ctx.Done()
		return ctx.Err()
	}
	return d.Driver.Stop(ctx, ref)
}

func (d *stopFenceDriver) Cleanup(ctx context.Context, ref Ref) error {
	d.cleanups.Add(1)
	return d.Driver.Cleanup(ctx, ref)
}

func stopFenceFixture(t *testing.T, after bool, cancel context.CancelFunc, timeout time.Duration) (*Manager, *stopFenceFailureStore, *stopFenceDriver) {
	t.Helper()
	base := t.TempDir()
	files, err := NewFileStore(filepath.Join(base, "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	mock, err := NewMockDriver(filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	store := &stopFenceFailureStore{Store: files, afterReplace: after, cancelCaller: cancel}
	driver := &stopFenceDriver{Driver: mock, observations: make(chan stopObservation, 32)}
	m, err := NewManager(store, driver, Options{MaxInstances: 1, StopTimeout: timeout,
		ReapInterval: time.Millisecond, RetryDelay: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		store.fail.Store(false)
		driver.failStop.Store(false)
		driver.waitDeadline.Store(false)
		ctx, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		if err := m.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return m, store, driver
}

func assertUnacknowledgedStop(t *testing.T, m *Manager, store *stopFenceFailureStore, driver *stopFenceDriver, r Record) {
	t.Helper()
	current, err := m.Get(r.ID)
	if err != nil || current.State != Stopping || !current.StoppedAt.IsZero() || !current.DestroyedAt.IsZero() {
		t.Fatalf("physical stop became a false durable acknowledgement: %+v %v", current, err)
	}
	if store.stoppedWrites.Load() != 0 || driver.cleanups.Load() != 0 || m.Stats().Active != 1 {
		t.Fatal("unconfirmed fence allowed STOPPED, Cleanup or capacity release")
	}
	i, _ := m.lookup(r.ID)
	select {
	case <-i.stopped:
		t.Fatal("unconfirmed stop published immutable stop acknowledgement")
	default:
	}
	if _, err := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo"}}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("volatile execution fence reopened: %v", err)
	}
	if _, err := m.Create(context.Background(), CreateRequest{}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("unconfirmed reclamation released capacity: %v", err)
	}
}

func TestStopFenceFailureStillRequestsPhysicalStopWithoutAck(t *testing.T) {
	for _, after := range []bool{false, true} {
		name := "before-replace"
		if after {
			name = "uncertain-after-replace"
		}
		t.Run(name, func(t *testing.T) {
			m, store, driver := stopFenceFixture(t, after, nil, time.Second)
			r := create(t, m, CreateRequest{})
			store.fail.Store(true)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			stopped, err := m.Stop(ctx, r.Ref)
			if !errors.Is(err, errStopFenceStore) || stopped.State != Stopping {
				t.Fatalf("failed persistence became successful Stop: %+v %v", stopped, err)
			}
			select {
			case observed := <-driver.observations:
				if observed.ref != r.Ref || observed.contextErr != nil || !observed.hasDeadline {
					t.Fatalf("physical stop lacked bounded generation authority: %+v", observed)
				}
			default:
				t.Fatal("persistence error prevented physical Stop")
			}
			assertUnacknowledgedStop(t, m, store, driver, r)
			rows, err := store.Load()
			want := Ready
			if after {
				want = Stopping
			}
			if err != nil || len(rows) != 1 || rows[0].State != want {
				t.Fatalf("test did not cover expected durability ambiguity: %+v %v", rows, err)
			}
		})
	}
}

func TestStopFenceFailurePreservesDriverErrorAndDetachesCancelledCaller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, store, driver := stopFenceFixture(t, false, cancel, time.Second)
	r := create(t, m, CreateRequest{})
	i, _ := m.lookup(r.ID)
	// Exercise the inner operation after acquiring the generation gate. A
	// caller cancelled BEFORE gate acquisition remains a separate contract.
	if _, err := i.opMu.acquire(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	defer i.opMu.release()
	store.fail.Store(true)
	driver.failStop.Store(true)
	err := m.stopLocked(ctx, i)
	if !errors.Is(err, errStopFenceStore) || !errors.Is(err, errEmergencyDriverStop) || ctx.Err() == nil {
		t.Fatalf("stop lost original or secondary failure: %v", err)
	}
	select {
	case observed := <-driver.observations:
		if observed.ref != r.Ref || observed.contextErr != nil || !observed.hasDeadline || observed.remaining > m.opts.StopTimeout {
			t.Fatalf("best-effort stop inherited cancelled caller or lacked bounded context: %+v", observed)
		}
	default:
		t.Fatal("physical stop not attempted after cancelled fence failure")
	}
	assertUnacknowledgedStop(t, m, store, driver, r)
}

func TestStopFenceFailurePhysicalAttemptHonorsStopTimeout(t *testing.T) {
	m, store, driver := stopFenceFixture(t, false, nil, 20*time.Millisecond)
	r := create(t, m, CreateRequest{})
	i, _ := m.lookup(r.ID)
	if _, err := i.opMu.acquire(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	defer i.opMu.release()
	store.fail.Store(true)
	driver.waitDeadline.Store(true)
	err := m.stopLocked(context.Background(), i)
	if !errors.Is(err, errStopFenceStore) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("physical attempt ignored its timeout or lost store failure: %v", err)
	}
	assertUnacknowledgedStop(t, m, store, driver, r)
}

func TestStopFenceFailureDoesNotAcknowledgeUndrainedCall(t *testing.T) {
	m, store, driver := stopFenceFixture(t, false, nil, time.Second)
	r := create(t, m, CreateRequest{})
	driver.execStarted, driver.execRelease = make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-driver.execRelease:
		default:
			close(driver.execRelease)
		}
	}()
	if _, err := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo"}}); err != nil {
		t.Fatal(err)
	}
	<-driver.execStarted
	store.fail.Store(true)
	if _, err := m.Stop(context.Background(), r.Ref); !errors.Is(err, errStopFenceStore) {
		t.Fatal(err)
	}
	assertUnacknowledgedStop(t, m, store, driver, r)
	store.fail.Store(false)
	m.notify()
	eventually(t, func() bool { return store.stoppingSaves.Load() > 0 })
	// Even after storage recovers, physical Stop returning nil cannot replace
	// the separate requirement that all admitted calls have actually exited.
	assertUnacknowledgedStop(t, m, store, driver, r)
	close(driver.execRelease)
	waitState(t, m, r.ID, Stopped)
	if m.Stats().Active != 1 {
		t.Fatal("STOPPED released capacity before durable destruction")
	}
}
