package sandbox

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Only the bounded capability operation is implemented. An accidental storage,
// Stop or Cleanup call through the embedded nil interfaces fails the test.
type immediateRevokeDriver struct {
	Driver
	i     *instance
	calls atomic.Int64
	err   error
	bad   atomic.Bool
}

func (d *immediateRevokeDriver) RevokeLease(ref Ref) error {
	if ref != d.i.ref || d.i.intent.Load() != 2 || d.i.leaseEligible.Load() {
		d.bad.Store(true)
	}
	d.calls.Add(1)
	return d.err
}

func immediateRevokeManager() (*Manager, *instance, *immediateRevokeDriver) {
	i := newInstance(Record{Ref: Ref{ID: "owned", Generation: "generation"}, TenantID: "alpha", State: Ready})
	i.leaseEligible.Store(true)
	d := &immediateRevokeDriver{i: i}
	m := &Manager{
		records: map[string]*instance{i.ref.ID: i}, active: map[string]*instance{i.ref.ID: i},
		driver: d, wake: make(chan struct{}, 1),
	}
	// Deliberately no reaper: a direct revocation must not depend on its next
	// tick/wakeup, nor on a lifecycle worker or a generation/storage lock.
	return m, i, d
}

func TestManagedRevokeImmediatelySignalsLeaseWithoutLifecycleLocks(t *testing.T) {
	m, i, d := immediateRevokeManager()
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.opMu.tryAcquire() {
		t.Fatal("could not hold generation gate")
	}
	defer i.opMu.release()
	m.workMu.Lock()
	defer m.workMu.Unlock()
	done := make(chan error, 1)
	go func() { done <- m.RevokeScoped("alpha", i.ref) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("volatile revocation waited for lifecycle/storage locks")
	}
	if d.calls.Load() != 1 || d.bad.Load() {
		t.Fatal("lease was not signalled immediately after the immutable admission fence")
	}
	if i.record.State != Ready || i.record.DeleteRequested || len(m.active) != 1 {
		t.Fatal("capability revocation changed durable state or released capacity")
	}
	select {
	case <-i.stopped:
		t.Fatal("capability revocation falsely acknowledged physical Stop")
	default:
	}
	if len(m.wake) != 1 {
		t.Fatal("revocation did not retain independent reconciliation")
	}
}

func TestManagedImmediateRevokeValidatesAuthorityBeforeDriver(t *testing.T) {
	for _, tc := range []struct {
		name, tenant string
		ref          Ref
		want         error
	}{
		{"empty-tenant", "", Ref{"owned", "generation"}, ErrNotFound},
		{"foreign-tenant", "beta", Ref{"owned", "generation"}, ErrNotFound},
		{"unknown-id", "alpha", Ref{"unknown", "generation"}, ErrNotFound},
		{"stale-generation", "alpha", Ref{"owned", "stale"}, ErrStale},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, i, d := immediateRevokeManager()
			if err := m.RevokeScoped(tc.tenant, tc.ref); !errors.Is(err, tc.want) {
				t.Fatalf("wrong authority error: %v", err)
			}
			if d.calls.Load() != 0 || i.intent.Load() != 0 || !i.leaseEligible.Load() || len(m.wake) != 0 {
				t.Fatal("unauthorized or stale identity reached the live capability")
			}
		})
	}
}

func TestManagedImmediateRevokeFailureRetainsFenceAndReconciliation(t *testing.T) {
	m, i, d := immediateRevokeManager()
	d.err = errors.New("capability delivery failed")
	if err := m.RevokeScoped("alpha", i.ref); err != nil {
		t.Fatal("volatile admission fence must not become a durability/Stop reply", err)
	}
	if d.calls.Load() != 1 || !i.leaseFailed.Load() || i.intent.Load() != 2 || i.leaseEligible.Load() || len(m.wake) != 1 {
		t.Fatal("failed immediate signal lost the monotonic fence or reconciliation")
	}
	if i.record.State != Ready || i.record.DeleteRequested || len(m.active) != 1 {
		t.Fatal("failed immediate signal released ownership or capacity")
	}
}

func TestManagedImmediateRevokeConcurrentCallsRemainVolatile(t *testing.T) {
	m, i, d := immediateRevokeManager()
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if err := m.RevokeScoped("alpha", i.ref); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if d.calls.Load() != 32 || d.bad.Load() || i.intent.Load() != 2 || i.leaseEligible.Load() || len(m.wake) != 1 {
		t.Fatal("concurrent immediate revocation changed authority or lost the fence")
	}
	if i.record.State != Ready || len(m.active) != 1 {
		t.Fatal("volatile calls released durable ownership")
	}
}

type lateRevokeDriver struct {
	Driver
	published atomic.Bool
	revoked   chan Ref
}

func (d *lateRevokeDriver) RevokeLease(ref Ref) error {
	if d.published.Load() {
		select {
		case d.revoked <- ref:
		default:
		}
	}
	return nil
}

func TestManagedImmediateRevokeMissRetriedAfterLatePublication(t *testing.T) {
	m, i, _ := immediateRevokeManager()
	d := &lateRevokeDriver{revoked: make(chan Ref, 1)}
	m.driver = d
	if err := m.RevokeScoped("alpha", i.ref); err != nil {
		t.Fatal(err)
	}
	select {
	case <-d.revoked:
		t.Fatal("unpublished capability was invented")
	default:
	}
	// Publish after the direct attempt, then start the original reconciliation
	// loop. No lifecycle worker runs; no Stop/storage/capacity proof is possible.
	d.published.Store(true)
	i.publish()
	if i.leaseEligible.Load() {
		t.Fatal("late publication revived renewal eligibility")
	}
	m.opts.ReapInterval = time.Hour
	m.stopQueue = make(chan *instance, 1)
	m.cleanupQueue = make(chan *instance, 1)
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.workers.Add(1)
	go m.reaper()
	defer func() { m.cancel(); m.workers.Wait() }()
	select {
	case ref := <-d.revoked:
		if ref != i.ref {
			t.Fatal("reconciliation revoked another generation")
		}
	case <-time.After(time.Second):
		t.Fatal("direct miss suppressed independent reconciliation")
	}
	// Reaper may update in-memory lifecycle state, but no worker can release
	// durable ownership or acknowledge Stop on behalf of this signal.
	m.mu.Lock()
	active := len(m.active)
	m.mu.Unlock()
	if active != 1 {
		t.Fatal("retry released capacity without cleanup")
	}
	select {
	case <-i.stopped:
		t.Fatal("retry falsely acknowledged physical Stop")
	default:
	}
}
