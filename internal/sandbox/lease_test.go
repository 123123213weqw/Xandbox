package sandbox

import (
	"context"
	"errors"
	"github.com/123123213weqw/Xandbox/internal/hostclock"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type leaseProbe struct {
	Driver
	renewals atomic.Int64
	failure  atomic.Bool
}

func (d *leaseProbe) RefreshLease(ref Ref) error {
	d.renewals.Add(1)
	if d.failure.Load() {
		return ErrBackendFenced
	}
	return nil
}
func TestReconcileRenewsWithoutWaitingForRecordIOAndFencesFailure(t *testing.T) {
	var d *leaseProbe
	m, _, _ := setup(t, Options{ReapInterval: time.Millisecond}, func(base Driver) Driver { d = &leaseProbe{Driver: base}; return d })
	r := create(t, m, CreateRequest{})
	i, _ := m.lookup(r.ID)
	i.mu.Lock()
	before := d.renewals.Load()
	m.notify()
	deadline := time.Now().Add(time.Second)
	for d.renewals.Load() == before && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	renewed := d.renewals.Load() > before
	i.mu.Unlock()
	if !renewed {
		t.Fatal("record I/O suppressed controller lease refresh")
	}
	d.failure.Store(true)
	m.notify()
	waitState(t, m, r.ID, Destroyed)
}
func TestWallClockProjectionCannotExtendOrExpireHostDeadline(t *testing.T) {
	m, _, _ := setup(t, Options{}, nil)
	r := create(t, m, CreateRequest{})
	i, _ := m.lookup(r.ID)
	i.mu.Lock()
	next := i.record
	next.ExpiresAt = time.Unix(1, 0)
	err := m.saveLocked(i, next)
	i.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo", "host-clock"}}); err != nil {
		t.Fatal("wall-clock projection controlled runtime expiry: ", err)
	}
	i.mu.Lock()
	next = i.record
	next.ExpiresAt = time.Now().Add(365 * 24 * time.Hour)
	nowNS, clockErr := hostclock.NowNS()
	if clockErr != nil {
		i.mu.Unlock()
		t.Fatal(clockErr)
	}
	i.expiresNS = nowNS - 1
	err = m.saveLocked(i, next)
	i.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	m.notify()
	waitState(t, m, r.ID, Destroyed)
}

type readyPersistenceBarrier struct {
	Store
	entered chan Ref
	release chan struct{}
}

func (s *readyPersistenceBarrier) Save(r Record) error {
	if r.State == Ready {
		s.entered <- r.Ref
		<-s.release
	}
	return s.Store.Save(r)
}
func TestStopDuringReadyFsyncCannotPublishUsableCreation(t *testing.T) {
	dir := t.TempDir()
	base, err := NewFileStore(filepath.Join(dir, "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	store := &readyPersistenceBarrier{Store: base, entered: make(chan Ref, 1), release: make(chan struct{})}
	driver, err := NewMockDriver(filepath.Join(dir, "instances"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(store, driver, Options{ReapInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	var released sync.Once
	defer func() {
		released.Do(func() { close(store.release) })
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	created := make(chan error, 1)
	go func() { _, err := m.Create(context.Background(), CreateRequest{}); created <- err }()
	var ref Ref
	select {
	case ref = <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("readiness fsync not reached")
	}
	stopped := make(chan error, 1)
	go func() { _, err := m.Stop(context.Background(), ref); stopped <- err }()
	i, _ := m.lookup(ref.ID)
	deadline := time.Now().Add(time.Second)
	for i.intent.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if i.intent.Load() != 1 || i.leaseEligible.Load() {
		t.Fatal("blocked record mutex prevented atomic renewal revocation")
	}
	released.Do(func() { close(store.release) })
	if err := <-created; err == nil {
		t.Fatal("revoked READY persistence returned successful creation")
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	r, err := m.Get(ref.ID)
	if err != nil || r.State != Stopped || r.DeleteRequested {
		t.Fatalf("explicit Stop intent lost: %+v %v", r, err)
	}
	if _, err := m.Exec(ref.ID, ExecRequest{Generation: ref.Generation, Argv: []string{"echo"}}); !errors.Is(err, ErrNotReady) {
		t.Fatal("revoked generation admitted execution")
	}
}
