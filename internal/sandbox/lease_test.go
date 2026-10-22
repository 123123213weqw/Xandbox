package sandbox

import (
	"github.com/123123213weqw/Xandbox/internal/hostclock"
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
