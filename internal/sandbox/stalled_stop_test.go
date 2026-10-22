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

type stalledStopStore struct {
	Store
	hold    atomic.Bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *stalledStopStore) Save(r Record) error {
	if r.State == Stopping && s.hold.Load() {
		s.once.Do(func() { close(s.entered) })
		<-s.release
	}
	return s.Store.Save(r)
}

type revokedLeaseDriver struct {
	Driver
	revoked chan Ref
	cleaned atomic.Int64
}

func (d *revokedLeaseDriver) RevokeLease(r Ref) error {
	select {
	case d.revoked <- r:
	default:
	}
	return nil
}
func (d *revokedLeaseDriver) Cleanup(ctx context.Context, r Ref) error {
	d.cleaned.Add(1)
	return d.Driver.Cleanup(ctx, r)
}

func TestStalledStopSaveCannotSuppressIndependentLeaseRevocation(t *testing.T) {
	base := t.TempDir()
	files, e := NewFileStore(filepath.Join(base, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	mock, e := NewMockDriver(filepath.Join(base, "runtime"))
	if e != nil {
		t.Fatal(e)
	}
	s := &stalledStopStore{Store: files, entered: make(chan struct{}), release: make(chan struct{})}
	d := &revokedLeaseDriver{Driver: mock, revoked: make(chan Ref, 16)}
	m, e := NewManager(s, d, Options{MaxInstances: 1, ReapInterval: time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, done := context.WithTimeout(context.Background(), time.Second)
		defer done()
		if e := m.Close(ctx); e != nil {
			t.Error(e)
		}
	})
	r := create(t, m, CreateRequest{})
	s.hold.Store(true)
	var release sync.Once
	unblock := func() { release.Do(func() { s.hold.Store(false); close(s.release) }) }
	defer unblock()
	accepted := make(chan error, 1)
	go func() { _, e := m.Destroy(r.Ref); accepted <- e }()
	select {
	case <-s.entered:
	case <-time.After(time.Second):
		t.Fatal("stop fence Save not held")
	}
	select {
	case ref := <-d.revoked:
		if ref != r.Ref {
			t.Fatal("wrong revocation authority")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("held Save suppressed independent lease revocation")
	}
	select {
	case <-accepted:
		t.Fatal("held Save falsely acknowledged Destroy")
	default:
	}
	i, _ := m.lookup(r.ID)
	select {
	case <-i.stopped:
		t.Fatal("lease revocation falsely acknowledged durable STOPPED")
	default:
	}
	if d.cleaned.Load() != 0 || m.Stats().Active != 1 {
		t.Fatal("held durability released resources or capacity")
	}
	unblock()
	select {
	case e := <-accepted:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("Destroy did not resume")
	}
	waitState(t, m, r.ID, Destroyed)
}

func TestRevokedExecAndStaleGenerationNeverWaitForRecordIO(t *testing.T) {
	m, _, _ := setup(t, Options{}, nil)
	r := create(t, m, CreateRequest{})
	i, _ := m.lookup(r.ID)
	i.mu.Lock()
	i.requestIntent(true)
	var unlocked sync.Once
	defer unlocked.Do(i.mu.Unlock)
	for _, test := range []struct {
		generation string
		want       error
	}{{r.Generation, ErrNotReady}, {"stale", ErrStale}} {
		result := make(chan error, 1)
		go func(g string) { _, e := m.Exec(r.ID, ExecRequest{Generation: g, Argv: []string{"true"}}); result <- e }(test.generation)
		select {
		case e := <-result:
			if !errors.Is(e, test.want) {
				t.Fatalf("wrong admission error: %v", e)
			}
		case <-time.After(250 * time.Millisecond):
			t.Fatal("revoked execution queued behind held record I/O")
		}
	}
}
