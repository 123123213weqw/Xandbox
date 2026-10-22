package sandbox

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagedAdmissionCannotBeBypassedOrPreoccupiedByPlainCreate(t *testing.T) {
	m, _, _ := setup(t, Options{MaxInstances: 4}, nil)
	owner := Owner{TenantID: "alpha", MaxInstances: 4}
	var open atomic.Bool
	open.Store(true)
	permit := NewAdmission(func(Ref) bool { return open.Load() })
	var reserved atomic.Int32
	r, e := m.CreateManagedScoped(context.Background(), owner, "same-key", CreateRequest{}, permit, func(Ref) { reserved.Add(1) })
	if e != nil {
		t.Fatal(e)
	}
	plain, e := m.CreateScoped(context.Background(), owner, "same-key", CreateRequest{})
	if e != nil || plain.Ref == r.Ref {
		t.Fatal("public create collided with managed namespace", e)
	}
	if _, e = m.ExecScoped("alpha", r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo", "bypass"}}); !errors.Is(e, ErrNotReady) {
		t.Fatal(e)
	}
	if _, e = m.ExecManagedScoped("alpha", r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo", "wrong"}}, NewAdmission(func(Ref) bool { return true })); !errors.Is(e, ErrNotReady) {
		t.Fatal(e)
	}
	if _, e = m.ExecManagedScoped("alpha", r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo", "ok"}}, permit); e != nil {
		t.Fatal(e)
	}
	replay, e := m.CreateManagedScoped(context.Background(), owner, "same-key", CreateRequest{}, permit, func(Ref) { reserved.Add(1) })
	if e != nil || replay.Ref != r.Ref || reserved.Load() != 1 {
		t.Fatal("reservation/replay", e, reserved.Load())
	}
	open.Store(false)
	if _, e = m.ExecManagedScoped("alpha", r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo"}}, permit); !errors.Is(e, ErrNotReady) {
		t.Fatal("revoked route admitted work", e)
	}
	if e = m.RevokeScoped("beta", r.Ref); !errors.Is(e, ErrNotFound) {
		t.Fatal(e)
	}
	if e = m.RevokeScoped("alpha", r.Ref); e != nil {
		t.Fatal(e)
	}
	waitState(t, m, r.ID, Destroyed)
}

func TestManagedGuardRecheckedAfterWaitingForRecordIO(t *testing.T) {
	m, _, _ := setup(t, Options{}, nil)
	var open atomic.Bool
	open.Store(true)
	permit := NewAdmission(func(Ref) bool { return open.Load() })
	owner := Owner{TenantID: "alpha", MaxInstances: 2}
	r, e := m.CreateManagedScoped(context.Background(), owner, "wait", CreateRequest{}, permit, func(Ref) {})
	if e != nil {
		t.Fatal(e)
	}
	i, _ := m.lookup(r.ID)
	i.mu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := m.ExecManagedScoped("alpha", r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo"}}, permit)
		done <- err
	}()
	open.Store(false)
	i.mu.Unlock()
	if e := <-done; !errors.Is(e, ErrNotReady) {
		t.Fatal("late-resolved old route admitted execution", e)
	}
}

type initialWriteBarrier struct {
	Store
	entered chan Ref
	release chan struct{}
}

func (s *initialWriteBarrier) Save(r Record) error {
	if r.State == Creating {
		s.entered <- r.Ref
		<-s.release
	}
	return s.Store.Save(r)
}
func TestManagedReservationRevokesBeforeBlockedOwnershipFsync(t *testing.T) {
	dir := t.TempDir()
	fs, e := NewFileStore(filepath.Join(dir, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	s := &initialWriteBarrier{Store: fs, entered: make(chan Ref, 1), release: make(chan struct{})}
	driver, e := NewMockDriver(filepath.Join(dir, "instances"))
	if e != nil {
		t.Fatal(e)
	}
	m, e := NewManager(s, driver, Options{ReapInterval: time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if e := m.Close(ctx); e != nil {
			t.Error(e)
		}
	}()
	captured := make(chan Ref, 1)
	done := make(chan error, 1)
	go func() {
		_, err := m.CreateManagedScoped(context.Background(), Owner{TenantID: "alpha", MaxInstances: 2}, "blocked", CreateRequest{}, NewAdmission(func(Ref) bool { return true }), func(ref Ref) { captured <- ref })
		done <- err
	}()
	ref := <-captured
	stored := <-s.entered
	if ref != stored {
		t.Fatal("wrong ownership ref")
	}
	revoked := make(chan error, 1)
	go func() { revoked <- m.RevokeScoped("alpha", ref) }()
	select {
	case e := <-revoked:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("volatile revoke waited for ownership I/O")
	}
	close(s.release)
	if e := <-done; e == nil {
		t.Fatal("revoked reservation became ready")
	}
	waitState(t, m, ref.ID, Destroyed)
}
