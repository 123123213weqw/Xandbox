package session

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func drainFixture(t *testing.T) (*Broker, *sandbox.Manager, *sandbox.AdmissionGate, *stageBarrier) {
	t.Helper()
	root := t.TempDir()
	ledger, e := sandbox.NewFileStore(filepath.Join(root, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	mock, e := sandbox.NewMockDriver(filepath.Join(root, "instances"))
	if e != nil {
		t.Fatal(e)
	}
	g := sandbox.NewAdmissionGate(true)
	core, e := sandbox.NewManager(ledger, mock, sandbox.Options{AdmissionGate: g, MaxInstances: 4, ReapInterval: time.Millisecond, RetryDelay: time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	fs, e := NewFileStore(filepath.Join(root, "sessions"))
	if e != nil {
		t.Fatal(e)
	}
	barrier := &stageBarrier{Store: fs, stage: Creating, revision: 0, entered: make(chan Record, 1), release: make(chan struct{})}
	b, e := New(core, barrier, Options{MaxSessions: 8, RetryInterval: time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if e := b.Close(ctx); e != nil {
			t.Error(e)
		}
		if e := core.Close(ctx); e != nil {
			t.Error(e)
		}
	})
	return b, core, g, barrier
}
func TestDrainPreservesAcceptedSessionOpenWithoutNewSessionOrSwitchHistory(t *testing.T) {
	b, core, g, barrier := drainFixture(t)
	barrier.armed.Store(true)
	type reply struct {
		r Result
		e error
	}
	done := make(chan reply, 1)
	go func() {
		r, e := b.Open(context.Background(), alpha, "accepted", sandbox.CreateRequest{})
		done <- reply{r, e}
	}()
	<-barrier.entered
	if g.Pending() != 1 || core.Metrics().Allocated != 0 {
		t.Fatal("pre-Core session reservation not counted")
	}
	g.SetOpen(false)
	if _, e := b.Open(context.Background(), alpha, "not-reserved", sandbox.CreateRequest{}); !errors.Is(e, sandbox.ErrDraining) {
		t.Fatal(e)
	}
	if rows, _ := b.Metrics(); rows != 1 {
		t.Fatal("drained session consumed metadata")
	}
	close(barrier.release)
	opened := <-done
	if opened.e != nil || g.Pending() != 0 || core.Metrics().Allocated != 1 {
		t.Fatal("accepted session lost its one Core ticket", opened.e)
	}
	first := opened.r
	if replay, e := b.Open(context.Background(), alpha, "accepted", sandbox.CreateRequest{}); e != nil || replay.Current != first.Current {
		t.Fatal("accepted replay blocked", e)
	}
	if _, e := b.Exec(alpha.TenantID, first.ID, first.Revision, sandbox.ExecRequest{Argv: []string{"echo", "alive"}}); e != nil {
		t.Fatal("existing session execution blocked", e)
	}
	if _, e := b.Switch(context.Background(), alpha, first.ID, "fresh-switch", SwitchRequest{ExpectedRevision: first.Revision}); !errors.Is(e, sandbox.ErrDraining) {
		t.Fatal(e)
	}
	r, active, e := b.Get(alpha.TenantID, first.ID)
	if e != nil || !active || len(r.Attempts) != 1 || r.Current != first.Current {
		t.Fatal("rejected switch changed route/history", r, e)
	}
	g.SetOpen(true)
	if _, e = b.Switch(context.Background(), alpha, first.ID, "fresh-switch", SwitchRequest{ExpectedRevision: first.Revision}); e != nil {
		t.Fatal("rejected key was incorrectly consumed", e)
	}
}
func TestDrainPreservesAlreadyAcceptedSwitchAndOldExecution(t *testing.T) {
	b, _, g, barrier := drainFixture(t)
	first := open(t, b, "initial")
	barrier.stage, barrier.revision = Preparing, first.Revision
	barrier.armed.Store(true)
	type reply struct {
		r Result
		e error
	}
	done := make(chan reply, 1)
	go func() {
		r, e := b.Switch(context.Background(), alpha, first.ID, "accepted-switch", SwitchRequest{ExpectedRevision: first.Revision})
		done <- reply{r, e}
	}()
	<-barrier.entered
	g.SetOpen(false)
	if g.Pending() != 1 {
		t.Fatal("accepted switch had no pending ticket")
	}
	if _, e := b.Exec(alpha.TenantID, first.ID, first.Revision, sandbox.ExecRequest{Argv: []string{"echo", "old-alive"}}); e != nil {
		t.Fatal("drain revoked old route", e)
	}
	close(barrier.release)
	next := <-done
	if next.e != nil || next.r.Revision != 2 || g.Pending() != 0 {
		t.Fatal("accepted switch failed after drain", next.e)
	}
	if replay, e := b.Switch(context.Background(), alpha, first.ID, "accepted-switch", SwitchRequest{ExpectedRevision: first.Revision}); e != nil || replay.Current != next.r.Current {
		t.Fatal("accepted switch replay blocked", e)
	}
	if _, e := b.Switch(context.Background(), alpha, first.ID, "later", SwitchRequest{ExpectedRevision: next.r.Revision}); !errors.Is(e, sandbox.ErrDraining) {
		t.Fatal(e)
	}
	if _, e := b.Exec(alpha.TenantID, first.ID, next.r.Revision, sandbox.ExecRequest{Argv: []string{"echo", "new-alive"}}); e != nil {
		t.Fatal(e)
	}
}
