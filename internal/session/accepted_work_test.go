package session

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func TestAcceptedWorkSessionTicketStaysPendingThroughFinalJournalAndPublication(t *testing.T) {
	for _, kind := range []string{"open-before-core", "open-final-journal", "switch-before-core", "switch-final-journal"} {
		t.Run(kind, func(t *testing.T) {
			b, core, g, barrier := drainFixture(t)
			var first Result
			isSwitch := kind == "switch-before-core" || kind == "switch-final-journal"
			if isSwitch {
				first = open(t, b, "initial")
			}
			barrier.stage, barrier.revision = Creating, 0
			if isSwitch {
				barrier.stage, barrier.revision = Preparing, 1
			}
			if kind == "open-final-journal" {
				barrier.stage, barrier.revision = Active, 1
			}
			if kind == "switch-final-journal" {
				barrier.stage, barrier.revision = Active, 2
			}
			var once sync.Once
			release := func() { once.Do(func() { close(barrier.release) }) }
			defer release()
			barrier.armed.Store(true)
			type result struct {
				r Result
				e error
			}
			done := make(chan result, 1)
			go func() {
				var r Result
				var e error
				if isSwitch {
					r, e = b.Switch(context.Background(), alpha, first.ID, "accepted", SwitchRequest{ExpectedRevision: first.Revision})
				} else {
					r, e = b.Open(context.Background(), alpha, "accepted", sandbox.CreateRequest{})
				}
				done <- result{r, e}
			}()
			<-barrier.entered
			if s := g.FreezeAcceptedWork(); s.Pending != 1 || s.Complete() {
				t.Fatal("journal not in accepted cohort", s)
			}
			if _, e := b.Open(context.Background(), alpha, "new", sandbox.CreateRequest{}); !errors.Is(e, sandbox.ErrDraining) {
				t.Fatal(e)
			}
			if isSwitch {
				if _, e := b.Exec(alpha.TenantID, first.ID, first.Revision, sandbox.ExecRequest{Argv: []string{"echo", "late"}}); e == nil {
					t.Fatal("old route accepted new execution")
				}
			}
			release()
			got := <-done
			if got.e != nil {
				t.Fatal("accepted mutation cancelled by freeze", got.e)
			}
			if s := g.AcceptedWorkStatus(); !s.Complete() {
				t.Fatal("terminal mutation not settled", s)
			}
			r, active, e := b.Get(alpha.TenantID, got.r.ID)
			if e != nil || !active || r.Current != got.r.Current {
				t.Fatal(r, active, e)
			}
			if _, e = b.Exec(alpha.TenantID, got.r.ID, got.r.Revision, sandbox.ExecRequest{Argv: []string{"echo", "late"}}); !errors.Is(e, sandbox.ErrDraining) {
				t.Fatal("published route bypassed freeze", e)
			}
			if core.Metrics().Allocated < 1 {
				t.Fatal("work completion falsely implies resource reclaim")
			}
		})
	}
}

func TestAcceptedWorkFailedAcceptedSessionNeverBecomesSuccessfulIdle(t *testing.T) {
	b, _, g, barrier := drainFixture(t)
	var once sync.Once
	release := func() { once.Do(func() { close(barrier.release) }) }
	defer release()
	barrier.armed.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := b.Open(ctx, alpha, "accepted", sandbox.CreateRequest{}); done <- e }()
	<-barrier.entered
	g.FreezeAcceptedWork()
	cancel()
	release()
	if e := <-done; e == nil {
		t.Fatal("cancelled mutation succeeded")
	}
	if s := g.AcceptedWorkStatus(); s.Pending != 0 || s.Failed != 1 || s.Complete() {
		t.Fatal("idle erased failed result", s)
	}
}
