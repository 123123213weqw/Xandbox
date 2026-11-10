package sandbox

import (
	"context"
	"errors"
	"sync"
	"testing"
)

type acceptedWorkDriver struct {
	Driver
	prepareEnter, prepareRelease chan struct{}
	execEnter, execRelease       chan struct{}
	execErr                      error
	exitCode                     int
}

func (d *acceptedWorkDriver) Prepare(ctx context.Context, ref Ref, p Preparation) error {
	if d.prepareEnter != nil {
		close(d.prepareEnter)
		<-d.prepareRelease
	}
	return d.Driver.Prepare(ctx, ref, p)
}
func (d *acceptedWorkDriver) Exec(context.Context, Ref, ExecRequest, int) (Output, error) {
	close(d.execEnter)
	<-d.execRelease // Deliberately ignores cancellation: termination is NOT completion.
	return Output{ExitCode: d.exitCode}, d.execErr
}

func TestAcceptedWorkFreezeWaitsActualExecReturnAndRejectsNewAdmission(t *testing.T) {
	g := NewAdmissionGate(true)
	d := &acceptedWorkDriver{execEnter: make(chan struct{}), execRelease: make(chan struct{})}
	m, _, _ := setup(t, Options{AdmissionGate: g}, func(inner Driver) Driver { d.Driver = inner; return d })
	var once sync.Once
	release := func() { once.Do(func() { close(d.execRelease) }) }
	t.Cleanup(release)
	r := create(t, m, CreateRequest{})
	j, e := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"blocked"}})
	if e != nil {
		t.Fatal(e)
	}
	<-d.execEnter
	if s := g.FreezeAcceptedWork(); s.Pending != 1 || s.Complete() {
		t.Fatal(s)
	}
	g.SetOpen(true)
	if g.Open() {
		t.Fatal("finish-only fence reopened")
	}
	if _, e = m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"late"}}); !errors.Is(e, ErrDraining) {
		t.Fatal(e)
	}
	if _, e = m.Create(context.Background(), CreateRequest{}); !errors.Is(e, ErrDraining) {
		t.Fatal(e)
	}
	if e = m.ReserveSessionAttempt(func(*CreationTicket) { t.Fatal("late session admitted") }); !errors.Is(e, ErrDraining) {
		t.Fatal(e)
	}
	// Stop/cancel intent cannot turn an unreturned backend call into success.
	i, e := m.lookup(r.ID)
	if e != nil {
		t.Fatal(e)
	}
	i.mu.Lock()
	i.jobs[j.ID].cancel()
	i.mu.Unlock()
	if s := g.AcceptedWorkStatus(); s.Pending != 1 || s.Complete() {
		t.Fatal(s)
	}
	release()
	eventually(t, func() bool { return g.AcceptedWorkStatus().Pending == 0 })
	if s := g.AcceptedWorkStatus(); s.Complete() || s.Failed != 1 {
		t.Fatal("cancelled work certified", s)
	}
}

func TestAcceptedWorkSuccessfulJobAndPrepareRequireTheirTerminalPaths(t *testing.T) {
	g := NewAdmissionGate(true)
	d := &acceptedWorkDriver{prepareEnter: make(chan struct{}), prepareRelease: make(chan struct{}), execEnter: make(chan struct{}), execRelease: make(chan struct{})}
	m, _, _ := setup(t, Options{AdmissionGate: g}, func(inner Driver) Driver { d.Driver = inner; return d })
	var pOnce, eOnce sync.Once
	releasePrepare := func() { pOnce.Do(func() { close(d.prepareRelease) }) }
	releaseExec := func() { eOnce.Do(func() { close(d.execRelease) }) }
	t.Cleanup(releasePrepare)
	t.Cleanup(releaseExec)
	type result struct {
		r Record
		e error
	}
	done := make(chan result, 1)
	go func() { r, e := m.Create(context.Background(), CreateRequest{}); done <- result{r, e} }()
	<-d.prepareEnter
	if s := g.FreezeAcceptedWork(); s.Pending != 1 || s.Complete() {
		t.Fatal(s)
	}
	releasePrepare()
	made := <-done
	if made.e != nil {
		t.Fatal(made.e)
	}
	if s := g.AcceptedWorkStatus(); !s.Complete() || s.Succeeded != 1 {
		t.Fatal(s)
	}
	// An already completed cohort stays closed; new Exec is not accepted.
	if _, e := m.Exec(made.r.ID, ExecRequest{Generation: made.r.Generation, Argv: []string{"late"}}); !errors.Is(e, ErrDraining) {
		t.Fatal(e)
	}
}

func TestAcceptedWorkOutcomesAreStickyAndNotJustIdleCounts(t *testing.T) {
	for _, kind := range []string{"success", "nonzero", "error"} {
		t.Run(kind, func(t *testing.T) {
			g := NewAdmissionGate(true)
			d := &acceptedWorkDriver{execEnter: make(chan struct{}), execRelease: make(chan struct{})}
			if kind == "nonzero" {
				d.exitCode = 7
			}
			if kind == "error" {
				d.execErr = errors.New("backend failed")
			}
			m, _, _ := setup(t, Options{AdmissionGate: g}, func(inner Driver) Driver { d.Driver = inner; return d })
			var once sync.Once
			release := func() { once.Do(func() { close(d.execRelease) }) }
			t.Cleanup(release)
			r := create(t, m, CreateRequest{})
			if _, e := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"controlled"}}); e != nil {
				t.Fatal(e)
			}
			<-d.execEnter
			g.FreezeAcceptedWork()
			release()
			eventually(t, func() bool { return g.AcceptedWorkStatus().Pending == 0 })
			s := g.FreezeAcceptedWork()
			if s.Complete() != (kind == "success") || s.Succeeded+s.Failed != 1 {
				t.Fatal(s)
			}
			if again := g.FreezeAcceptedWork(); again != s {
				t.Fatal("outcome reset", again, s)
			}
		})
	}
}

func TestAcceptedWorkTicketParentSurvivesChildConsumptionAndDoubleCompletion(t *testing.T) {
	g := NewAdmissionGate(true)
	m, _, _ := setup(t, Options{AdmissionGate: g}, nil)
	var ticket *CreationTicket
	if e := m.ReserveSessionAttempt(func(v *CreationTicket) { ticket = v }); e != nil {
		t.Fatal(e)
	}
	if s := g.FreezeAcceptedWork(); s.Pending != 1 || s.Complete() {
		t.Fatal(s)
	}
	permit := NewAdmission(func(Ref) bool { return true })
	if _, e := m.CreateReservedManagedScoped(context.Background(), Owner{TenantID: "alpha", MaxInstances: 4}, "accepted", CreateRequest{}, permit, func(Ref) {}, ticket); e != nil {
		t.Fatal(e)
	}
	if s := g.AcceptedWorkStatus(); s.Pending != 1 || s.Succeeded != 1 || s.Complete() || g.Pending() != 0 {
		t.Fatal("consumed ticket dropped parent", s)
	}
	ticket.Complete(nil)
	ticket.Complete(errors.New("duplicate"))
	ticket.Release()
	if s := g.AcceptedWorkStatus(); !s.Complete() || s.Succeeded != 2 {
		t.Fatal(s)
	}
	if e := g.reserve(ticket, func() { t.Fatal("completed ticket reused") }); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
}

func TestAcceptedWorkExecQueuedBeforeFenceIsNotAlreadyAccepted(t *testing.T) {
	g := NewAdmissionGate(true)
	m, _, _ := setup(t, Options{AdmissionGate: g}, nil)
	r := create(t, m, CreateRequest{})
	i, e := m.lookup(r.ID)
	if e != nil {
		t.Fatal(e)
	}
	i.mu.Lock()
	done := make(chan error, 1)
	go func() {
		_, e := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo", "late"}})
		done <- e
	}()
	if s := g.FreezeAcceptedWork(); !s.Complete() {
		t.Fatal(s)
	}
	i.mu.Unlock()
	if e := <-done; !errors.Is(e, ErrDraining) {
		t.Fatal("queued caller bypassed actual admission", e)
	}
	if s := g.AcceptedWorkStatus(); !s.Complete() || s.Succeeded != 0 {
		t.Fatal(s)
	}
}

func TestAcceptedWorkAbandonedTicketAndUnknownHistoryNeverComplete(t *testing.T) {
	g := NewAdmissionGate(true)
	m, _, _ := setup(t, Options{AdmissionGate: g}, nil)
	var ticket *CreationTicket
	if e := m.ReserveSessionAttempt(func(v *CreationTicket) { ticket = v }); e != nil {
		t.Fatal(e)
	}
	g.FreezeAcceptedWork()
	ticket.Release()
	ticket.Release()
	if s := g.AcceptedWorkStatus(); s.Pending != 0 || s.Failed != 1 || s.Complete() {
		t.Fatal(s)
	}
	other := NewAdmissionGate(true)
	other.MarkAcceptedWorkUncertain()
	if s := other.FreezeAcceptedWork(); s.Complete() || !s.Uncertain || s.Pending != 0 {
		t.Fatal(s)
	}
}

func TestAcceptedWorkRecoveredOwnershipRemainsUncertainAfterDurableCleanup(t *testing.T) {
	m, base, store := setup(t, Options{}, nil)
	r := create(t, m, CreateRequest{})
	if e := m.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	// Restore ONLY this private test's old READY ledger, representing a crash
	// without durable job outcomes. This is not live state rollback/adoption.
	if e := store.Save(r); e != nil {
		t.Fatal(e)
	}
	d, e := NewMockDriver(base + "/instances")
	if e != nil {
		t.Fatal(e)
	}
	g := NewAdmissionGate(true)
	next, e := NewManager(store, d, Options{AdmissionGate: g})
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close(context.Background())
	if e = next.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	if s := g.FreezeAcceptedWork(); s.Pending != 0 || !s.Uncertain || s.Complete() {
		t.Fatal("cleanup invented old work outcomes", s)
	}
}
