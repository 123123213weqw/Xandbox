//go:build linux || darwin

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

type observedResultDriver struct {
	Driver
	execs, stops atomic.Int64
}

func (d *observedResultDriver) Exec(c context.Context, r Ref, q ExecRequest, n int) (Output, error) {
	d.execs.Add(1)
	return d.Driver.Exec(c, r, q, n)
}
func (d *observedResultDriver) Stop(c context.Context, r Ref) error {
	d.stops.Add(1)
	return d.Driver.Stop(c, r)
}

type gatedResultStore struct {
	ResultStore
	reserveEnter, reserveRelease, completeEnter, completeRelease chan struct{}
	completeError                                                bool
}

func (s *gatedResultStore) Reserve(h ResultReservation) error {
	if s.reserveEnter != nil {
		close(s.reserveEnter)
		<-s.reserveRelease
	}
	return s.ResultStore.Reserve(h)
}
func (s *gatedResultStore) Complete(j Job) error {
	if s.completeEnter != nil {
		close(s.completeEnter)
		<-s.completeRelease
	}
	if s.completeError {
		return ErrResultUnavailable
	}
	return s.ResultStore.Complete(j)
}
func releaseResultGate(t *testing.T, ch chan struct{}) func() {
	var once sync.Once
	f := func() { once.Do(func() { close(ch) }) }
	t.Cleanup(f)
	return f
}

func TestManagerRetainedResultSurvivesCleanupAndNewManagerWithoutCommandReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results")
	results := resultOpen(t, path, resultLimits())
	d := &observedResultDriver{}
	m, _, ledger := setup(t, Options{Results: results}, func(inner Driver) Driver { d.Driver = inner; return d })
	r := create(t, m, CreateRequest{})
	j := execDone(t, m, r, "echo", "retained value")
	if !j.ResultRetained || j.Output.Stdout != "retained value\n" {
		t.Fatal(j)
	}
	if _, e := m.Destroy(r.Ref); e != nil {
		t.Fatal(e)
	}
	waitState(t, m, r.ID, Destroyed)
	again, e := m.GetJobScoped("local", r.ID, j.ID)
	if e != nil || !again.ResultRetained || again.Output != j.Output {
		t.Fatal("cleanup lost result", again, e)
	}
	if _, e = m.GetJobScoped("foreign", r.ID, j.ID); !errors.Is(e, ErrNotFound) {
		t.Fatal("tenant disclosure", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if e = m.Close(ctx); e != nil {
		t.Fatal(e)
	}
	results.Close()
	reopened := resultOpen(t, path, resultLimits())
	next, e := NewManager(ledger, d, Options{Results: reopened})
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close(ctx)
	again, e = next.GetJobScoped("local", r.ID, j.ID)
	if e != nil || again.Output != j.Output || !again.ResultRetained || d.execs.Load() != 1 {
		t.Fatal("restart lost/replayed", again, e, d.execs.Load())
	}
}
func TestManagerResultReserveIOIsTrackedBeforeExecutionAndDoesNotBlockStopMutex(t *testing.T) {
	store := &gatedResultStore{ResultStore: resultOpen(t, filepath.Join(t.TempDir(), "results"), resultLimits()), reserveEnter: make(chan struct{}), reserveRelease: make(chan struct{})}
	gate := NewAdmissionGate(true)
	d := &observedResultDriver{}
	m, _, _ := setup(t, Options{Results: store, AdmissionGate: gate}, func(inner Driver) Driver { d.Driver = inner; return d })
	release := releaseResultGate(t, store.reserveRelease)
	r := create(t, m, CreateRequest{})
	done := make(chan error, 1)
	go func() {
		_, e := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo", "not-executed"}})
		done <- e
	}()
	<-store.reserveEnter
	if s := gate.FreezeAcceptedWork(); s.Pending != 1 || s.Complete() {
		t.Fatal(s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, e := m.Stop(ctx, r.Ref); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	if d.execs.Load() != 0 || d.stops.Load() == 0 {
		t.Fatal("executed before reservation or stop blocked")
	}
	release()
	if e := <-done; !errors.Is(e, ErrResultUnavailable) {
		t.Fatal(e)
	}
	eventually(t, func() bool { return gate.AcceptedWorkStatus().Pending == 0 })
	if s := gate.AcceptedWorkStatus(); s.Complete() || s.Failed != 1 {
		t.Fatal(s)
	}
}
func TestManagerResultCompletionIOStaysPendingAndOutputIsNotPublishedEarly(t *testing.T) {
	store := &gatedResultStore{ResultStore: resultOpen(t, filepath.Join(t.TempDir(), "results"), resultLimits()), completeEnter: make(chan struct{}), completeRelease: make(chan struct{})}
	gate := NewAdmissionGate(true)
	d := &observedResultDriver{}
	m, _, _ := setup(t, Options{Results: store, AdmissionGate: gate}, func(inner Driver) Driver { d.Driver = inner; return d })
	release := releaseResultGate(t, store.completeRelease)
	r := create(t, m, CreateRequest{})
	j, e := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo", "durable"}})
	if e != nil {
		t.Fatal(e)
	}
	<-store.completeEnter
	if s := gate.FreezeAcceptedWork(); s.Pending != 1 || s.Complete() {
		t.Fatal(s)
	}
	observed, e := m.GetJob(r.ID, j.ID)
	if e != nil || observed.Status != "RUNNING" || observed.ResultRetained || observed.Output.Stdout != "" {
		t.Fatal(observed, e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, e = m.Stop(ctx, r.Ref); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	if d.stops.Load() == 0 {
		t.Fatal("result IO blocked independent stop")
	}
	release()
	eventually(t, func() bool { return gate.AcceptedWorkStatus().Pending == 0 })
	if s := gate.AcceptedWorkStatus(); !s.Complete() {
		t.Fatal(s)
	}
	observed, e = m.GetJob(r.ID, j.ID)
	if e != nil || !observed.ResultRetained || observed.Output.Stdout != "durable\n" {
		t.Fatal(observed, e)
	}
}
func TestManagerFailedResultDurabilityNeverPublishesOutputOrWorkSuccess(t *testing.T) {
	store := &gatedResultStore{ResultStore: resultOpen(t, filepath.Join(t.TempDir(), "results"), resultLimits()), completeEnter: make(chan struct{}), completeRelease: make(chan struct{}), completeError: true}
	gate := NewAdmissionGate(true)
	m, _, _ := setup(t, Options{Results: store, AdmissionGate: gate}, nil)
	release := releaseResultGate(t, store.completeRelease)
	r := create(t, m, CreateRequest{})
	j, e := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo", "must-not-publish"}})
	if e != nil {
		t.Fatal(e)
	}
	<-store.completeEnter
	gate.FreezeAcceptedWork()
	release()
	eventually(t, func() bool { return gate.AcceptedWorkStatus().Pending == 0 })
	if s := gate.AcceptedWorkStatus(); s.Complete() || s.Failed != 1 {
		t.Fatal(s)
	}
	if _, e = m.GetJob(r.ID, j.ID); !errors.Is(e, ErrResultUnavailable) {
		t.Fatal("volatile success leaked", e)
	}
}
func TestManagerResultCapacityRejectsBeforeDriverAndPendingRestartIsUncertain(t *testing.T) {
	h := resultHeader()
	s := resultOpen(t, filepath.Join(t.TempDir(), "results"), ResultLimits{Bytes: 1, TenantBytes: 1, Records: 1})
	d := &observedResultDriver{}
	m, _, _ := setup(t, Options{Results: s}, func(inner Driver) Driver { d.Driver = inner; return d })
	r := create(t, m, CreateRequest{})
	if _, e := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo", "no"}}); !errors.Is(e, ErrResultCapacity) {
		t.Fatal(e)
	}
	if d.execs.Load() != 0 {
		t.Fatal("driver called above result budget")
	}
	h.Ref = r.Ref
	h.MaxOutputBytes = r.Limits.MaxOutputBytes
	path := filepath.Join(t.TempDir(), "results")
	pending := resultOpen(t, path, resultLimits())
	if e := pending.Reserve(h); e != nil {
		t.Fatal(e)
	}
	if u, e := pending.Bind([]Record{resultOwner(h)}); e != nil || !u {
		t.Fatal(u, e)
	}
	if j, e := pending.Get(h.Ref, h.TenantID, h.JobID); e != nil || j.Status != "INTERRUPTED" || j.ResultRetained {
		t.Fatal(j, e)
	}
}

func TestManagerPendingResultWithDestroyedLedgerStillMarksRestartUncertain(t *testing.T) {
	m, _, ledger := setup(t, Options{}, nil)
	r := create(t, m, CreateRequest{})
	if _, e := m.Destroy(r.Ref); e != nil {
		t.Fatal(e)
	}
	waitState(t, m, r.ID, Destroyed)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if e := m.Close(ctx); e != nil {
		t.Fatal(e)
	}
	store := resultOpen(t, filepath.Join(t.TempDir(), "results"), resultLimits())
	h := resultHeader()
	h.Ref = r.Ref
	h.TenantID = r.TenantID
	h.MaxOutputBytes = r.Limits.MaxOutputBytes
	if e := store.Reserve(h); e != nil {
		t.Fatal(e)
	}
	gate := NewAdmissionGate(true)
	next, e := NewManager(ledger, m.driver, Options{Results: store, AdmissionGate: gate})
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close(ctx)
	j, e := next.GetJobScoped(r.TenantID, r.ID, h.JobID)
	if e != nil || j.Status != "INTERRUPTED" || j.ResultRetained || !gate.AcceptedWorkStatus().Uncertain {
		t.Fatal(j, e, gate.AcceptedWorkStatus())
	}
	if gate.FreezeAcceptedWork().Complete() {
		t.Fatal("pending result certified after reboot")
	}
}
