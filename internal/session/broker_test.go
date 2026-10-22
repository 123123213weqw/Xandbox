package session

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

type probeDriver struct {
	sandbox.Driver
	calls atomic.Int32
	fail  atomic.Bool
}

func (d *probeDriver) Prepare(ctx context.Context, ref sandbox.Ref, p sandbox.Preparation) error {
	d.calls.Add(1)
	if d.fail.Swap(false) {
		return errors.New("injected prepare failure")
	}
	return d.Driver.Prepare(ctx, ref, p)
}
func fixture(t *testing.T, opts Options, wrap func(Store) Store) (*Broker, *sandbox.Manager, *probeDriver, *FileStore) {
	t.Helper()
	dir := t.TempDir()
	vmStore, e := sandbox.NewFileStore(filepath.Join(dir, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	mock, e := sandbox.NewMockDriver(filepath.Join(dir, "instances"))
	if e != nil {
		t.Fatal(e)
	}
	driver := &probeDriver{Driver: mock}
	core, e := sandbox.NewManager(vmStore, driver, sandbox.Options{MaxInstances: 4, ReapInterval: time.Millisecond, RetryDelay: time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	fs, e := NewFileStore(filepath.Join(dir, "sessions"))
	if e != nil {
		t.Fatal(e)
	}
	var store Store = fs
	if wrap != nil {
		store = wrap(store)
	}
	opts.RetryInterval = time.Millisecond
	b, e := New(core, store, opts)
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
	return b, core, driver, fs
}

var alpha = sandbox.Owner{TenantID: "alpha", MaxInstances: 4}

func open(t *testing.T, b *Broker, key string) Result {
	t.Helper()
	r, e := b.Open(context.Background(), alpha, key, sandbox.CreateRequest{})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func eventually(t *testing.T, p func() bool) {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		if p() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not reached")
}
func run(t *testing.T, b *Broker, core *sandbox.Manager, r Result, argv ...string) sandbox.Job {
	t.Helper()
	job, e := b.Exec("alpha", r.ID, r.Revision, sandbox.ExecRequest{Argv: argv})
	if e != nil {
		t.Fatal(e)
	}
	vmID, jobID := job.Ref.ID, job.ID
	eventually(t, func() bool {
		var e error
		job, e = core.GetJobScoped("alpha", vmID, jobID)
		return e == nil && job.Status != "RUNNING"
	})
	return job
}

func TestColdSwitchCASIsolatedWorkspaceAndRetiredReclamation(t *testing.T) {
	b, core, d, _ := fixture(t, Options{}, nil)
	first := open(t, b, "create")
	if job := run(t, b, core, first, "write", "note", "old"); job.Status != "EXITED" {
		t.Fatal(job.Status)
	}
	if _, e := core.ExecScoped("alpha", first.Current.ID, sandbox.ExecRequest{Generation: first.Current.Generation, Argv: []string{"echo", "bypass"}}); !errors.Is(e, sandbox.ErrNotReady) {
		t.Fatal("plain endpoint bypassed session", e)
	}
	second, e := b.Switch(context.Background(), alpha, first.ID, "switch", SwitchRequest{ExpectedRevision: first.Revision})
	if e != nil {
		t.Fatal(e)
	}
	if second.Revision != 2 || second.Previous != first.Current || second.Current == first.Current || d.calls.Load() != 2 {
		t.Fatal(second, d.calls.Load())
	}
	if job := run(t, b, core, second, "read", "note"); job.Status != "FAILED" {
		t.Fatal("fresh workspace contained old data", job.Status)
	}
	if _, e := b.Exec("alpha", first.ID, first.Revision, sandbox.ExecRequest{Argv: []string{"echo", "stale"}}); !errors.Is(e, ErrStale) {
		t.Fatal(e)
	}
	if _, e := b.Exec("beta", first.ID, second.Revision, sandbox.ExecRequest{Argv: []string{"echo"}}); !errors.Is(e, sandbox.ErrNotFound) {
		t.Fatal(e)
	}
	eventually(t, func() bool {
		r, e := core.GetScoped("alpha", first.Current.ID)
		return e == nil && r.State == sandbox.Destroyed
	})
	replay, e := b.Switch(context.Background(), alpha, first.ID, "switch", SwitchRequest{ExpectedRevision: first.Revision})
	if e != nil || replay.Current != second.Current {
		t.Fatal("same-key replay created another VM", e)
	}
	if _, e = b.Switch(context.Background(), alpha, first.ID, "switch", SwitchRequest{ExpectedRevision: 2}); !errors.Is(e, sandbox.ErrIdempotencyConflict) {
		t.Fatal(e)
	}
	if _, e = b.Open(context.Background(), alpha, "create", sandbox.CreateRequest{}); !errors.Is(e, ErrGone) {
		t.Fatal("old create key rebound to latest version", e)
	}
}

func TestConcurrentSameSwitchKeyPreparesOnce(t *testing.T) {
	b, _, d, _ := fixture(t, Options{}, nil)
	first := open(t, b, "create")
	var wg sync.WaitGroup
	refs := make(chan sandbox.Ref, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := b.Switch(context.Background(), alpha, first.ID, "same", SwitchRequest{ExpectedRevision: 1})
			if e != nil {
				t.Error(e)
				return
			}
			refs <- r.Current
		}()
	}
	wg.Wait()
	close(refs)
	var ref sandbox.Ref
	for r := range refs {
		if ref == (sandbox.Ref{}) {
			ref = r
		}
		if r != ref {
			t.Fatal("multiple targets")
		}
	}
	if d.calls.Load() != 2 {
		t.Fatal("duplicate candidate preparation", d.calls.Load())
	}
}

func TestPrepareFailurePreservesOldRouteButConsumesAttemptKey(t *testing.T) {
	b, core, d, _ := fixture(t, Options{}, nil)
	first := open(t, b, "create")
	d.fail.Store(true)
	if _, e := b.Switch(context.Background(), alpha, first.ID, "failed", SwitchRequest{ExpectedRevision: 1}); e == nil {
		t.Fatal("failed prepare succeeded")
	}
	if job := run(t, b, core, first, "echo", "old-still-live"); job.Status != "EXITED" {
		t.Fatal(job.Status)
	}
	if _, e := b.Switch(context.Background(), alpha, first.ID, "failed", SwitchRequest{ExpectedRevision: 1}); !errors.Is(e, ErrGone) {
		t.Fatal(e)
	}
	if _, e := b.Switch(context.Background(), alpha, first.ID, "fresh", SwitchRequest{ExpectedRevision: 1}); e != nil {
		t.Fatal(e)
	}
}

type stageBarrier struct {
	Store
	stage    string
	revision uint64
	entered  chan Record
	release  chan struct{}
	armed    atomic.Bool
}

func (s *stageBarrier) Save(r Record) error {
	if r.State == s.stage && r.Revision == s.revision && s.armed.Swap(false) {
		s.entered <- clone(r)
		<-s.release
	}
	return s.Store.Save(r)
}
func TestCancellationDuringPreparedFsyncStopsOnlyCandidate(t *testing.T) {
	var barrier *stageBarrier
	b, core, _, _ := fixture(t, Options{}, func(base Store) Store {
		barrier = &stageBarrier{Store: base, stage: Prepared, revision: 1, entered: make(chan Record, 1), release: make(chan struct{})}
		return barrier
	})
	first := open(t, b, "create")
	barrier.armed.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var release sync.Once
	defer release.Do(func() { close(barrier.release) })
	result := make(chan error, 1)
	go func() {
		_, e := b.Switch(ctx, alpha, first.ID, "cancel", SwitchRequest{ExpectedRevision: 1})
		result <- e
	}()
	var prepared Record
	select {
	case prepared = <-barrier.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("prepared fsync not reached")
	}
	candidate := prepared.Attempts[len(prepared.Attempts)-1].Target
	cancel()
	eventually(t, func() bool {
		r, e := core.GetScoped("alpha", candidate.ID)
		return e == nil && r.State == sandbox.Destroyed
	})
	if job := run(t, b, core, first, "echo", "old"); job.Status != "EXITED" {
		t.Fatal("preparation blocked old routing")
	}
	release.Do(func() { close(barrier.release) })
	if e := <-result; e == nil {
		t.Fatal("cancelled switch succeeded")
	}
	if _, has, e := b.Get("alpha", first.ID); e != nil || !has {
		t.Fatal("old binding lost after pre-fence cancellation", e)
	}
}

func TestCloseDuringCommitFsyncNeverPublishesLateBinding(t *testing.T) {
	var barrier *stageBarrier
	b, core, _, _ := fixture(t, Options{}, func(base Store) Store {
		barrier = &stageBarrier{Store: base, stage: Active, revision: 2, entered: make(chan Record, 1), release: make(chan struct{})}
		return barrier
	})
	first := open(t, b, "create")
	barrier.armed.Store(true)
	var release sync.Once
	defer release.Do(func() { close(barrier.release) })
	switched := make(chan error, 1)
	go func() {
		_, e := b.Switch(context.Background(), alpha, first.ID, "blocked", SwitchRequest{ExpectedRevision: 1})
		switched <- e
	}()
	var pending Record
	select {
	case pending = <-barrier.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("commit fsync not reached")
	}
	if _, e := b.Exec("alpha", first.ID, 1, sandbox.ExecRequest{Argv: []string{"echo"}}); !errors.Is(e, ErrBusy) {
		t.Fatal("old route remained open after fence", e)
	}
	eventually(t, func() bool {
		r, e := core.GetScoped("alpha", first.Current.ID)
		return e == nil && r.State == sandbox.Destroyed
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if e := b.Close(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("Close claimed blocked writer terminated", e)
	}
	eventually(t, func() bool {
		r, e := core.GetScoped("alpha", pending.Current.ID)
		return e == nil && r.State == sandbox.Destroyed
	})
	release.Do(func() { close(barrier.release) })
	if e := <-switched; e == nil {
		t.Fatal("late commit reopened closed binding")
	}
	end, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if e := b.Close(end); e != nil {
		t.Fatal(e)
	}
	r, has, e := b.Get("alpha", first.ID)
	if e != nil || has || r.State != Closed {
		t.Fatal("closed session resurrected", e, has, r.State)
	}
}

type ambiguousCommit struct {
	Store
	fail atomic.Bool
}

func (s *ambiguousCommit) Save(r Record) error {
	if e := s.Store.Save(r); e != nil {
		return e
	}
	if r.State == Active && r.Revision == 2 && s.fail.Swap(false) {
		return errors.New("error after committed rename")
	}
	return nil
}
func TestAmbiguousBindingCommitClosesBothGenerations(t *testing.T) {
	var s *ambiguousCommit
	b, core, _, fs := fixture(t, Options{}, func(base Store) Store { s = &ambiguousCommit{Store: base}; return s })
	first := open(t, b, "create")
	s.fail.Store(true)
	if _, e := b.Switch(context.Background(), alpha, first.ID, "ambiguous", SwitchRequest{ExpectedRevision: 1}); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	eventually(t, func() bool { return core.Stats().Active == 0 })
	eventually(t, func() bool { rows, e := fs.Load(); return e == nil && len(rows) == 1 && rows[0].State == Closed })
	if _, has, e := b.Get("alpha", first.ID); e != nil || has {
		t.Fatal("ambiguous commit exposed route", e)
	}
}

func TestSessionQuotaAndHistoryRetainTombstones(t *testing.T) {
	b, _, _, _ := fixture(t, Options{MaxSessions: 1, MaxAttempts: 2}, nil)
	first := open(t, b, "create")
	second, e := b.Switch(context.Background(), alpha, first.ID, "one", SwitchRequest{ExpectedRevision: 1})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.Switch(context.Background(), alpha, first.ID, "two", SwitchRequest{ExpectedRevision: 2}); !errors.Is(e, ErrHistory) {
		t.Fatal(e)
	}
	if e = b.CloseSession("alpha", first.ID, 1); !errors.Is(e, ErrStale) {
		t.Fatal(e)
	}
	if e = b.CloseSession("alpha", first.ID, second.Revision); e != nil {
		t.Fatal(e)
	}
	if _, e = b.Open(context.Background(), alpha, "new", sandbox.CreateRequest{}); !errors.Is(e, ErrCapacity) {
		t.Fatal("closed session freed permanent key slot", e)
	}
}

func TestCallerCancellationAfterFenceResolvesCommitIdempotently(t *testing.T) {
	var barrier *stageBarrier
	b, core, _, _ := fixture(t, Options{}, func(base Store) Store {
		barrier = &stageBarrier{Store: base, stage: Active, revision: 2, entered: make(chan Record, 1), release: make(chan struct{})}
		return barrier
	})
	first := open(t, b, "create")
	barrier.armed.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var release sync.Once
	defer release.Do(func() { close(barrier.release) })
	type outcome struct {
		r Result
		e error
	}
	finished := make(chan outcome, 1)
	go func() {
		r, e := b.Switch(ctx, alpha, first.ID, "after-fence", SwitchRequest{ExpectedRevision: 1})
		finished <- outcome{r, e}
	}()
	var pending Record
	select {
	case pending = <-barrier.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("commit not reached")
	}
	cancel()
	// Cancellation after the irrevocable old fence must not race a delayed
	// cancellation callback into killing a legitimately committed new route.
	release.Do(func() { close(barrier.release) })
	got := <-finished
	if got.e != nil || got.r.Current != pending.Current {
		t.Fatal(got.e)
	}
	if job := run(t, b, core, got.r, "echo", "committed"); job.Status != "EXITED" {
		t.Fatal(job.Status)
	}
	replay, e := b.Switch(context.Background(), alpha, first.ID, "after-fence", SwitchRequest{ExpectedRevision: 1})
	if e != nil || replay.Current != got.r.Current {
		t.Fatal(e)
	}
}

func TestRestartNeverRevivesDurableSessionBinding(t *testing.T) {
	b, core, _, fs := fixture(t, Options{}, nil)
	first := open(t, b, "create")
	saved, _, e := b.Get("alpha", first.ID)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if e = b.Close(ctx); e != nil {
		t.Fatal(e)
	}
	if e = core.Close(ctx); e != nil {
		t.Fatal(e)
	}
	// Model the last durable pre-crash ACTIVE journal against known core
	// identities. Process/KVM acceptance separately exercises an actual SIGKILL.
	if e = fs.Save(saved); e != nil {
		t.Fatal(e)
	}
	base := filepath.Dir(fs.dir)
	vmStore, e := sandbox.NewFileStore(filepath.Join(base, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	d, e := sandbox.NewMockDriver(filepath.Join(base, "instances"))
	if e != nil {
		t.Fatal(e)
	}
	nextCore, e := sandbox.NewManager(vmStore, d, sandbox.Options{})
	if e != nil {
		t.Fatal(e)
	}
	defer nextCore.Close(ctx)
	next, e := New(nextCore, fs, Options{MaxSessions: 1})
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close(ctx)
	row, has, e := next.Get("alpha", first.ID)
	if e != nil || has || row.State != Closed {
		t.Fatal(e, row.State, has)
	}
	if _, e = next.Open(ctx, alpha, "create", sandbox.CreateRequest{}); !errors.Is(e, ErrGone) {
		t.Fatal("restarted old session created new VM", e)
	}
	if nextCore.Stats().Active != 0 {
		t.Fatal("old binding was revived")
	}
}

type closedFailure struct {
	Store
	fail atomic.Bool
}

func (s *closedFailure) Save(r Record) error {
	if r.State == Closed && s.fail.Load() {
		return errors.New("closed journal fsync failed")
	}
	return s.Store.Save(r)
}
func TestFailedClosedJournalRetainsUnfinishedCloseButNotExecution(t *testing.T) {
	var s *closedFailure
	b, core, _, _ := fixture(t, Options{}, func(base Store) Store { s = &closedFailure{Store: base}; return s })
	open(t, b, "create")
	s.fail.Store(true)
	t.Cleanup(func() { s.fail.Store(false); b.notify() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if e := b.Close(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("failed journal counted as durable Close", e)
	}
	eventually(t, func() bool { return core.Stats().Active == 0 })
	select {
	case <-b.Done():
		t.Fatal("unfinished journal worker reported terminated")
	default:
	}
	s.fail.Store(false)
	b.notify()
	end, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if e := b.Close(end); e != nil {
		t.Fatal(e)
	}
}
