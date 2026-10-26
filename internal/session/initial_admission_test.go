package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

// These are control-plane Mock tests, never KVM/physical recovery evidence.
func initialAdmissionFull(t *testing.T, tenant bool, wrap func(Store) Store) (*Broker, *sandbox.Manager, *probeDriver, *FileStore, sandbox.Owner, []sandbox.Record) {
	t.Helper()
	b, core, driver, fs := fixture(t, Options{}, wrap)
	owner := alpha
	holder := sandbox.Owner{TenantID: "holder", MaxInstances: 4}
	count := 4
	if tenant {
		owner.MaxInstances = 1
		holder, count = owner, 1
	}
	var held []sandbox.Record
	for i := 0; i < count; i++ {
		vm, e := core.CreateScoped(context.Background(), holder, fmt.Sprintf("held-%d", i), sandbox.CreateRequest{})
		if e != nil {
			t.Fatal(e)
		}
		held = append(held, vm)
	}
	return b, core, driver, fs, owner, held
}

func TestInitialOpenCapacityRefusalHasDurableClosedIntentWithoutCandidate(t *testing.T) {
	for _, tenant := range []bool{false, true} {
		t.Run(fmt.Sprintf("tenant_%t", tenant), func(t *testing.T) {
			b, core, driver, fs, owner, held := initialAdmissionFull(t, tenant, nil)
			want := sandbox.ErrCapacity
			if tenant {
				want = sandbox.ErrTenantCapacity
			}
			before := core.Metrics()
			calls := driver.calls.Load()
			got, e := b.Open(context.Background(), owner, "refused-initial", sandbox.CreateRequest{})
			if !errors.Is(e, want) || errors.Is(e, ErrUnavailable) || got != (Result{}) {
				t.Fatalf("unallocated capacity must not be mislabeled as a fenced session: %v", e)
			}
			if driver.calls.Load() != calls || core.Metrics().Records != before.Records || core.Metrics().Allocated != before.Allocated {
				t.Fatal("refusal created or released a VM/ownership record")
			}
			// Read immediately, not eventually: the ordinary error response may
			// not conceal a pending/failed CLOSED journal commit.
			rows, e := fs.Load()
			if e != nil || len(rows) != 1 || rows[0].State != Closed || rows[0].Revision != 0 || !zeroRef(rows[0].Current) || len(rows[0].Attempts) != 1 || rows[0].Attempts[0].State != "FAILED" || !zeroRef(rows[0].Attempts[0].Target) {
				t.Fatal("capacity error preceded durable failed initial intent", e)
			}
			if _, has, e := b.Get(owner.TenantID, rows[0].ID); e != nil || has {
				t.Fatal("rejected initial session published admission", e)
			}
			if records, _ := b.Metrics(); records != 1 {
				t.Fatal("failed permanent key slot was discarded")
			}
			if _, e = b.Open(context.Background(), owner, "refused-initial", sandbox.CreateRequest{}); !errors.Is(e, ErrGone) {
				t.Fatal("refused key restarted a failed initial session", e)
			}
			// Only ordinary destruction frees the full instance slot. The old
			// key stays gone while a NEW key can create a clean candidate.
			if _, e = core.DestroyScoped(held[0].TenantID, held[0].Ref); e != nil {
				t.Fatal(e)
			}
			eventually(t, func() bool { return core.Metrics().Allocated == before.Allocated-1 })
			if _, e = b.Open(context.Background(), owner, "new-after-capacity", sandbox.CreateRequest{}); e != nil {
				t.Fatal(e)
			}
			if _, e = b.Open(context.Background(), owner, "refused-initial", sandbox.CreateRequest{}); !errors.Is(e, ErrGone) {
				t.Fatal("slot reuse revived rejected key", e)
			}
		})
	}
}

type initialClosedErrorStore struct {
	Store
	armed       atomic.Bool
	commitFirst bool
}

func (s *initialClosedErrorStore) Save(r Record) error {
	if r.State == Closed && s.armed.Load() {
		if s.commitFirst {
			if e := s.Store.Save(r); e != nil {
				return e
			}
		}
		return errors.New("synthetic closed commit uncertainty")
	}
	return s.Store.Save(r)
}

func TestInitialOpenCapacityCannotMaskClosedJournalErrorOrAmbiguity(t *testing.T) {
	for _, commitFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("commit_then_error_%t", commitFirst), func(t *testing.T) {
			var store *initialClosedErrorStore
			b, core, driver, fs, owner, _ := initialAdmissionFull(t, false, func(s Store) Store {
				store = &initialClosedErrorStore{Store: s, commitFirst: commitFirst}
				return store
			})
			store.armed.Store(true)
			t.Cleanup(func() { store.armed.Store(false) })
			calls := driver.calls.Load()
			before := core.Metrics()
			if _, e := b.Open(context.Background(), owner, "uncertain-initial", sandbox.CreateRequest{}); !errors.Is(e, ErrUnavailable) || errors.Is(e, sandbox.ErrCapacity) {
				t.Fatal("journal error became ordinary overload", e)
			}
			if driver.calls.Load() != calls || core.Metrics().Allocated != before.Allocated || core.Metrics().Records != before.Records {
				t.Fatal("failed journal changed instance ownership")
			}
			if _, e := b.Open(context.Background(), owner, "uncertain-initial", sandbox.CreateRequest{}); !errors.Is(e, ErrGone) {
				t.Fatal("ambiguous initial key admitted execution", e)
			}
			store.armed.Store(false)
			eventually(t, func() bool {
				r, e := fs.Load()
				return e == nil && len(r) == 1 && r[0].State == Closed && r[0].Attempts[0].State == "FAILED"
			})
		})
	}
}

type initialPrepareCapacityError struct{ sandbox.Driver }

func (d *initialPrepareCapacityError) Prepare(context.Context, sandbox.Ref, sandbox.Preparation) error {
	return sandbox.ErrCapacity // Backend error AFTER Core reserved a generation.
}

func TestInitialOpenAllocatedBackendCapacityErrorStillFences(t *testing.T) {
	b, core, driver, fs := fixture(t, Options{}, nil)
	driver.Driver = &initialPrepareCapacityError{Driver: driver.Driver}
	if _, e := b.Open(context.Background(), alpha, "backend-capacity", sandbox.CreateRequest{}); !errors.Is(e, ErrUnavailable) || errors.Is(e, sandbox.ErrCapacity) {
		t.Fatal("allocated backend error became ordinary overload", e)
	}
	eventually(t, func() bool { return core.Metrics().Allocated == 0 })
	eventually(t, func() bool {
		r, e := fs.Load()
		return e == nil && len(r) == 1 && r[0].State == Closed && r[0].Attempts[0].State == "FAILED" && !zeroRef(r[0].Attempts[0].Target)
	})
}

func TestInitialCapacityPredicateRejectsWrappedUnknownAllocatedOrFencedErrors(t *testing.T) {
	for _, cause := range []error{fmt.Errorf("wrapped: %w", sandbox.ErrCapacity), errors.Join(sandbox.ErrCapacity, errors.New("io")), sandbox.ErrMetadataCapacity, sandbox.ErrTenantMetadataCapacity, sandbox.ErrDraining, sandbox.ErrClosing, context.Canceled, errors.New("unknown")} {
		b, e, a := &Broker{}, newEntry(Record{}), &attempt{}
		if handled, err := b.rejectInitialCapacity(e, a, cause); handled || err != nil || e.closed.Load() {
			t.Fatal("nondefinitive error became ordinary capacity")
		}
	}
	for _, kind := range []string{"switch", "allocated", "fenced", "cancelled", "closed"} {
		b, e, a := &Broker{}, newEntry(Record{}), &attempt{}
		switch kind {
		case "switch":
			a.index = 1
		case "allocated":
			a.ref = sandbox.Ref{ID: "reserved", Generation: "reserved"}
		case "fenced":
			a.fenced = true
		case "cancelled":
			a.cancelled = true
		case "closed":
			e.closed.Store(true)
		}
		if handled, err := b.rejectInitialCapacity(e, a, sandbox.ErrCapacity); handled || err != nil || e.closed.Load() != (kind == "closed") {
			t.Fatal("existing authority/closure became ordinary capacity", kind)
		}
	}
}

type initialClosedBarrier struct {
	Store
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *initialClosedBarrier) Save(r Record) error {
	if r.State == Closed {
		s.once.Do(func() { close(s.entered); <-s.release })
	}
	return s.Store.Save(r)
}

func TestInitialOpenCapacityReplyWaitsForActualClosedCommit(t *testing.T) {
	var barrier *initialClosedBarrier
	b, core, driver, fs, owner, _ := initialAdmissionFull(t, false, func(s Store) Store {
		barrier = &initialClosedBarrier{Store: s, entered: make(chan struct{}), release: make(chan struct{})}
		return barrier
	})
	var release sync.Once
	unblock := func() { release.Do(func() { close(barrier.release) }) }
	t.Cleanup(unblock) // Release BEFORE fixture's broker/core Close, including fatal paths.
	calls := driver.calls.Load()
	before := core.Metrics()
	done := make(chan error, 1)
	go func() {
		_, err := b.Open(context.Background(), owner, "held-closed", sandbox.CreateRequest{})
		done <- err
	}()
	select {
	case <-barrier.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("actual closed store call did not reach controlled barrier")
	}
	select {
	case <-done:
		t.Fatal("ordinary capacity replied before CLOSED commit")
	default:
	}
	rows, err := fs.Load()
	if err != nil || len(rows) != 1 || rows[0].State != Creating {
		t.Fatal("synthetic pre-commit hold already changed disk state", err)
	}
	if _, route, err := b.Get(owner.TenantID, rows[0].ID); err != nil || route {
		t.Fatal("held failed initial intent admitted execution", err)
	}
	if driver.calls.Load() != calls || core.Metrics().Allocated != before.Allocated || core.Metrics().Records != before.Records {
		t.Fatal("held initial refusal changed live instance ownership")
	}
	unblock()
	select {
	case err = <-done:
		if !errors.Is(err, sandbox.ErrCapacity) || errors.Is(err, ErrUnavailable) {
			t.Fatal("completed closed commit did not preserve capacity", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("closed commit did not complete")
	}
	rows, err = fs.Load()
	if err != nil || len(rows) != 1 || rows[0].State != Closed || rows[0].Attempts[0].State != "FAILED" {
		t.Fatal("capacity reply lacks durable failed intent", err)
	}
}
