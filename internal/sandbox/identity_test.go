package sandbox

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingPrepare struct {
	Driver
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (d *countingPrepare) Prepare(ctx context.Context, ref Ref, limits Preparation) error {
	d.calls.Add(1)
	if d.entered != nil {
		close(d.entered)
		select {
		case <-d.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return d.Driver.Prepare(ctx, ref, limits)
}

func TestConcurrentIdempotentCreate(t *testing.T) {
	d := &countingPrepare{}
	m, _, _ := setup(t, Options{MaxInstances: 2}, func(base Driver) Driver { d.Driver = base; return d })
	owner := Owner{TenantID: "alpha", MaxInstances: 1}
	var wg sync.WaitGroup
	results := make(chan Record, 64)
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := m.CreateScoped(context.Background(), owner, "request-1", CreateRequest{})
			if err != nil {
				t.Errorf("create: %v", err)
				return
			}
			results <- r
		}()
	}
	wg.Wait()
	close(results)
	var first Record
	for r := range results {
		if first.ID == "" {
			first = r
		}
		if r.Ref != first.Ref {
			t.Fatal("same key allocated multiple instances")
		}
	}
	if d.calls.Load() != 1 || m.Stats().Active != 1 {
		t.Fatalf("prepare=%d stats=%+v", d.calls.Load(), m.Stats())
	}
	// Explicit defaults normalize to the same creation request; replay precedes quota checks.
	defaults, _ := normalizeCreate(CreateRequest{})
	if r, err := m.CreateScoped(context.Background(), owner, "request-1", defaults); err != nil || r.Ref != first.Ref {
		t.Fatalf("normalized replay: %+v %v", r, err)
	}
	if _, err := m.CreateScoped(context.Background(), owner, "request-1", CreateRequest{TTLMS: 10_000}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict: %v", err)
	}
	if _, err := m.CreateScoped(context.Background(), owner, "other-key", CreateRequest{}); !errors.Is(err, ErrTenantCapacity) {
		t.Fatalf("quota: %v", err)
	}
	other := Owner{TenantID: "beta", MaxInstances: 1}
	if r, err := m.CreateScoped(context.Background(), other, "request-1", CreateRequest{}); err != nil || r.Ref == first.Ref {
		t.Fatalf("tenant key scope: %+v %v", r, err)
	}
	if _, err := m.Destroy(first.Ref); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, first.ID, Destroyed)
	if _, err := m.CreateScoped(context.Background(), owner, "request-1", CreateRequest{}); !errors.Is(err, ErrIdempotencyGone) {
		t.Fatalf("destroyed key silently reused: %v", err)
	}
}

func TestIdempotentWaitHonorsCallerDeadline(t *testing.T) {
	d := &countingPrepare{entered: make(chan struct{}), release: make(chan struct{})}
	m, _, _ := setup(t, Options{}, func(base Driver) Driver { d.Driver = base; return d })
	owner := Owner{TenantID: "alpha", MaxInstances: 1}
	done := make(chan error, 1)
	go func() { _, err := m.CreateScoped(context.Background(), owner, "slow", CreateRequest{}); done <- err }()
	select {
	case <-d.entered:
	case <-time.After(time.Second):
		t.Fatal("prepare did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := m.CreateScoped(ctx, owner, "slow", CreateRequest{})
	close(d.release)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait did not honor deadline: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTenantQuotaConcurrentAndReclaiming(t *testing.T) {
	d := &gateDriver{entered: make(chan struct{}), release: make(chan struct{})}
	m, _, _ := setup(t, Options{MaxInstances: 128}, func(base Driver) Driver { d.Driver = base; return d })
	defer close(d.release)
	owner := Owner{TenantID: "alpha", MaxInstances: 3}
	var wg sync.WaitGroup
	var admitted atomic.Int32
	results := make(chan Record, 64)
	for n := range 64 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			r, err := m.CreateScoped(context.Background(), owner, fmt.Sprint(n), CreateRequest{})
			if err == nil {
				admitted.Add(1)
				results <- r
			} else if !errors.Is(err, ErrTenantCapacity) {
				t.Errorf("admission: %v", err)
			}
		}(n)
	}
	wg.Wait()
	close(results)
	if admitted.Load() != 3 {
		t.Fatalf("non-atomic tenant quota: %d", admitted.Load())
	}
	for r := range results {
		if _, err := m.Destroy(r.Ref); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-d.entered:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not start")
	}
	if _, err := m.CreateScoped(context.Background(), owner, "after-delete", CreateRequest{}); !errors.Is(err, ErrTenantCapacity) {
		t.Fatalf("quota returned before reclamation: %v", err)
	}
	if _, err := m.CreateScoped(context.Background(), Owner{TenantID: "beta", MaxInstances: 1}, "new", CreateRequest{}); err != nil {
		t.Fatalf("tenant quota leaked across tenants: %v", err)
	}
}

func TestScopedOperationsHideOtherTenant(t *testing.T) {
	m, _, _ := setup(t, Options{}, nil)
	r, err := m.CreateScoped(context.Background(), Owner{TenantID: "alpha", MaxInstances: 2}, "one", CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	j := execDone(t, m, r, "echo", "private")
	_, getErr := m.GetScoped("beta", r.ID)
	_, execErr := m.ExecScoped("beta", r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo"}})
	_, jobErr := m.GetJobScoped("beta", r.ID, j.ID)
	_, stopErr := m.StopScoped(context.Background(), "beta", r.Ref)
	_, destroyErr := m.DestroyScoped("beta", r.Ref)
	for _, err := range []error{getErr, execErr, jobErr, stopErr, destroyErr} {
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("ownership bypass: %v", err)
		}
	}
	current, _ := m.Get(r.ID)
	if current.State != Ready {
		t.Fatal("unauthorized lifecycle mutation")
	}
}

func TestIdempotencySurvivesRestartWithoutResurrection(t *testing.T) {
	m, base, store := setup(t, Options{}, nil)
	owner := Owner{TenantID: "alpha", MaxInstances: 2}
	r, err := m.CreateScoped(context.Background(), owner, "persistent", CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.Close(ctx); err != nil {
		t.Fatal(err)
	}
	driver, err := NewMockDriver(filepath.Join(base, "instances"))
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewManager(store, driver, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close(ctx)
	if _, err := next.CreateScoped(ctx, owner, "persistent", CreateRequest{}); !errors.Is(err, ErrIdempotencyGone) {
		t.Fatalf("restart reused key: %v", err)
	}
	if current, err := next.GetScoped("alpha", r.ID); err != nil || current.State != Destroyed {
		t.Fatalf("lost durable ownership: %+v %v", current, err)
	}
}

type ambiguousOwnershipStore struct {
	Store
	fail atomic.Bool
}

func (s *ambiguousOwnershipStore) Save(r Record) error {
	if err := s.Store.Save(r); err != nil {
		return err
	}
	if r.State == Creating && s.fail.Swap(false) {
		return errors.New("injected error after committed rename")
	}
	return nil
}

func TestAmbiguousInitialCommitKeepsIdempotencyReservation(t *testing.T) {
	base := t.TempDir()
	fs, err := NewFileStore(filepath.Join(base, "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	store := &ambiguousOwnershipStore{Store: fs}
	store.fail.Store(true)
	driver, err := NewMockDriver(filepath.Join(base, "instances"))
	if err != nil {
		t.Fatal(err)
	}
	d := &countingPrepare{Driver: driver}
	m, err := NewManager(store, d, Options{ReapInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	defer m.Close(ctx)
	owner := Owner{TenantID: "alpha", MaxInstances: 1}
	if _, err := m.CreateScoped(ctx, owner, "ambiguous", CreateRequest{}); err == nil {
		t.Fatal("ambiguous commit reported success")
	}
	if d.calls.Load() != 0 {
		t.Fatal("resources prepared after durability error")
	}
	if _, err := m.CreateScoped(ctx, owner, "ambiguous", CreateRequest{}); !errors.Is(err, ErrIdempotencyGone) {
		t.Fatalf("ambiguous key forgotten: %v", err)
	}
	eventually(t, func() bool { return m.Stats().Active == 0 })
	rows, err := store.Load()
	if err != nil || len(rows) != 1 || rows[0].State != Destroyed || rows[0].CreateKeyHash == "" {
		t.Fatalf("durable tombstone missing: %+v %v", rows, err)
	}
}

func TestRejectInvalidOwnershipAndKeys(t *testing.T) {
	m, _, _ := setup(t, Options{}, nil)
	for _, owner := range []Owner{{}, {TenantID: "../alpha", MaxInstances: 1}, {TenantID: "alpha", MaxInstances: 0}} {
		if _, err := m.CreateScoped(context.Background(), owner, "key", CreateRequest{}); !errors.Is(err, ErrInvalid) {
			t.Errorf("owner accepted: %+v %v", owner, err)
		}
	}
	for _, key := range []string{"with space", "with\nnewline", strings.Repeat("k", 129), "非ASCII"} {
		if _, err := m.CreateScoped(context.Background(), Owner{TenantID: "alpha", MaxInstances: 1}, key, CreateRequest{}); !errors.Is(err, ErrInvalid) {
			t.Errorf("key accepted: %q %v", key, err)
		}
	}
}

type snapshotStore struct{ records []Record }

func (s snapshotStore) Load() ([]Record, error) { return append([]Record(nil), s.records...), nil }
func (s snapshotStore) Save(Record) error       { return nil }

func TestLoadValidatesOwnershipAndKeyMetadata(t *testing.T) {
	driver, err := NewMockDriver(filepath.Join(t.TempDir(), "instances"))
	if err != nil {
		t.Fatal(err)
	}
	base := Record{Ref: Ref{ID: strings.Repeat("1", 32), Generation: strings.Repeat("2", 32)}, Backend: "mock", State: Destroyed, TenantID: "alpha"}
	keyed := base
	keyed.CreateKeyHash = strings.Repeat("a", 64)
	keyed.CreateSpecHash = strings.Repeat("b", 64)
	duplicate := keyed
	duplicate.ID = strings.Repeat("3", 32)
	badTenant := base
	badTenant.TenantID = "../alpha"
	missingSpec := keyed
	missingSpec.CreateSpecHash = ""
	badHash := keyed
	badHash.CreateKeyHash = "not-a-digest"
	for _, rows := range [][]Record{{badTenant}, {missingSpec}, {badHash}, {keyed, duplicate}} {
		if m, err := NewManager(snapshotStore{rows}, driver, Options{}); err == nil {
			m.cancel()
			<-m.workerDone
			t.Fatalf("invalid ledger metadata accepted: %+v", rows)
		}
	}
	legacy := base
	legacy.TenantID = ""
	m, err := NewManager(snapshotStore{[]Record{legacy}}, driver, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	defer m.Close(ctx)
	if r, err := m.GetScoped("local", legacy.ID); err != nil || r.TenantID != "local" {
		t.Fatalf("legacy local owner migration: %+v %v", r, err)
	}
}
