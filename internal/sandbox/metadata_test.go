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
	"unicode/utf8"

	"github.com/123123213weqw/Xandbox/internal/hostclock"
)

func TestMetadataAdmissionAtomicAndKeysWinAtCapacity(t *testing.T) {
	d := &countingPrepare{}
	m, _, _ := setup(t, Options{MaxRecords: 3, MaxTenantRecords: 3, MaxInstances: 64}, func(base Driver) Driver { d.Driver = base; return d })
	owner := Owner{TenantID: "alpha", MaxInstances: 64}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for n := 0; n < 32; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, e := m.CreateScoped(context.Background(), owner, fmt.Sprint(n), CreateRequest{})
			if e == nil {
				accepted.Add(1)
			} else if !errors.Is(e, ErrMetadataCapacity) {
				t.Error(e)
			}
		}(n)
	}
	wg.Wait()
	if accepted.Load() != 3 || d.calls.Load() != 3 || m.Stats().Records != 3 {
		t.Fatal("record capacity race", m.Stats(), d.calls.Load())
	}
	m.mu.Lock()
	var first *instance
	for _, i := range m.records {
		first = i
		break
	}
	m.mu.Unlock()
	// Find this chosen record's key without reading private digests via the API.
	for n := 0; n < 32; n++ {
		kh, _, _ := createHashes(fmt.Sprint(n), mustNormalize(t, CreateRequest{}))
		first.mu.Lock()
		savedKey := first.record.CreateKeyHash
		first.mu.Unlock()
		if kh != savedKey {
			continue
		}
		r, e := m.CreateScoped(context.Background(), owner, fmt.Sprint(n), CreateRequest{})
		if e != nil || r.Ref != first.ref {
			t.Fatal("live key retry blocked by metadata quota", r, e)
		}
		if _, e = m.Destroy(r.Ref); e != nil {
			t.Fatal(e)
		}
		waitState(t, m, r.ID, Destroyed)
		if _, e = m.CreateScoped(context.Background(), owner, fmt.Sprint(n), CreateRequest{}); !errors.Is(e, ErrIdempotencyGone) {
			t.Fatal("destroyed key recreated at cap", e)
		}
	}
	if _, e := m.CreateScoped(context.Background(), owner, "fresh", CreateRequest{}); !errors.Is(e, ErrMetadataCapacity) {
		t.Fatal("destroy freed metadata slot", e)
	}
}
func mustNormalize(t *testing.T, r CreateRequest) CreateRequest {
	t.Helper()
	r, e := normalizeCreate(r)
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func TestTenantMetadataBudgetDoesNotConsumeAnotherTenantBudget(t *testing.T) {
	m, _, _ := setup(t, Options{MaxRecords: 3, MaxTenantRecords: 1}, nil)
	alpha, beta := Owner{TenantID: "alpha", MaxInstances: 2}, Owner{TenantID: "beta", MaxInstances: 2}
	a, e := m.CreateScoped(context.Background(), alpha, "a", CreateRequest{})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Destroy(a.Ref); e != nil {
		t.Fatal(e)
	}
	waitState(t, m, a.ID, Destroyed)
	if _, e = m.CreateScoped(context.Background(), alpha, "a2", CreateRequest{}); !errors.Is(e, ErrTenantMetadataCapacity) {
		t.Fatal(e)
	}
	if _, e = m.CreateScoped(context.Background(), beta, "b", CreateRequest{}); e != nil {
		t.Fatal(e)
	}
}

func TestLoweredMetadataLimitsStillRecoverEveryOwnedGeneration(t *testing.T) {
	base := t.TempDir()
	store, e := NewFileStore(filepath.Join(base, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	d, e := NewMockDriver(filepath.Join(base, "instances"))
	if e != nil {
		t.Fatal(e)
	}
	now, e := hostclock.NowNS()
	if e != nil {
		t.Fatal(e)
	}
	for n := 1; n <= 2; n++ {
		r := ledgerFixture(n)
		r.State = Ready
		r.StoppedAt = time.Time{}
		r.DestroyedAt = time.Time{}
		r.DeleteRequested = false
		if e = store.Save(r); e != nil {
			t.Fatal(e)
		}
		if e = d.Prepare(context.Background(), r.Ref, Preparation{Limits: r.Limits, DeadlineNS: now + int64(time.Minute)}); e != nil {
			t.Fatal(e)
		}
	}
	m, e := NewManager(store, d, Options{MaxRecords: 1, MaxTenantRecords: 1, MaxInstances: 1, ReapInterval: time.Millisecond})
	if e != nil {
		t.Fatal("lowered limit prevented recovery", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	defer m.Close(ctx)
	for n := 1; n <= 2; n++ {
		waitState(t, m, ledgerFixture(n).ID, Destroyed)
	}
	if m.Stats().Records != 2 {
		t.Fatal("over-budget records forgotten", m.Stats())
	}
	if _, e = m.Create(context.Background(), CreateRequest{}); !errors.Is(e, ErrMetadataCapacity) {
		t.Fatal(e)
	}
}

func TestAmbiguousCommitRetainsMetadataSlotAndNeverPrepares(t *testing.T) {
	base := t.TempDir()
	fs, e := NewFileStore(filepath.Join(base, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	store := &ambiguousOwnershipStore{Store: fs}
	store.fail.Store(true)
	driver, e := NewMockDriver(filepath.Join(base, "instances"))
	if e != nil {
		t.Fatal(e)
	}
	d := &countingPrepare{Driver: driver}
	m, e := NewManager(store, d, Options{MaxRecords: 1, ReapInterval: time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	defer m.Close(ctx)
	if _, e = m.Create(context.Background(), CreateRequest{}); e == nil {
		t.Fatal("ambiguous save succeeded")
	}
	eventually(t, func() bool { return m.Stats().Active == 0 })
	if d.calls.Load() != 0 || m.Stats().Records != 1 {
		t.Fatal("ambiguous identity forgotten or prepared", m.Stats())
	}
	if _, e = m.Create(context.Background(), CreateRequest{}); !errors.Is(e, ErrMetadataCapacity) {
		t.Fatal(e)
	}
}

func TestLedgerErrorsBoundedBeforePrivatePersistence(t *testing.T) {
	m, _, _ := setup(t, Options{}, nil)
	r := create(t, m, CreateRequest{})
	i, _ := m.lookup(r.ID)
	m.failed(i, errors.New(strings.Repeat("\xff中", 100_000)))
	r, e := m.Get(r.ID)
	if e != nil || len(r.LastError) > MaxLedgerErrorBytes || !utf8.ValidString(r.LastError) || !strings.HasSuffix(r.LastError, "...[truncated]") {
		t.Fatal("unbounded/private error", e, len(r.LastError))
	}
}

func TestMetadataOptionBounds(t *testing.T) {
	_, _, s := setup(t, Options{}, nil)
	d, _ := NewMockDriver(filepath.Join(t.TempDir(), "mock"))
	for _, o := range []Options{{MaxRecords: -1}, {MaxRecords: MaxLedgerRecords + 1}, {MaxTenantRecords: -1}, {MaxRecords: 1, MaxTenantRecords: 2}} {
		if m, e := NewManager(s, d, o); e == nil {
			m.cancel()
			<-m.workerDone
			t.Fatal("invalid metadata limits accepted", o)
		}
	}
}
