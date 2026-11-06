package sandbox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/telemetry"
)

// Deterministic control-plane/Mock tests, not Firecracker or latency evidence.
type queuedCreateReply struct {
	record Record
	err    error
}

// The FIFO/order and deadline-identity proofs have NO storage/VM I/O. Neither is a
// durability or physical reclamation test; those retain real FileStore/Mock
// resources in TestCreateCapacityQueueRequiresDurableDestroyedBeforeGrant.
// Do not make this proof depend on a disk completing unrelated fsyncs within
// the two-second test deadline, or increase that deadline to mask contention.
type queueOrderingStore struct{}

func (queueOrderingStore) Load() ([]Record, error) { return nil, nil }
func (queueOrderingStore) Save(Record) error       { return nil }

type queueOrderingDriver struct{ calls atomic.Int32 }

func (*queueOrderingDriver) Name() string           { return "mock" }
func (*queueOrderingDriver) RefreshLease(Ref) error { return nil }
func (*queueOrderingDriver) RevokeLease(Ref) error  { return nil }
func (d *queueOrderingDriver) Prepare(ctx context.Context, _ Ref, _ Preparation) error {
	d.calls.Add(1)
	return ctx.Err()
}
func (*queueOrderingDriver) Exec(context.Context, Ref, ExecRequest, int) (Output, error) {
	return Output{}, ErrNotReady
}
func (*queueOrderingDriver) Stop(ctx context.Context, _ Ref) error    { return ctx.Err() }
func (*queueOrderingDriver) Cleanup(ctx context.Context, _ Ref) error { return ctx.Err() }

func queueOrderingManager(t *testing.T) (*Manager, *queueOrderingDriver) {
	t.Helper()
	d := &queueOrderingDriver{}
	return queueOrderingManagerWithDriver(t, d), d
}

func queueOrderingManagerWithDriver(t *testing.T, d Driver) *Manager {
	t.Helper()
	m, err := NewManager(queueOrderingStore{}, d, Options{MaxInstances: 1, ReapInterval: 5 * time.Millisecond, RetryDelay: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return m
}

func startQueuedCreate(f func() (Record, error)) <-chan queuedCreateReply {
	done := make(chan queuedCreateReply, 1)
	go func() { r, err := f(); done <- queuedCreateReply{r, err} }()
	return done
}

func queueCaller(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx, cancel
}

func waitCreateQueued(t *testing.T, m *Manager, n int, pending ...<-chan queuedCreateReply) {
	t.Helper()
	eventually(t, func() bool {
		for _, ch := range pending {
			select {
			case reply := <-ch:
				t.Fatalf("future capacity was refused or allocated before release: state=%s err=%v", reply.record.State, reply.err)
			default:
			}
		}
		return m.Metrics().CreateQueued == int64(n)
	})
}

func queuedReply(t *testing.T, ch <-chan queuedCreateReply, want error) Record {
	t.Helper()
	select {
	case v := <-ch:
		if (want == nil && v.err != nil) || (want != nil && !errors.Is(v.err, want)) {
			t.Fatalf("queued reply: state=%s err=%v want=%v", v.record.State, v.err, want)
		}
		if want != nil && v.record.Ref != (Ref{}) {
			t.Fatal("pre-reservation refusal exposed an allocated Ref")
		}
		return v.record
	case <-time.After(3 * time.Second):
		t.Fatal("queued create did not settle")
		return Record{}
	}
}

func TestCreateCapacityQueueFIFOAndIndependentClassBounds(t *testing.T) {
	m, d := queueOrderingManager(t)
	owner := Owner{TenantID: "alpha", MaxInstances: 1}
	held, err := m.CreateScoped(context.Background(), owner, "held", CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, _ := queueCaller(t)
	permit := NewAdmission(func(Ref) bool { return true })
	var captured atomic.Int32
	managed := startQueuedCreate(func() (Record, error) {
		return m.CreateManagedScoped(ctx, owner, "first-managed", CreateRequest{}, permit, func(Ref) { captured.Add(1) })
	})
	waitCreateQueued(t, m, 1, managed)
	raw := startQueuedCreate(func() (Record, error) { return m.CreateScoped(ctx, owner, "second-raw", CreateRequest{}) })
	waitCreateQueued(t, m, 2, managed, raw)
	// A full raw queue must not occupy the managed waiting positions. This
	// partitions WAITING bounds, not VM slots or priorities; N is still ONE.
	for n := range 16 {
		r, e := m.CreateScoped(ctx, owner, fmt.Sprintf("raw-overflow-%d", n), CreateRequest{})
		if !errors.Is(e, ErrCapacity) || r.Ref != (Ref{}) {
			t.Fatal("full class did not shed new work", e)
		}
	}
	if d.calls.Load() != 1 || captured.Load() != 0 || m.Metrics().Records != 1 || m.Metrics().Allocated != 1 {
		t.Fatal("waiting/overflow allocated resources or metadata")
	}
	if _, err = m.Destroy(held.Ref); err != nil {
		t.Fatal(err)
	}
	first := queuedReply(t, managed, nil) // The earlier transactional waiter wins.
	waitCreateQueued(t, m, 1, raw)
	newManaged := startQueuedCreate(func() (Record, error) {
		return m.CreateManagedScoped(ctx, owner, "third-managed", CreateRequest{}, permit, func(Ref) { captured.Add(1) })
	})
	waitCreateQueued(t, m, 2, raw, newManaged)
	if _, err = m.Destroy(first.Ref); err != nil {
		t.Fatal(err)
	}
	second := queuedReply(t, raw, nil) // Later managed arrivals cannot steal the raw turn.
	waitCreateQueued(t, m, 1, newManaged)
	if captured.Load() != 1 || d.calls.Load() != 3 || m.Metrics().Allocated != 1 {
		t.Fatal("unbounded or duplicated reservation")
	}
	if _, err = m.Destroy(second.Ref); err != nil {
		t.Fatal(err)
	}
	queuedReply(t, newManaged, nil)
	if d.calls.Load() != 4 || m.Metrics().CreateQueued != 0 {
		t.Fatal("queue did not drain without retry")
	}
}

func TestCreateCapacityQueueSkipsQuotaBlockedTenant(t *testing.T) {
	m, _, _ := setup(t, Options{MaxInstances: 2}, nil)
	a := Owner{TenantID: "alpha", MaxInstances: 1}
	b := Owner{TenantID: "beta", MaxInstances: 1}
	c := Owner{TenantID: "gamma", MaxInstances: 1}
	if _, err := m.CreateScoped(context.Background(), a, "held", CreateRequest{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := queueCaller(t)
	blocked := startQueuedCreate(func() (Record, error) {
		return m.CreateManagedScoped(ctx, a, "blocked", CreateRequest{}, NewAdmission(func(Ref) bool { return true }), func(Ref) {})
	})
	waitCreateQueued(t, m, 1, blocked)
	// The FIFO head is tenant-quota blocked, not globally capacity blocked.
	other, err := m.CreateScoped(context.Background(), b, "bypass-ineligible", CreateRequest{})
	if err != nil {
		t.Fatal("one tenant blocked available capacity for another", err)
	}
	ctx2, _ := queueCaller(t)
	next := startQueuedCreate(func() (Record, error) { return m.CreateScoped(ctx2, c, "next", CreateRequest{}) })
	waitCreateQueued(t, m, 2, blocked, next)
	if _, err = m.Destroy(other.Ref); err != nil {
		t.Fatal(err)
	}
	queuedReply(t, next, nil)
	waitCreateQueued(t, m, 1, blocked)
	cancel()
	queuedReply(t, blocked, context.Canceled)
	if m.Metrics().CreateQueued != 0 || m.Metrics().Records != 3 || m.Metrics().Allocated != 2 {
		t.Fatal("blocked/cancelled waiter consumed ownership")
	}
}

func TestCreateCapacityQueueDrainHonorsAcceptedTicketOnly(t *testing.T) {
	g := NewAdmissionGate(true)
	m, _, _ := setup(t, Options{MaxInstances: 1, AdmissionGate: g}, nil)
	owner := Owner{TenantID: "alpha", MaxInstances: 1}
	held := create(t, m, CreateRequest{})
	var ticket *CreationTicket
	if err := m.ReserveSessionAttempt(func(v *CreationTicket) { ticket = v }); err != nil {
		t.Fatal(err)
	}
	ctx, _ := queueCaller(t)
	permit := NewAdmission(func(Ref) bool { return true })
	accepted := startQueuedCreate(func() (Record, error) {
		return m.CreateReservedManagedScoped(ctx, owner, "accepted", CreateRequest{}, permit, func(Ref) {}, ticket)
	})
	waitCreateQueued(t, m, 1, accepted)
	raw := startQueuedCreate(func() (Record, error) { return m.CreateScoped(ctx, owner, "raw", CreateRequest{}) })
	waitCreateQueued(t, m, 2, raw, accepted)
	g.SetOpen(false)
	queuedReply(t, raw, ErrDraining)
	waitCreateQueued(t, m, 1, accepted)
	if g.Pending() != 1 || m.Metrics().Allocated != 1 {
		t.Fatal("drain consumed or allocated a queued ticket")
	}
	if _, err := m.Destroy(held.Ref); err != nil {
		t.Fatal(err)
	}
	queuedReply(t, accepted, nil)
	if g.Pending() != 0 || m.Metrics().CreateQueued != 0 || m.Metrics().Allocated != 1 {
		t.Fatal("accepted ticket did not complete exactly once after drain")
	}
}

func TestCreateCapacityQueueReleasedForeignAndUsedTicketsNeverWait(t *testing.T) {
	g := NewAdmissionGate(true)
	m, _, _ := setup(t, Options{MaxInstances: 1, AdmissionGate: g}, nil)
	create(t, m, CreateRequest{})
	var ticket *CreationTicket
	if err := m.ReserveSessionAttempt(func(v *CreationTicket) { ticket = v }); err != nil {
		t.Fatal(err)
	}
	ctx, _ := queueCaller(t)
	permit := NewAdmission(func(Ref) bool { return true })
	done := startQueuedCreate(func() (Record, error) {
		return m.CreateReservedManagedScoped(ctx, Owner{TenantID: "alpha", MaxInstances: 1}, "accepted", CreateRequest{}, permit, func(Ref) { t.Error("released ticket allocated") }, ticket)
	})
	waitCreateQueued(t, m, 1, done)
	ticket.Release()
	queuedReply(t, done, ErrInvalid)
	foreign := &CreationTicket{gate: NewAdmissionGate(true)}
	used := &CreationTicket{gate: g, used: true}
	for _, bad := range []*CreationTicket{ticket, foreign, used} {
		if _, err := m.CreateReservedManagedScoped(ctx, Owner{TenantID: "alpha", MaxInstances: 1}, "invalid", CreateRequest{}, permit, func(Ref) { t.Error("invalid ticket allocated") }, bad); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid ticket did not fail before capacity waiting", err)
		}
	}
	if g.Pending() != 0 || m.Metrics().CreateQueued != 0 || m.Metrics().Records != 1 {
		t.Fatal("ticket return/validation leaked queue or metadata")
	}
}

func TestCreateCapacityQueueCloseCancelsUnallocatedWaiters(t *testing.T) {
	d := &countingPrepare{}
	m, _, _ := setup(t, Options{MaxInstances: 1}, func(base Driver) Driver { d.Driver = base; return d })
	create(t, m, CreateRequest{})
	ctx, _ := queueCaller(t)
	done := startQueuedCreate(func() (Record, error) {
		return m.CreateManagedScoped(ctx, Owner{TenantID: "alpha", MaxInstances: 1}, "queued", CreateRequest{}, NewAdmission(func(Ref) bool { return true }), func(Ref) {})
	})
	waitCreateQueued(t, m, 1, done)
	closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := m.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
	queuedReply(t, done, ErrClosing)
	if m.Metrics().CreateQueued != 0 || d.calls.Load() != 1 || m.Metrics().Records != 1 || m.Metrics().Allocated != 0 {
		t.Fatal("close allowed an unallocated waiter to create")
	}
}

func TestCreateCapacityQueueTimeoutIsPreReservationCapacityRefusal(t *testing.T) {
	d := &countingPrepare{}
	m, _, _ := setup(t, Options{MaxInstances: 1, CapacityWaitTimeout: 5 * time.Millisecond}, func(base Driver) Driver { d.Driver = base; return d })
	create(t, m, CreateRequest{})
	for _, tenant := range []bool{false, true} {
		owner := Owner{TenantID: "alpha", MaxInstances: 1}
		want := ErrCapacity
		if tenant {
			// Exercise tenant capacity independently from global capacity.
			m2, _, _ := setup(t, Options{MaxInstances: 2, CapacityWaitTimeout: 5 * time.Millisecond}, nil)
			if _, err := m2.CreateScoped(context.Background(), owner, "held", CreateRequest{}); err != nil {
				t.Fatal(err)
			}
			m = m2
			want = ErrTenantCapacity
		}
		r, err := m.CreateManagedScoped(context.Background(), owner, "timeout", CreateRequest{}, NewAdmission(func(Ref) bool { return true }), func(Ref) {})
		if !errors.Is(err, want) || r.Ref != (Ref{}) || m.Metrics().CreateQueued != 0 || m.Metrics().Records != 1 || m.Metrics().Allocated != 1 {
			t.Fatal("capacity deadline was converted to allocated failure", err)
		}
	}
	if d.calls.Load() != 1 {
		t.Fatal("timed-out waiter entered driver")
	}
}

func TestCreateCapacityQueueDuplicateKeysReplayWithoutSecondReservation(t *testing.T) {
	d := &countingPrepare{}
	m, _, _ := setup(t, Options{MaxInstances: 2}, func(base Driver) Driver { d.Driver = base; return d })
	owner := Owner{TenantID: "alpha", MaxInstances: 2}
	a, err := m.CreateScoped(context.Background(), owner, "held-a", CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.CreateScoped(context.Background(), owner, "held-b", CreateRequest{}); err != nil {
		t.Fatal(err)
	}
	ctx, _ := queueCaller(t)
	permit := NewAdmission(func(Ref) bool { return true })
	call := func() (Record, error) {
		return m.CreateManagedScoped(ctx, owner, "same", CreateRequest{}, permit, func(Ref) {})
	}
	first := startQueuedCreate(call)
	waitCreateQueued(t, m, 1, first)
	second := startQueuedCreate(call)
	waitCreateQueued(t, m, 2, first, second)
	if replay, err := m.CreateScoped(ctx, owner, "held-a", CreateRequest{}); err != nil || replay.Ref != a.Ref {
		t.Fatal("accepted replay waited behind a full queue", err)
	}
	if _, err := m.CreateScoped(ctx, owner, "held-a", CreateRequest{TTLMS: 10_000}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatal("conflicting replay changed ownership", err)
	}
	if _, err = m.Destroy(a.Ref); err != nil {
		t.Fatal(err)
	}
	r1, r2 := queuedReply(t, first, nil), queuedReply(t, second, nil)
	if r1.Ref != r2.Ref || d.calls.Load() != 3 || m.Metrics().Records != 3 || m.Metrics().Allocated != 2 || m.Metrics().CreateQueued != 0 {
		t.Fatal("queued duplicate reallocated or leaked a waiting position")
	}
}

func TestCreateCapacityQueueRequiresDurableDestroyedBeforeGrant(t *testing.T) {
	m, store := faultManager(t)
	held := create(t, m, CreateRequest{})
	store.failDestroyed.Store(true)
	if _, err := m.Destroy(held.Ref); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		r, _ := m.Get(held.ID)
		return r.State == Reclaiming && r.LastError != ""
	}) // Cleanup returned, but the durable Destroyed write failed.
	ctx, _ := queueCaller(t)
	var captured atomic.Int32
	done := startQueuedCreate(func() (Record, error) {
		return m.CreateManagedScoped(ctx, Owner{TenantID: "alpha", MaxInstances: 1}, "next", CreateRequest{}, NewAdmission(func(Ref) bool { return true }), func(Ref) { captured.Add(1) })
	})
	waitCreateQueued(t, m, 1, done)
	if captured.Load() != 0 || m.Metrics().Allocated != 1 || m.Metrics().Records != 1 {
		t.Fatal("physical cleanup alone returned capacity")
	}
	store.failDestroyed.Store(false)
	queuedReply(t, done, nil)
	if captured.Load() != 1 || m.Metrics().Allocated != 1 || m.Metrics().Records != 2 || m.Metrics().CreateQueued != 0 {
		t.Fatal("durable capacity grant was not single-use")
	}
}

type queueDeadlineDriver struct {
	Driver
	calls    atomic.Int32
	deadline chan time.Time
}

func (d *queueDeadlineDriver) Prepare(ctx context.Context, ref Ref, p Preparation) error {
	if d.calls.Add(1) > 1 {
		deadline, _ := ctx.Deadline()
		d.deadline <- deadline
	}
	return d.Driver.Prepare(ctx, ref, p)
}

func TestCreateCapacityQueueSharesOriginalPrepareDeadline(t *testing.T) {
	d := &queueDeadlineDriver{Driver: &queueOrderingDriver{}, deadline: make(chan time.Time, 1)}
	m := queueOrderingManagerWithDriver(t, d)
	held := create(t, m, CreateRequest{})
	ctx, _ := queueCaller(t)
	done := startQueuedCreate(func() (Record, error) {
		return m.CreateManagedScoped(ctx, Owner{TenantID: "alpha", MaxInstances: 1}, "next", CreateRequest{}, NewAdmission(func(Ref) bool { return true }), func(Ref) {})
	})
	waitCreateQueued(t, m, 1, done)
	m.mu.Lock()
	deadline, hasDeadline := m.createQueue[0].ctx.Deadline()
	m.mu.Unlock()
	if !hasDeadline {
		t.Fatal("unbounded capacity wait")
	}
	if _, err := m.Destroy(held.Ref); err != nil {
		t.Fatal(err)
	}
	queuedReply(t, done, nil)
	if actual := <-d.deadline; !actual.Equal(deadline) {
		t.Fatal("prepare got a NEW timeout after capacity waiting")
	}
}

func TestCreateCapacityQueueBoundsAndLockFreeMetrics(t *testing.T) {
	m, _, _ := setup(t, Options{MaxInstances: 1}, nil)
	create(t, m, CreateRequest{})
	ctx, cancel := queueCaller(t)
	raw := startQueuedCreate(func() (Record, error) {
		return m.CreateManagedScoped(ctx, Owner{TenantID: "alpha", MaxInstances: 1}, "raw", CreateRequest{}, NewAdmission(func(Ref) bool { return true }), func(Ref) {})
	})
	waitCreateQueued(t, m, 1, raw)
	m.mu.Lock()
	metrics := make(chan telemetry.Gauges, 1)
	go func() { metrics <- m.Metrics() }()
	var g telemetry.Gauges
	select {
	case g = <-metrics:
	case <-time.After(time.Second):
		t.Error("queue metrics took lifecycle lock")
	}
	m.mu.Unlock()
	if g.CreateQueued != 1 || g.CreateQueueCapacity != 2 || g.CreateClassQueueCapacity != 1 {
		t.Fatal("queue gauge/bounds differ", g)
	}
	s := string((*telemetry.Registry)(nil).Render(g))
	for _, line := range []string{"xandbox_create_queued 1\n", "xandbox_create_queue_capacity 2\n", "xandbox_create_queue_capacity_per_class 1\n"} {
		if !strings.Contains(s, line) {
			t.Fatal("missing fixed-cardinality queue metric", line)
		}
	}
	cancel()
	queuedReply(t, raw, context.Canceled)
	if m.Metrics().CreateQueued != 0 {
		t.Fatal("cancelled waiter left a queue charge")
	}
	// The hard upper bound is independent of untrusted request volume.
	large := &Manager{opts: Options{MaxInstances: 10_000}}
	if large.createQueueCapacity() != 256 || large.createClassQueueCapacity() != 128 || large.tenantCreateQueueCapacity(Owner{MaxInstances: 1}) != 1 {
		t.Fatal("queue bounds are not finite or tenant-scoped")
	}
}

func TestCreateCapacityQueueTimeoutOptionNeverExtendsPrepare(t *testing.T) {
	for _, wait := range []time.Duration{-time.Nanosecond, 2 * time.Second} {
		if _, err := NewManager(nil, nil, Options{PrepareTimeout: time.Second, CapacityWaitTimeout: wait}); err == nil {
			t.Fatal("invalid/extended capacity timeout accepted")
		}
	}
}

func TestCreateCapacityQueueTenantPendingBounds(t *testing.T) {
	m, _, _ := setup(t, Options{MaxInstances: 2}, nil)
	holder := Owner{TenantID: "holder", MaxInstances: 2}
	for n := range 2 {
		if _, err := m.CreateScoped(context.Background(), holder, fmt.Sprintf("held-%d", n), CreateRequest{}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := queueCaller(t)
	owner := Owner{TenantID: "alpha", MaxInstances: 1}
	permit := NewAdmission(func(Ref) bool { return true })
	managed := startQueuedCreate(func() (Record, error) {
		return m.CreateManagedScoped(ctx, owner, "managed", CreateRequest{}, permit, func(Ref) { t.Error("pending candidate allocated") })
	})
	waitCreateQueued(t, m, 1, managed)
	raw := startQueuedCreate(func() (Record, error) { return m.CreateScoped(ctx, owner, "raw", CreateRequest{}) })
	waitCreateQueued(t, m, 2, managed, raw)
	if _, err := m.CreateScoped(ctx, owner, "tenant-overflow", CreateRequest{}); !errors.Is(err, ErrTenantCapacity) {
		t.Fatal("tenant occupied extra raw waiting positions", err)
	}
	waitCreateQueued(t, m, 2, raw, managed)
	if _, err := m.CreateManagedScoped(ctx, owner, "managed-overflow", CreateRequest{}, permit, func(Ref) { t.Error("overflow allocated") }); !errors.Is(err, ErrTenantCapacity) {
		t.Fatal("tenant occupied extra managed waiting positions", err)
	}
	cancel()
	queuedReply(t, raw, context.Canceled)
	queuedReply(t, managed, context.Canceled)
	if m.Metrics().CreateQueued != 0 || m.Metrics().Records != 2 || m.Metrics().Allocated != 2 {
		t.Fatal("pending limits consumed or leaked resource ownership")
	}
}

func TestCreateCapacityQueueIndependentBoundsAndRawOnlyRefusal(t *testing.T) {
	for _, managedFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("managed_first_%t", managedFirst), func(t *testing.T) {
			m, _, _ := setup(t, Options{MaxInstances: 1}, nil)
			create(t, m, CreateRequest{})
			ctx, cancel := queueCaller(t)
			owner := Owner{TenantID: "alpha", MaxInstances: 1}
			permit := NewAdmission(func(Ref) bool { return true })
			call := func(managed bool, key string) (Record, error) {
				if managed {
					return m.CreateManagedScoped(ctx, owner, key, CreateRequest{}, permit, func(Ref) { t.Error("unreleased capacity allocated") })
				}
				return m.CreateScoped(ctx, owner, key, CreateRequest{})
			}
			if !managedFirst {
				if r, err := call(false, "raw-alone"); !errors.Is(err, ErrCapacity) || r.Ref != (Ref{}) || m.Metrics().CreateQueued != 0 {
					t.Fatal("raw alone must preserve immediate capacity refusal", err)
				}
			}
			first := startQueuedCreate(func() (Record, error) { return call(true, "first") })
			waitCreateQueued(t, m, 1, first)
			second := startQueuedCreate(func() (Record, error) { return call(false, "second") })
			waitCreateQueued(t, m, 2, first, second)
			for _, class := range []bool{false, true} {
				if r, err := call(class, "overflow"); !errors.Is(err, ErrCapacity) || r.Ref != (Ref{}) {
					t.Fatal("class bound/overflow is not symmetric", err)
				}
			}
			cancel()
			queuedReply(t, first, context.Canceled)
			queuedReply(t, second, context.Canceled)
			if m.Metrics().CreateQueued != 0 || m.Metrics().Records != 1 {
				t.Fatal("class queue cancellation leaked metadata")
			}
		})
	}
}
