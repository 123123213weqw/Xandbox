package sandbox

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// Memory-only resource-turn controls. No real VM, filesystem, cost/timing model
// or assertion that this request mix completes a physical 35-second actor.
func demandManager(t *testing.T, n int) (*Manager, *queueOrderingDriver, []Record) {
	t.Helper()
	d := &queueOrderingDriver{}
	m, err := NewManager(queueOrderingStore{}, d, Options{MaxInstances: n, ReapInterval: time.Millisecond, RetryDelay: time.Millisecond})
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
	var held []Record
	for index := range n {
		r, err := m.CreateScoped(context.Background(), Owner{TenantID: "holder", MaxInstances: n}, fmt.Sprintf("held-%d", index), CreateRequest{})
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, r)
	}
	return m, d, held
}

func demandRelease(t *testing.T, m *Manager, ref Ref) {
	t.Helper()
	if _, err := m.Destroy(ref); err != nil {
		t.Fatal(err)
	}
	// This is an in-memory fake store/driver. Real durable release barriers
	// remain separately tested by the existing failure-store controls.
	eventually(t, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.active[ref.ID] == nil
	})
}

func demandRejectWithoutQueueGrowth(t *testing.T, m *Manager, before int64, done <-chan queuedCreateReply) {
	t.Helper()
	var reply queuedCreateReply
	eventually(t, func() bool {
		select {
		case reply = <-done:
			return true
		default:
			if actual := m.Metrics().CreateQueued; actual > before {
				t.Fatalf("pending caller bound exceeded: before=%d actual=%d allocated=%d", before, actual, m.Metrics().Allocated)
			}
			return false
		}
	})
	if !errors.Is(reply.err, ErrTenantCapacity) || reply.record.Ref != (Ref{}) {
		t.Fatal("different intent was not refused before reservation", reply.err)
	}
}

func TestCreateDemandTwoSequentialManagedReservationsWithRawBursts(t *testing.T) {
	m, driver, held := demandManager(t, 4)
	ctx, _ := queueCaller(t)
	alpha := Owner{TenantID: "alpha", MaxInstances: 3}
	beta := Owner{TenantID: "beta", MaxInstances: 3}
	permitA := NewAdmission(func(Ref) bool { return true })
	permitB := NewAdmission(func(Ref) bool { return true })
	var captured atomic.Int32
	for round := range 2 {
		prefix := fmt.Sprintf("round-%d-", round)
		seed := startQueuedCreate(func() (Record, error) {
			return m.CreateManagedScoped(ctx, beta, prefix+"other-managed", CreateRequest{}, permitB, func(Ref) {})
		})
		waitCreateQueued(t, m, 1, seed)
		rawA := startQueuedCreate(func() (Record, error) {
			return m.CreateScoped(ctx, alpha, prefix+"raw-a", CreateRequest{})
		})
		waitCreateQueued(t, m, 2, seed, rawA)
		rawB := startQueuedCreate(func() (Record, error) {
			return m.CreateScoped(ctx, beta, prefix+"raw-b", CreateRequest{})
		})
		waitCreateQueued(t, m, 3, seed, rawA, rawB)
		// Live quota is three, but it must not buy three DIFFERENT future
		// reservations ahead of the next transaction. No capacity is released.
		for _, owner := range []Owner{alpha, beta} {
			extra := startQueuedCreate(func() (Record, error) {
				return m.CreateScoped(ctx, owner, prefix+owner.TenantID+"-extra", CreateRequest{})
			})
			demandRejectWithoutQueueGrowth(t, m, 3, extra)
		}
		target := startQueuedCreate(func() (Record, error) {
			return m.CreateManagedScoped(ctx, alpha, prefix+"target", CreateRequest{}, permitA, func(Ref) { captured.Add(1) })
		})
		waitCreateQueued(t, m, 4, seed, rawA, rawB, target)
		if m.Metrics().Allocated != 4 || driver.calls.Load() != int32(4+round*4) {
			t.Fatal("unallocated demand or refusal consumed a VM turn")
		}
		// Grant exactly the existing FIFO, without class priority. Only a
		// committed Destroyed release makes the next reservation possible.
		demandRelease(t, m, held[0].Ref)
		other := queuedReply(t, seed, nil)
		demandRelease(t, m, held[1].Ref)
		a := queuedReply(t, rawA, nil)
		demandRelease(t, m, held[2].Ref)
		b := queuedReply(t, rawB, nil)
		if round == 0 {
			demandRelease(t, m, held[3].Ref)
		} else {
			// Keep the first managed generation READY until its replacement
			// is ready. Do NOT get an easy pass by stopping it to free a slot.
			old, err := m.Get(held[3].ID)
			if err != nil || old.State != Ready || old.Ref != held[3].Ref {
				t.Fatal("old managed generation stopped before replacement", err)
			}
			demandRelease(t, m, a.Ref) // Ordinary completed raw work releases a slot.
		}
		next := queuedReply(t, target, nil)
		if round == 1 {
			old, err := m.Get(held[3].ID)
			if err != nil || old.State != Ready {
				t.Fatal("waiting/creation revoked the old generation", err)
			}
			demandRelease(t, m, held[3].Ref)
		}
		if next.State != Ready || captured.Load() != int32(round+1) || m.Metrics().CreateQueued != 0 {
			t.Fatal("managed reservation did not progress exactly once")
		}
		if round == 0 {
			held = []Record{other, a, b, next}
		}
	}
	if driver.calls.Load() != 12 || m.Metrics().Records != 12 || m.Metrics().Allocated != 3 {
		t.Fatal("extra allocations, lost tombstones or incorrect release accounting")
	}
}

func TestCreateDemandDuplicateWaitersShareOneFutureIntent(t *testing.T) {
	m, driver, held := demandManager(t, 4)
	ctx, _ := queueCaller(t)
	owner := Owner{TenantID: "alpha", MaxInstances: 2}
	seed := startQueuedCreate(func() (Record, error) {
		return m.CreateManagedScoped(ctx, Owner{TenantID: "beta", MaxInstances: 3}, "seed", CreateRequest{}, NewAdmission(func(Ref) bool { return true }), func(Ref) {})
	})
	waitCreateQueued(t, m, 1, seed)
	call := func() (Record, error) { return m.CreateScoped(ctx, owner, "same-key", CreateRequest{}) }
	first := startQueuedCreate(call)
	waitCreateQueued(t, m, 2, seed, first)
	duplicate := startQueuedCreate(call)
	waitCreateQueued(t, m, 3, seed, first, duplicate)
	third := startQueuedCreate(call)
	demandRejectWithoutQueueGrowth(t, m, 3, third) // Preserve the old per-tenant caller cap too.
	if ref, err := m.CreateScoped(ctx, owner, "different-key", CreateRequest{}); !errors.Is(err, ErrTenantCapacity) || ref.Ref != (Ref{}) {
		t.Fatal("duplicate callers bought another distinct future intent", err)
	}
	neighbor := startQueuedCreate(func() (Record, error) {
		return m.CreateScoped(ctx, Owner{TenantID: "beta", MaxInstances: 3}, "neighbor", CreateRequest{})
	})
	waitCreateQueued(t, m, 4, seed, first, duplicate, neighbor)
	demandRelease(t, m, held[0].Ref)
	queuedReply(t, seed, nil)
	demandRelease(t, m, held[1].Ref)
	a, b := queuedReply(t, first, nil), queuedReply(t, duplicate, nil)
	if a.Ref != b.Ref || driver.calls.Load() != 6 {
		t.Fatal("duplicate waiting calls allocated more than one candidate")
	}
	waitCreateQueued(t, m, 1, neighbor)
	demandRelease(t, m, held[2].Ref)
	queuedReply(t, neighbor, nil)
	if driver.calls.Load() != 7 || m.Metrics().Records != 7 || m.Metrics().CreateQueued != 0 {
		t.Fatal("neighbor progress or duplicate-key accounting was lost")
	}
}

func TestCreateDemandEmptyKeysAndDifferentSpecsCannotShareIntent(t *testing.T) {
	for _, kind := range []string{"empty-key", "different-spec", "different-admission"} {
		t.Run(kind, func(t *testing.T) {
			m, _, held := demandManager(t, 4)
			ctx, cancel := queueCaller(t)
			owner := Owner{TenantID: "alpha", MaxInstances: 3}
			seed := startQueuedCreate(func() (Record, error) {
				return m.CreateManagedScoped(ctx, Owner{TenantID: "beta", MaxInstances: 3}, "seed", CreateRequest{}, NewAdmission(func(Ref) bool { return true }), func(Ref) {})
			})
			waitCreateQueued(t, m, 1, seed)
			key := "pending"
			if kind == "empty-key" {
				key = ""
			}
			permit := NewAdmission(func(Ref) bool { return true })
			call := func(req CreateRequest, admission *Admission) (Record, error) {
				if kind == "different-admission" {
					return m.CreateManagedScoped(ctx, owner, key, req, admission, func(Ref) {})
				}
				return m.CreateScoped(ctx, owner, key, req)
			}
			first := startQueuedCreate(func() (Record, error) { return call(CreateRequest{}, permit) })
			waitCreateQueued(t, m, 2, seed, first)
			req, other := CreateRequest{}, permit
			if kind == "different-spec" {
				req.TTLMS = 10000
			}
			if kind == "different-admission" {
				other = NewAdmission(func(Ref) bool { return true })
			}
			extra := startQueuedCreate(func() (Record, error) { return call(req, other) })
			queuedReply(t, extra, ErrTenantCapacity)
			if m.Metrics().Records != 4 || m.Metrics().Allocated != 4 {
				t.Fatal("refusal published a key or reservation")
			}
			cancel()
			queuedReply(t, seed, context.Canceled)
			queuedReply(t, first, context.Canceled)
			// A refused/cancelled key is not consumed. A new request may use
			// the changed spec/capability after ordinary capacity is released.
			demandRelease(t, m, held[0].Ref)
			var r Record
			var err error
			if kind == "different-admission" {
				r, err = m.CreateManagedScoped(context.Background(), owner, key, req, other, func(Ref) {})
			} else {
				r, err = m.CreateScoped(context.Background(), owner, key, req)
			}
			if err != nil || r.State != Ready {
				t.Fatal("unallocated refusal permanently consumed a key", err)
			}
		})
	}
}

func TestCreateDemandZeroValueAdmissionGateNotifiesWithoutPanic(t *testing.T) {
	var gate AdmissionGate
	if gate.Open() {
		t.Fatal("zero-value gate admitted work")
	}
	gate.SetOpen(true)
	changed, err := gate.inspect(nil)
	if err != nil || changed == nil {
		t.Fatal("open gate has no paired notification", err)
	}
	gate.SetOpen(false)
	select {
	case <-changed:
	default:
		t.Fatal("drain failed to notify inspected waiter")
	}
	if _, err := gate.inspect(nil); !errors.Is(err, ErrDraining) {
		t.Fatal("closed gate admitted work", err)
	}
}
