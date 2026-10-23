package sandbox

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestAdmissionGateFenceAndSingleUseAcceptedTicket(t *testing.T) {
	g := NewAdmissionGate(true)
	m, _, _ := setup(t, Options{MaxInstances: 4, AdmissionGate: g}, nil)
	owner := Owner{TenantID: "alpha", MaxInstances: 4}
	r, e := m.CreateScoped(context.Background(), owner, "old", CreateRequest{})
	if e != nil {
		t.Fatal(e)
	}
	var ticket *CreationTicket
	if e = m.ReserveSessionAttempt(func(v *CreationTicket) { ticket = v }); e != nil {
		t.Fatal(e)
	}
	if g.Pending() != 1 {
		t.Fatal("accepted attempt not counted")
	}
	g.SetOpen(false)
	if _, e = m.CreateScoped(context.Background(), owner, "new", CreateRequest{}); !errors.Is(e, ErrDraining) {
		t.Fatal(e)
	}
	if m.Stats().Records != 1 {
		t.Fatal("drained create reserved metadata")
	}
	if replay, e := m.CreateScoped(context.Background(), owner, "old", CreateRequest{}); e != nil || replay.Ref != r.Ref {
		t.Fatal("accepted key replay blocked", e)
	}
	permit := NewAdmission(func(Ref) bool { return true })
	accepted, e := m.CreateReservedManagedScoped(context.Background(), owner, "accepted", CreateRequest{}, permit, func(Ref) {}, ticket)
	if e != nil || g.Pending() != 0 {
		t.Fatal("pre-drain ticket did not finish", e)
	}
	if _, e = m.CreateReservedManagedScoped(context.Background(), owner, "reuse", CreateRequest{}, permit, func(Ref) {}, ticket); !errors.Is(e, ErrInvalid) {
		t.Fatal("ticket reused", e)
	}
	if replay, e := m.CreateReservedManagedScoped(context.Background(), owner, "accepted", CreateRequest{}, permit, func(Ref) {}, ticket); e != nil || replay.Ref != accepted.Ref {
		t.Fatal("accepted managed replay blocked", e)
	}
	if _, e = m.CreateManagedScoped(context.Background(), owner, "bypass", CreateRequest{}, permit, func(Ref) {}); !errors.Is(e, ErrDraining) {
		t.Fatal("managed capability bypassed drain", e)
	}
	if _, e = m.ExecScoped(owner.TenantID, r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo", "alive"}}); e != nil {
		t.Fatal("existing Exec blocked", e)
	}
	if _, e = m.Destroy(r.Ref); e != nil {
		t.Fatal(e)
	}
	waitState(t, m, r.ID, Destroyed)
	g.SetOpen(true)
	if _, e = m.CreateScoped(context.Background(), owner, "resumed", CreateRequest{}); e != nil {
		t.Fatal(e)
	}
}
func TestAdmissionTicketForeignReleasedAndFenceLinearization(t *testing.T) {
	g := NewAdmissionGate(true)
	m, _, _ := setup(t, Options{AdmissionGate: g}, nil)
	var ticket *CreationTicket
	if e := m.ReserveSessionAttempt(func(v *CreationTicket) { ticket = v }); e != nil {
		t.Fatal(e)
	}
	foreign := NewAdmissionGate(true)
	if e := foreign.reserve(ticket, func() { t.Fatal("foreign callback ran") }); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	ticket.Release()
	ticket.Release()
	if g.Pending() != 0 {
		t.Fatal("ticket leaked or returned twice")
	}
	if e := g.reserve(ticket, func() { t.Fatal("released ticket accepted") }); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	var count atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				_ = g.reserve(nil, func() { count.Add(1) })
			}
		}()
	}
	g.SetOpen(false)
	atFence := count.Load()
	wg.Wait()
	if count.Load() != atFence {
		t.Fatal("new reservation linearized after acknowledged fence")
	}
	if e := m.ReserveSessionAttempt(func(*CreationTicket) { t.Fatal("new ticket after fence") }); !errors.Is(e, ErrDraining) {
		t.Fatal(e)
	}
}
