package sandbox

import (
	"sync"
	"sync/atomic"
)

// AdmissionGate linearizes NEW lifecycle/session reservations against an
// operator fence. Callbacks are trusted, bounded memory changes ONLY: no I/O,
// goroutine waits, or calls back into this gate. Replays do not reserve again.
// Stop, Cleanup and existing executions never acquire it.
type AdmissionGate struct {
	mu      sync.Mutex
	open    atomic.Bool
	pending int
}

func NewAdmissionGate(open bool) *AdmissionGate {
	g := &AdmissionGate{}
	g.open.Store(open)
	return g
}
func (g *AdmissionGate) Open() bool        { return g.open.Load() }
func (g *AdmissionGate) SetOpen(open bool) { g.mu.Lock(); g.open.Store(open); g.mu.Unlock() }
func (g *AdmissionGate) Pending() int      { g.mu.Lock(); defer g.mu.Unlock(); return g.pending }

// CreationTicket authorizes ONE Core reservation for a session mutation that
// was already accepted before drain. It is an in-process capability, never a
// tenant token, JSON field, durable value, or authority surviving a restart.
type CreationTicket struct {
	gate           *AdmissionGate
	used, returned bool
}

func (t *CreationTicket) Release() {
	if t == nil || t.gate == nil {
		return
	}
	g := t.gate
	g.mu.Lock()
	defer g.mu.Unlock()
	if !t.used && !t.returned {
		t.returned = true
		g.pending--
	}
}
func (g *AdmissionGate) reserve(ticket *CreationTicket, commit func()) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if ticket != nil {
		if ticket.gate != g || ticket.used || ticket.returned {
			return ErrInvalid
		}
		ticket.used = true
		g.pending--
	} else if !g.open.Load() {
		return ErrDraining
	}
	commit()
	return nil
}
func (m *Manager) ReserveSessionAttempt(commit func(*CreationTicket)) error {
	if commit == nil {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing {
		return ErrClosing
	}
	g := m.opts.AdmissionGate
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.open.Load() {
		return ErrDraining
	}
	t := &CreationTicket{gate: g}
	g.pending++
	commit(t)
	return nil
}
func (m *Manager) AdmissionOpen() bool {
	m.mu.Lock()
	closing := m.closing
	m.mu.Unlock()
	return !closing && m.opts.AdmissionGate.Open()
}
