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
	changed chan struct{}
}

func NewAdmissionGate(open bool) *AdmissionGate {
	g := &AdmissionGate{changed: make(chan struct{})}
	g.open.Store(open)
	return g
}
func (g *AdmissionGate) Open() bool { return g.open.Load() }
func (g *AdmissionGate) SetOpen(open bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.open.Load() != open {
		g.open.Store(open)
		g.signalLocked()
	}
}
func (g *AdmissionGate) Pending() int { g.mu.Lock(); defer g.mu.Unlock(); return g.pending }

func (g *AdmissionGate) signalLocked() {
	close(g.changed)
	g.changed = make(chan struct{})
}

// inspect pairs the state check with its notification under the same lock.
// A fence between inspection and reservation still wins in reserve.
func (g *AdmissionGate) inspect(ticket *CreationTicket) (<-chan struct{}, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if ticket != nil {
		if ticket.gate != g || ticket.used || ticket.returned {
			return nil, ErrInvalid
		}
	} else if !g.open.Load() {
		return nil, ErrDraining
	}
	return g.changed, nil
}

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
		g.signalLocked()
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
		g.signalLocked()
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
