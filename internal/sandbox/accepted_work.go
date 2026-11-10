package sandbox

// AcceptedWorkStatus describes a live, irreversible finish-only fence. These
// counts are backed by the actual reservation/Exec terminal paths, not Stats or
// VM/process absence. It is NOT durable work history, a reclaim certificate or
// permission to change files. No capability or success survives process restart.
type AcceptedWorkStatus struct {
	Version   int  `json:"version"`
	Frozen    bool `json:"frozen"`
	Pending   int  `json:"pending"`
	Succeeded int  `json:"succeeded"`
	Failed    int  `json:"failed"`
	Uncertain bool `json:"uncertain"`
}

func (s AcceptedWorkStatus) Complete() bool {
	return s.Version == 1 && s.Frozen && s.Pending == 0 && s.Failed == 0 && !s.Uncertain
}

// acceptedWork is an in-process single-use completion obligation. Admission and
// freeze share gate.mu. An accepted session holds its parent obligation through
// its final journal write, so consuming its ticket after freeze cannot create a
// false zero interval. No user/driver callback runs with gate.mu held.
type acceptedWork struct {
	gate *AdmissionGate
	done bool // gate.mu
}

func (g *AdmissionGate) startWorkLocked() *acceptedWork {
	g.workPending++
	return &acceptedWork{gate: g}
}
func (w *acceptedWork) finish(success bool) {
	if w == nil {
		return
	}
	g := w.gate
	g.mu.Lock()
	defer g.mu.Unlock()
	if w.done {
		return
	}
	w.done = true
	g.workPending--
	if g.workFrozen {
		if success {
			g.workSucceeded++
		} else {
			g.workFailed++
		}
	}
}
func (g *AdmissionGate) acceptExecution() (*acceptedWork, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.workFrozen {
		return nil, ErrDraining
	}
	return g.startWorkLocked(), nil
}

// FreezeAcceptedWork is a distinct, irreversible in-process stage, NOT ordinary
// drain or maintenance BEGIN. It does not cancel accepted operations. Reserved
// session children can still finish; no fresh create/session/Exec can start.
// A bounded coordinator polls rather than spawning a waiter or blocking a lock.
func (g *AdmissionGate) FreezeAcceptedWork() AcceptedWorkStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.workFrozen = true
	g.open.Store(false)
	return g.workStatusLocked()
}
func (g *AdmissionGate) AcceptedWorkStatus() AcceptedWorkStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.workStatusLocked()
}
func (g *AdmissionGate) workStatusLocked() AcceptedWorkStatus {
	return AcceptedWorkStatus{Version: 1, Frozen: g.workFrozen, Pending: g.workPending, Succeeded: g.workSucceeded, Failed: g.workFailed, Uncertain: g.workUncertain}
}

// MarkAcceptedWorkUncertain is sticky. Startup with non-destroyed old ownership
// lacks durable job outcomes; recovery/Stop/empty counters cannot clear this bit.
func (g *AdmissionGate) MarkAcceptedWorkUncertain() {
	g.mu.Lock()
	g.workUncertain = true
	g.mu.Unlock()
}

// Complete ends the ENTIRE accepted session mutation, including final journal
// persistence and route publication. Only the trusted broker's terminal path
// calls it. Release is an unsuccessful/abandoned completion, never success.
func (t *CreationTicket) Complete(err error) {
	if t == nil || t.gate == nil {
		return
	}
	g := t.gate
	g.mu.Lock()
	if t.returned {
		g.mu.Unlock()
		return
	}
	t.returned = true
	if !t.used {
		g.pending--
	}
	// Keep completion under the same lock as the ticket state. The parent must
	// not disappear before a concurrent reserved child's obligation is created.
	w := t.work
	if w != nil && !w.done {
		w.done = true
		g.workPending--
		if g.workFrozen {
			if err == nil {
				g.workSucceeded++
			} else {
				g.workFailed++
			}
		}
	}
	g.mu.Unlock()
}
