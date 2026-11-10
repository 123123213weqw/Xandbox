package nodecontrol

import (
	"context"
	"errors"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
)

var ErrRuntimeCloseUnsupported = errors.New("bound runtime close protocol unsupported")

// Exact in-process authority; no arbitrary close/Stats callbacks are accepted.
// All mutable fields below are protected by Controller.mu; no lock spans close,
// persistence, scans or waits. Original independent shutdown budgets stay5s/5s.
type runtimeCloser struct {
	core                      *sandbox.Manager
	sessions                  *session.Broker
	sessionBudget, coreBudget time.Duration
	phase                     string
	done                      chan struct{}
	work                      sandbox.AcceptedWorkStatus
	coreProof                 *sandbox.ClosureProof
	sessionProof              *session.ClosureProof
}

func (c *Controller) AttachRuntime(core *sandbox.Manager, sessions *session.Broker) error {
	return c.attachRuntime(core, sessions, 5*time.Second, 5*time.Second)
}

// Private seam varies ONLY the NEW close deadlines for deterministic failure
// tests; production binding is always the original independent5s+5s budgets.
func (c *Controller) attachRuntime(core *sandbox.Manager, sessions *session.Broker, sb, cb time.Duration) error {
	if c == nil || core == nil || sessions == nil || !core.UsesAdmissionGate(c.gate) || !sessions.Uses(core) || sb < time.Millisecond || sb > 5*time.Second || cb < time.Millisecond || cb > 5*time.Second {
		return ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return ErrClosed
	}
	if c.runtime != nil {
		return ErrConflict
	}
	c.runtime = &runtimeCloser{core: core, sessions: sessions, sessionBudget: sb, coreBudget: cb, phase: "idle"}
	return nil
}

type RuntimeCloseRequest struct {
	Version     int                `json:"version"`
	Operation   string             `json:"operation"`
	Maintenance MaintenanceRequest `json:"maintenance"`
}

func (r RuntimeCloseRequest) Valid() bool {
	return r.Version == 1 && (r.Operation == "status" || r.Operation == "begin") && r.Maintenance.Valid()
}

type RuntimeCloseReply struct {
	Version     int                         `json:"version"`
	Maintenance MaintenanceReply            `json:"maintenance"`
	Work        sandbox.AcceptedWorkStatus  `json:"work"`
	Phase       string                      `json:"phase"`
	Core        *sandbox.ClosureObservation `json:"core,omitempty"`
	Sessions    *session.ClosureObservation `json:"sessions,omitempty"`
}

func (r RuntimeCloseReply) valid() bool {
	if r.Version != 1 || !r.Maintenance.valid() || r.Maintenance.Record == nil || r.Maintenance.Control.Phase != "ready" || r.Work.Version != 1 || r.Work.Pending < 0 || r.Work.Succeeded < 0 || r.Work.Failed < 0 {
		return false
	}
	switch r.Phase {
	case "idle":
		return r.Core == nil && r.Sessions == nil
	case "closing-sessions", "closing-core":
		return r.Work.Complete() && r.Core == nil && r.Sessions == nil
	case "fenced":
		return r.Work.Frozen && r.Core == nil && r.Sessions == nil
	case "closed":
		return r.Work.Complete() && r.Core != nil && r.Sessions != nil && r.Core.Valid() && r.Sessions.Valid()
	default:
		return false
	}
}
func (c *Controller) runtimeCloseReplyLocked() RuntimeCloseReply {
	record := *c.maintenance
	b := c.runtime
	r := RuntimeCloseReply{Version: 1, Maintenance: MaintenanceReply{Version: 1, Control: c.statusLocked(), Record: &record}, Work: c.gate.AcceptedWorkStatus(), Phase: b.phase}
	if b.phase == "closed" {
		if !b.coreProof.For(b.core) || !b.sessionProof.For(b.sessions, b.core) {
			r.Phase = "fenced"
			return r
		}
		core, sessions := b.coreProof.Observation(), b.sessionProof.Observation()
		r.Core, r.Sessions = &core, &sessions
	}
	return r
}

// RuntimeClose accepts only the SAME ready durable owner and actual completed
// live work fence. Begin is irreversible and does not inherit caller cancellation
// AFTER acceptance. No reopening/release or successful-work inference exists.
func (c *Controller) RuntimeClose(ctx context.Context, req RuntimeCloseRequest) (RuntimeCloseReply, error) {
	if !req.Valid() {
		return RuntimeCloseReply{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return RuntimeCloseReply{}, e
	}
	select {
	case c.serial <- struct{}{}:
		defer func() { <-c.serial }()
	default:
		return RuntimeCloseReply{}, ErrBusy
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return RuntimeCloseReply{}, e
	}
	if c.closed.Load() {
		return RuntimeCloseReply{}, ErrClosed
	}
	if c.runtime == nil {
		return RuntimeCloseReply{}, ErrRuntimeCloseUnsupported
	}
	if c.maintenance == nil || c.maintenance.Request != req.Maintenance {
		return RuntimeCloseReply{}, ErrMaintenance
	}
	if c.view.Phase != "ready" || c.view.Committed != c.maintenance.After() || c.view.PendingRequestID != "" {
		return RuntimeCloseReply{}, ErrFenced
	}
	b := c.runtime
	if req.Operation == "begin" && b.phase == "idle" {
		work := c.gate.AcceptedWorkStatus()
		if !c.maintenanceOriginLive || !work.Complete() {
			return RuntimeCloseReply{}, ErrFenced
		}
		b.work = work
		b.phase = "closing-sessions"
		b.done = make(chan struct{})
		go c.runRuntimeClose(b)
	}
	return c.runtimeCloseReplyLocked(), nil
}
func (c *Controller) runRuntimeClose(b *runtimeCloser) {
	defer close(b.done)
	// A broken session journal must NOT consume the independent Core cleanup
	// opportunity. Both results/proofs are required, but Core is always tried.
	sctx, scancel := context.WithTimeout(context.Background(), b.sessionBudget)
	serr := b.sessions.Close(sctx)
	var sp *session.ClosureProof
	if serr == nil {
		sp, serr = b.sessions.ClosedProof(sctx)
	}
	scancel()
	c.mu.Lock()
	b.phase = "closing-core"
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), b.coreBudget)
	cerr := b.core.Close(ctx)
	var cp *sandbox.ClosureProof
	if cerr == nil {
		cp, cerr = b.core.ClosedProof(ctx)
	}
	cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if serr != nil || cerr != nil || !sp.For(b.sessions, b.core) || !cp.For(b.core) || c.gate.AcceptedWorkStatus() != b.work {
		b.phase = "fenced"
		return
	}
	b.coreProof, b.sessionProof = cp, sp
	b.phase = "closed"
}

// Close/state-lock retention includes the actual journal/pool actors, not just
// this coordinator goroutine (a timed-out Close may leave an I/O writer alive).
func (c *Controller) waitRuntimeClose(ctx context.Context) error {
	c.mu.Lock()
	b := c.runtime
	var done chan struct{}
	if b != nil {
		done = b.done
	}
	c.mu.Unlock()
	if done == nil {
		return nil
	}
	for _, ch := range []<-chan struct{}{done, b.sessions.Done(), b.core.LifecycleDone()} {
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
