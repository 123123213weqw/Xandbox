package nodecontrol

import (
	"context"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
)

// Distinct protocol/endpoint: an old record-only reply can NEVER stand in for
// a result-bound closure. Old V1 request/reply validators remain unchanged.
type RuntimeResultsCloseRequest struct {
	Version     int                `json:"version"`
	Operation   string             `json:"operation"`
	Maintenance MaintenanceRequest `json:"maintenance"`
}

func (r RuntimeResultsCloseRequest) Valid() bool {
	return r.Version == 2 && (r.Operation == "status" || r.Operation == "begin") && r.Maintenance.Valid()
}

type RuntimeResultsCloseReply struct {
	Version     int                                    `json:"version"`
	Maintenance MaintenanceReply                       `json:"maintenance"`
	Work        sandbox.AcceptedWorkStatus             `json:"work"`
	Phase       string                                 `json:"phase"`
	Core        *sandbox.ResultBoundClosureObservation `json:"core,omitempty"`
	Sessions    *session.ClosureObservation            `json:"sessions,omitempty"`
}

func (r RuntimeResultsCloseReply) valid() bool {
	if r.Version != 2 || !r.Maintenance.valid() || r.Maintenance.Record == nil || r.Maintenance.Control.Phase != "ready" || r.Work.Version != 1 || r.Work.Pending < 0 || r.Work.Succeeded < 0 || r.Work.Failed < 0 {
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
	}
	return false
}
func (c *Controller) runtimeResultsCloseReplyLocked() RuntimeResultsCloseReply {
	record := *c.maintenance
	b := c.runtime
	r := RuntimeResultsCloseReply{Version: 2, Maintenance: MaintenanceReply{Version: 1, Control: c.statusLocked(), Record: &record}, Work: c.gate.AcceptedWorkStatus(), Phase: b.phase}
	if b.phase == "closed" {
		if !b.resultsProof.For(b.core) || !b.sessionProof.For(b.sessions, b.core) {
			r.Phase = "fenced"
			return r
		}
		core, sessions := b.resultsProof.Observation(), b.sessionProof.Observation()
		r.Core, r.Sessions = &core, &sessions
	}
	return r
}
func (c *Controller) RuntimeResultsClose(ctx context.Context, req RuntimeResultsCloseRequest) (RuntimeResultsCloseReply, error) {
	if !req.Valid() {
		return RuntimeResultsCloseReply{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return RuntimeResultsCloseReply{}, e
	}
	select {
	case c.serial <- struct{}{}:
		defer func() { <-c.serial }()
	default:
		return RuntimeResultsCloseReply{}, ErrBusy
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return RuntimeResultsCloseReply{}, e
	}
	if c.closed.Load() {
		return RuntimeResultsCloseReply{}, ErrClosed
	}
	if c.runtime == nil || !c.runtime.core.UsesResultRetention() {
		return RuntimeResultsCloseReply{}, ErrRuntimeCloseUnsupported
	}
	if c.maintenance == nil || c.maintenance.Request != req.Maintenance {
		return RuntimeResultsCloseReply{}, ErrMaintenance
	}
	if c.view.Phase != "ready" || c.view.Committed != c.maintenance.After() || c.view.PendingRequestID != "" {
		return RuntimeResultsCloseReply{}, ErrFenced
	}
	b := c.runtime
	if req.Operation == "begin" && b.phase == "idle" {
		work := c.gate.AcceptedWorkStatus()
		if !c.maintenanceOriginLive || !work.Complete() {
			return RuntimeResultsCloseReply{}, ErrFenced
		}
		b.work, b.phase, b.done = work, "closing-sessions", make(chan struct{})
		go c.runRuntimeResultsClose(b)
	}
	return c.runtimeResultsCloseReplyLocked(), nil
}
func (c *Controller) runRuntimeResultsClose(b *runtimeCloser) {
	defer close(b.done)
	// Preserve the ORIGINAL independent session/core budgets, including result
	// inspection inside the remaining core budget. No extra recovery allowance.
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
	var cp *sandbox.ResultBoundClosureProof
	if cerr == nil {
		cp, cerr = b.core.ClosedResultsProof(ctx)
	}
	cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if serr != nil || cerr != nil || !sp.For(b.sessions, b.core) || !cp.For(b.core) || c.gate.AcceptedWorkStatus() != b.work {
		b.phase = "fenced"
		return
	}
	b.resultsProof, b.sessionProof, b.phase = cp, sp, "closed"
}
