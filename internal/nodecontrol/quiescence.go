package nodecontrol

import (
	"context"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

// MaintenanceWorkReply is a live finish-only observation tied to the exact
// maintenance record and pinned daemon incarnation. It is never a durable
// receipt. Failure/uncertainty is sticky; no force, cancel or reopen mode exists.
type MaintenanceWorkReply struct {
	Version     int                        `json:"version"`
	Maintenance MaintenanceReply           `json:"maintenance"`
	Work        sandbox.AcceptedWorkStatus `json:"work"`
}

func (r MaintenanceWorkReply) valid() bool {
	return r.Version == 1 && r.Maintenance.valid() && r.Maintenance.Record != nil && r.Maintenance.Control.Phase == "ready" && r.Work.Version == 1 && r.Work.Frozen && r.Work.Pending >= 0 && r.Work.Succeeded >= 0 && r.Work.Failed >= 0
}

// QuiesceMaintenance is separate from BEGIN and ordinary drain. The original
// exact durable owner must already be ready. This bounded call only installs
// the admission fence and observes obligations; the caller supplies a bounded
// polling deadline. No memory lock spans I/O or waits for accepted work.
func (c *Controller) QuiesceMaintenance(ctx context.Context, req MaintenanceRequest) (MaintenanceWorkReply, error) {
	if !req.Valid() {
		return MaintenanceWorkReply{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return MaintenanceWorkReply{}, e
	}
	if _, ok := c.store.(MaintenanceStore); !ok {
		return MaintenanceWorkReply{}, ErrMaintenanceUnsupported
	}
	select {
	case c.serial <- struct{}{}:
		defer func() { <-c.serial }()
	default:
		return MaintenanceWorkReply{}, ErrBusy
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return MaintenanceWorkReply{}, e
	}
	if c.closed.Load() {
		return MaintenanceWorkReply{}, ErrClosed
	}
	if c.maintenance == nil || c.maintenance.Request != req {
		return MaintenanceWorkReply{}, ErrMaintenance
	}
	if c.view.Phase != "ready" || c.view.Committed != c.maintenance.After() || c.view.PendingRequestID != "" {
		return MaintenanceWorkReply{}, ErrFenced
	}
	// A loaded maintenance record says nothing about old job outcomes. Refuse
	// positive completion after restart even if all volatile counts are zero.
	if !c.maintenanceOriginLive {
		c.gate.MarkAcceptedWorkUncertain()
	}
	work := c.gate.FreezeAcceptedWork()
	record := *c.maintenance
	return MaintenanceWorkReply{Version: 1, Maintenance: MaintenanceReply{Version: 1, Control: c.statusLocked(), Record: &record}, Work: work}, nil
}
