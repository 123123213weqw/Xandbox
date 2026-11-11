package nodecontrol

import (
	"context"
	"errors"
	"math"

	"github.com/123123213weqw/Xandbox/internal/fixedhex"
)

var ErrMaintenance = errors.New("exclusive maintenance admission fence is held")
var ErrMaintenanceUnsupported = errors.New("durable maintenance protocol unsupported")
var maintenanceDigest = fixedhex.Pattern(64)

// MaintenanceOwner identifies the exact installed operation, NOT a tenant credential,
// process/executable proof, successful work or permission to select files.
type MaintenanceOwner struct {
	Version             int    `json:"version"`
	InstallCommitSHA256 string `json:"install_commit_sha256"`
	OperationID         string `json:"operation_id"`
}

func (o MaintenanceOwner) Valid() bool {
	return o.Version == 1 && maintenanceDigest.MatchString(o.InstallCommitSHA256) && hexID.MatchString(o.OperationID)
}

type MaintenanceRequest struct {
	Version int              `json:"version"`
	Owner   MaintenanceOwner `json:"owner"`
	Command Command          `json:"command"`
}

func (r MaintenanceRequest) Valid() bool {
	return r.Version == 1 && r.Owner.Valid() && r.Command.Valid() && r.Owner.OperationID != r.Command.RequestID
}

// The original v1 admission State format remains unchanged. This independent
// immutable side-record deliberately fences old readers that do not know it.
type MaintenanceRecord struct {
	Version int                `json:"version"`
	Request MaintenanceRequest `json:"request"`
	Before  State              `json:"before"`
}

func (r MaintenanceRecord) Valid() bool {
	return r.Version == 1 && r.Request.Valid() && r.Before.Valid() && r.Request.Command.Epoch == r.Before.Epoch && r.Request.Command.ExpectedRevision == r.Before.Revision && r.Request.Command.RequestID != r.Before.LastRequestID && r.Request.Owner.OperationID != r.Before.LastRequestID && (r.Before.Mode == ModeDrained || r.Before.Revision < math.MaxUint64)
}
func (r MaintenanceRecord) After() State {
	if r.Before.Mode == ModeDrained {
		return r.Before
	} // Preserve preexisting drain/revision/last command.
	return State{Version: 1, Epoch: r.Before.Epoch, Revision: r.Before.Revision + 1, Mode: ModeDrained, LastRequestID: r.Request.Command.RequestID, LastExpectedRevision: r.Before.Revision}
}

type MaintenanceReply struct {
	Version int                `json:"version"`
	Control Status             `json:"control"`
	Record  *MaintenanceRecord `json:"record,omitempty"`
}

func (r MaintenanceReply) valid() bool {
	if r.Version != 1 || !r.Control.valid() {
		return false
	}
	if r.Record == nil {
		return true
	}
	if !r.Record.Valid() || r.Control.AdmissionOpen || r.Control.DesiredMode != ModeDrained {
		return false
	}
	if r.Control.Phase == "ready" {
		return r.Control.Committed == r.Record.After() && r.Control.PendingRequestID == ""
	}
	return (r.Control.PendingRequestID == "" || r.Control.PendingRequestID == r.Record.Request.Command.RequestID) && (r.Control.Committed == r.Record.Before || r.Control.Committed == r.Record.After())
}

// Implementations require the daemon's ORIGINAL exclusive state ownership.
// Ensure writes/recovers only the exact supplied record; no release/resume,
// arbitrary adoption, rollback snapshot or restoration method exists.
type MaintenanceStore interface {
	Store
	LoadMaintenance() (*MaintenanceRecord, error)
	EnsureMaintenance(MaintenanceRecord) error
}

func recoverMaintenance(store Store, m MaintenanceStore, r MaintenanceRecord) (State, error) {
	if !r.Valid() {
		return State{}, ErrInvalid
	}
	if e := m.EnsureMaintenance(r); e != nil {
		return State{}, e
	}
	s, e := store.Load()
	if e != nil {
		return State{}, e
	}
	if s == r.Before && s != r.After() {
		if e = store.Save(s, r.After()); e != nil {
			return State{}, e
		}
	} else if s != r.After() {
		return State{}, ErrConflict
	}
	s, e = store.Load()
	if e != nil {
		return State{}, e
	}
	current, e := m.LoadMaintenance()
	if e != nil {
		return State{}, e
	}
	if current == nil || *current != r || s != r.After() {
		return State{}, ErrConflict
	}
	return s, nil
}

func (c *Controller) MaintenanceStatus() (MaintenanceReply, error) {
	if _, ok := c.store.(MaintenanceStore); !ok {
		return MaintenanceReply{}, ErrMaintenanceUnsupported
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	r := MaintenanceReply{Version: 1, Control: c.statusLocked()}
	if c.maintenance != nil {
		copy := *c.maintenance
		r.Record = &copy
	}
	return r, nil
}

// Begin serializes with EVERY ordinary drain/resume, closes admission BEFORE
// persistence and retains the same immutable owner on lost/uncertain outcomes.
// It preserves accepted tickets/tasks; this is not accepted-work completion.
func (c *Controller) BeginMaintenance(ctx context.Context, req MaintenanceRequest) (MaintenanceReply, error) {
	if !req.Valid() {
		return MaintenanceReply{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return MaintenanceReply{}, e
	}
	m, ok := c.store.(MaintenanceStore)
	if !ok {
		return MaintenanceReply{}, ErrMaintenanceUnsupported
	}
	if c.closed.Load() {
		return MaintenanceReply{}, ErrClosed
	}
	select {
	case c.serial <- struct{}{}:
		defer func() { <-c.serial }()
	default:
		return MaintenanceReply{}, ErrBusy
	}
	c.mu.Lock()
	if e := ctx.Err(); e != nil {
		c.mu.Unlock()
		return MaintenanceReply{}, e
	}
	if c.closed.Load() {
		c.mu.Unlock()
		return MaintenanceReply{}, ErrClosed
	}
	var record MaintenanceRecord
	if c.maintenance != nil {
		record = *c.maintenance
		if record.Request != req {
			c.mu.Unlock()
			return MaintenanceReply{}, ErrMaintenance
		}
	} else {
		if c.view.Phase != "ready" {
			c.mu.Unlock()
			return MaintenanceReply{}, ErrFenced
		}
		record = MaintenanceRecord{Version: 1, Request: req, Before: c.view.Committed}
		if !record.Valid() {
			c.mu.Unlock()
			return MaintenanceReply{}, ErrConflict
		}
		c.maintenance = &record
		c.maintenanceOriginLive = true
	}
	c.gate.SetOpen(false)
	c.view.Phase, c.view.DesiredMode, c.view.PendingRequestID = "pending", ModeDrained, req.Command.RequestID
	c.mu.Unlock()
	// No memory mutex spans disk I/O. Accepted cancellation never reopens a gate.
	after, e := recoverMaintenance(c.store, m, record)
	c.mu.Lock()
	if e != nil {
		c.view.Phase = "fenced"
	} else {
		c.view.Committed = after
		c.view.Phase = "ready"
		c.view.PendingRequestID = ""
	}
	if c.closed.Load() {
		c.view.Phase = "closed"
	}
	c.gate.SetOpen(false)
	c.mu.Unlock()
	if e != nil {
		return MaintenanceReply{}, ErrFenced
	}
	if c.closed.Load() {
		return MaintenanceReply{}, ErrClosed
	}
	return c.MaintenanceStatus()
}
