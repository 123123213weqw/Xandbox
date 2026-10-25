package nodecontrol

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

var (
	ErrInvalid   = errors.New("invalid control command")
	ErrConflict  = errors.New("control epoch, revision or request conflict")
	ErrBusy      = errors.New("control transition already in progress")
	ErrFenced    = errors.New("control persistence uncertain; exclusive restart required")
	ErrClosed    = errors.New("control is closed")
	ErrExhausted = errors.New("control revision exhausted")
)

type Command struct {
	Version          int    `json:"version"`
	Epoch            string `json:"epoch"`
	ExpectedRevision uint64 `json:"expected_revision"`
	RequestID        string `json:"request_id"`
}

func (c Command) Valid() bool {
	return c.Version == 1 && hexID.MatchString(c.Epoch) && c.ExpectedRevision > 0 && hexID.MatchString(c.RequestID)
}

type Status struct {
	Version                    int    `json:"version"`
	Committed                  State  `json:"committed"`
	Phase                      string `json:"phase"`
	DesiredMode                string `json:"desired_mode"`
	PendingRequestID           string `json:"pending_request_id,omitempty"`
	AdmissionOpen              bool   `json:"admission_open"`
	PendingSessionReservations int    `json:"pending_session_reservations"`
}

func (s Status) valid() bool {
	if s.Version != 1 || !s.Committed.valid() || s.PendingSessionReservations < 0 || (s.DesiredMode != ModeOpen && s.DesiredMode != ModeDrained) {
		return false
	}
	if s.PendingRequestID != "" && !hexID.MatchString(s.PendingRequestID) {
		return false
	}
	switch s.Phase {
	case "ready":
		if s.PendingRequestID != "" || s.DesiredMode != s.Committed.Mode {
			return false
		}
	case "pending", "fenced":
		if s.PendingRequestID == "" {
			return false
		}
	case "closed":
	default:
		return false
	}
	return !s.AdmissionOpen || (s.Phase == "ready" && s.Committed.Mode == ModeOpen)
}

type Controller struct {
	store  Store
	gate   *sandbox.AdmissionGate
	serial chan struct{}
	closed atomic.Bool
	mu     sync.Mutex // Only bounded memory/gate updates, NEVER persistence.
	view   Status
}

func New(store Store, gate *sandbox.AdmissionGate) (*Controller, error) {
	if store == nil || gate == nil {
		return nil, ErrInvalid
	}
	gate.SetOpen(false)
	s, e := store.Load()
	if e != nil {
		return nil, e
	}
	if !s.valid() {
		return nil, ErrInvalid
	}
	c := &Controller{store: store, gate: gate, serial: make(chan struct{}, 1), view: Status{Version: 1, Committed: s, Phase: "ready", DesiredMode: s.Mode}}
	gate.SetOpen(s.Mode == ModeOpen)
	return c, nil
}
func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.view
	s.AdmissionOpen = c.gate.Open()
	s.PendingSessionReservations = c.gate.Pending()
	return s
}

// Change fences NEW reservations before persistence, but does not cancel any
// accepted ticket, existing task, Stop or Cleanup. Once this command begins,
// caller disconnection does not roll it back: query/retry its exact ID/epoch/
// expected revision. Only the most recent committed command is replayable.
// A Save error may be post-commit: admission stays fenced until exclusive
// restart loads disk truth. No global lifecycle mutex is held over Save.
func (c *Controller) Change(ctx context.Context, target string, request Command) (Status, error) {
	if !request.Valid() || (target != ModeOpen && target != ModeDrained) {
		return c.Status(), ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return c.Status(), e
	}
	if c.closed.Load() {
		return c.Status(), ErrClosed
	}
	select {
	case c.serial <- struct{}{}:
		defer func() { <-c.serial }()
	default:
		return c.Status(), ErrBusy
	}
	c.mu.Lock()
	if c.closed.Load() {
		c.mu.Unlock()
		return c.Status(), ErrClosed
	}
	if e := ctx.Err(); e != nil {
		c.mu.Unlock()
		return c.Status(), e
	}
	if c.view.Phase == "fenced" {
		c.mu.Unlock()
		return c.Status(), ErrFenced
	}
	old := c.view.Committed
	if request.Epoch != old.Epoch {
		c.mu.Unlock()
		return c.Status(), ErrConflict
	}
	if request.RequestID == old.LastRequestID {
		ok := request.ExpectedRevision == old.LastExpectedRevision && old.Mode == target
		c.mu.Unlock()
		if !ok {
			return c.Status(), ErrConflict
		}
		return c.Status(), nil
	}
	if request.ExpectedRevision != old.Revision {
		c.mu.Unlock()
		return c.Status(), ErrConflict
	}
	if old.Revision == math.MaxUint64 || (old.Revision == math.MaxUint64-1 && target != ModeDrained) {
		c.mu.Unlock()
		return c.Status(), ErrExhausted
	}
	c.gate.SetOpen(false)
	c.view.Phase, c.view.DesiredMode, c.view.PendingRequestID = "pending", target, request.RequestID
	c.mu.Unlock()
	next := State{Version: 1, Epoch: old.Epoch, Revision: old.Revision + 1, Mode: target, LastRequestID: request.RequestID, LastExpectedRevision: old.Revision}
	e := c.store.Save(old, next)
	c.mu.Lock()
	if e != nil {
		c.view.Phase = "fenced"
	} else {
		c.view.Committed = next
		c.view.PendingRequestID = ""
		c.view.Phase = "ready"
		if !c.closed.Load() {
			c.gate.SetOpen(target == ModeOpen)
		}
	}
	if c.closed.Load() {
		c.view.Phase = "closed"
	}
	c.mu.Unlock()
	if e != nil {
		return c.Status(), ErrFenced
	}
	return c.Status(), nil
}

// Close must be included in state-lock retention. A blocked control Save can
// outlive HTTP Close just like a blocked lifecycle write; another controller
// must not acquire the same root while this writer can still commit.
func (c *Controller) FenceClose() {
	c.closed.Store(true)
	c.mu.Lock()
	c.gate.SetOpen(false)
	c.view.Phase = "closed"
	c.mu.Unlock()
}
func (c *Controller) Close(ctx context.Context) error {
	c.FenceClose()
	select {
	case c.serial <- struct{}{}:
		<-c.serial
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
