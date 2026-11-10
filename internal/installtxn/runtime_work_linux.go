//go:build linux

package installtxn

import (
	"context"
	"errors"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

var errAcceptedWork = errors.New("accepted work failed or has unknown outcomes; maintenance remains fenced")

// runtimeAcceptedWorkProof is deliberately opaque and live-only. It binds ONE
// original operation scope, exact v2 WAL and daemon incarnation. It is NOT full
// resource quiescence, physical Stop, accepted-work cancellation, a durable
// receipt or activation/file-selection authority. No constructor accepts counts.
type runtimeAcceptedWorkProof struct {
	scope    *runtimeScope
	intent   string
	process  nodecontrol.ProcessIdentity
	record   nodecontrol.MaintenanceRecord
	terminal sandbox.AcceptedWorkStatus
}

func (s *runtimeScope) quiesceAcceptedWork(ctx context.Context, base, operation string, c *nodecontrol.PinnedClient, m systemManager) (*runtimeAcceptedWorkProof, error) {
	return s.quiesceAcceptedWorkWithProof(ctx, base, operation, c, m, runtimeProcessProof)
}

// The private seam models ONLY executable/argv/placement as in maintain. Work
// admission, terminal paths, original OFD/WAL, Unix socket and pidfd stay real.
func (s *runtimeScope) quiesceAcceptedWorkWithProof(ctx context.Context, base, operation string, c *nodecontrol.PinnedClient, m systemManager, process func(context.Context, transaction, string, nodecontrol.ProcessIdentity) error) (*runtimeAcceptedWorkProof, error) {
	if _, bounded := ctx.Deadline(); !bounded || !digestPattern.MatchString(base) || !requestPattern.MatchString(operation) || c == nil || !c.Identity().Valid() || process == nil {
		return nil, ErrPolicy
	}
	var proof *runtimeAcceptedWorkProof
	e := s.run(ctx, func(f *filesystem) error {
		if m.fs != f {
			return ErrPolicy
		}
		var p runtimeDrainIntent
		var tx transaction
		input := func() error {
			return f.runtimeDrainLocked(ctx, func() error {
				if e := f.runtimeDrainBase(ctx, base, c); e != nil {
					return e
				}
				current, e := f.runtimeDrainReadIntent()
				if e != nil {
					return e
				}
				if !validRuntimeMaintenance(current) || current.Base != base || current.Request != operation || current.Process != c.Identity() {
					return ErrConflict
				}
				if p.Version != 0 && digest(encode(p)) != digest(encode(current)) {
					return ErrConflict
				}
				p = current
				if e = f.runtimeDrainInventory(&p); e != nil {
					return e
				}
				if e = f.exact(runtimeDrainRoot+"/drain.json", encode(runtimeDrainReceipt{Version: 1, Input: digest(encode(p)), After: drainedRuntimeState(p)}), 0600); e != nil {
					return e
				}
				tx, e = f.runtimeBase(base)
				return e
			})
		}
		peer := func() error {
			if e := s.valid(ctx); e != nil {
				return e
			}
			if e := m.enabledLinks(); e != nil {
				return e
			}
			before, e := m.observe(ctx, MainUnit)
			if e != nil {
				return e
			}
			if !validManagedUnit(before, MainUnit) || before.pid != c.Identity().PID || before.active != "active" {
				return ErrConflict
			}
			if e = process(ctx, tx, MainUnit, c.Identity()); e != nil {
				return e
			}
			after, e := m.observe(ctx, MainUnit)
			if e != nil {
				return e
			}
			if before != after {
				return ErrConflict
			}
			return s.valid(ctx)
		}
		if e := input(); e != nil {
			return e
		}
		if e := peer(); e != nil {
			return e
		}
		if e := runtimeLiveDrain(ctx, p, c); e != nil {
			return e
		}
		if e := f.point("runtime-work-before-freeze"); e != nil {
			return e
		}
		for {
			r, e := c.QuiesceMaintenance(ctx, *p.Maintenance)
			if e != nil {
				return e
			}
			if r.Work.Failed != 0 || r.Work.Uncertain {
				return errAcceptedWork
			}
			if r.Work.Complete() {
				if e = f.point("runtime-work-after-terminal"); e != nil {
					return e
				}
				// A positive live reply alone is insufficient. Rejoin original
				// installed/WAL/process/manager authority, then requery the peer.
				if e = input(); e != nil {
					return e
				}
				if e = peer(); e != nil {
					return e
				}
				final, e := c.QuiesceMaintenance(ctx, *p.Maintenance)
				if e != nil {
					return e
				}
				if !final.Work.Complete() || final.Work != r.Work {
					return ErrConflict
				}
				proof = &runtimeAcceptedWorkProof{scope: s, intent: digest(encode(p)), process: p.Process, record: *p.Maintenance, terminal: final.Work}
				return nil
			}
			timer := time.NewTimer(10 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	})
	if e != nil {
		return nil, e
	}
	return proof, nil
}
