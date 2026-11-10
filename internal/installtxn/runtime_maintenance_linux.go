//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

// Explicit v2 of the original drain WAL. v1 bytes/protocol are unchanged and
// never upgraded/adopted silently. The new record owns an immutable node fence.
// No release, service activation, file selection or successful work claim here.
type runtimeMaintenanceResult struct {
	runtimeDrainResult
	MaintenanceHeld bool
}

func maintenanceCommandID(p runtimeDrainIntent) string {
	input := struct {
		Domain    string                      `json:"domain"`
		Base      string                      `json:"base"`
		Operation string                      `json:"operation"`
		Process   nodecontrol.ProcessIdentity `json:"process"`
		Before    nodecontrol.State           `json:"before"`
	}{"xandbox-maintenance-command-v1", p.Base, p.Request, p.Process, p.Before}
	return digest(encode(input))[:32]
}
func validRuntimeMaintenance(p runtimeDrainIntent) bool {
	if p.Version != 2 || p.Maintenance == nil {
		return false
	}
	r := *p.Maintenance
	return r.Valid() && r.Before == p.Before && r.Request.Owner.InstallCommitSHA256 == p.Base && r.Request.Owner.OperationID == p.Request && r.Request.Command.RequestID == maintenanceCommandID(p)
}
func maintenanceReady(r nodecontrol.MaintenanceReply, p runtimeDrainIntent) bool {
	return validRuntimeMaintenance(p) && r.Record != nil && *r.Record == *p.Maintenance && runtimeDrainStatus(r.Control, p.Maintenance.After())
}
func runtimeLiveDrain(ctx context.Context, p runtimeDrainIntent, c *nodecontrol.PinnedClient) error {
	if c == nil || c.Identity() != p.Process {
		return ErrConflict
	}
	if p.Version == 2 {
		r, e := c.MaintenanceStatus(ctx)
		if e != nil {
			return e
		}
		if !maintenanceReady(r, p) {
			return ErrConflict
		}
		return nil
	}
	if p.Version != 1 || !validRuntimeDrain(p) {
		return ErrInventory
	}
	r, e := c.Status(ctx)
	if e != nil {
		return e
	}
	if !runtimeDrainStatus(r.Control, drainedRuntimeState(p)) {
		return ErrConflict
	}
	return nil
}

// A fresh coordinator may recover a COMPLETE canonical original scratch only.
// Empty/truncated unknown-owner intent never invents a new Before/CAS from the
// node's current state. Startup is already fenced by the side namespace.
func (f *filesystem) readMaintenanceIntent() (runtimeDrainIntent, bool, error) {
	p, e := f.runtimeDrainReadIntent()
	if e == nil {
		if !validRuntimeMaintenance(p) {
			return p, false, ErrConflict
		}
		return p, true, nil
	}
	if !errors.Is(e, unix.ENOENT) {
		return p, false, e
	}
	b, e := f.read(runtimeDrainRoot+"/.intent.json.next", MaxPlan, 0600)
	if errors.Is(e, unix.ENOENT) {
		return p, false, nil
	}
	if e != nil {
		return p, false, e
	}
	if strictjson.Decode(b, &p) != nil || !validRuntimeDrain(p) || !validRuntimeMaintenance(p) || !bytes.Equal(b, encode(p)) {
		return p, false, ErrInventory
	}
	return p, true, nil
}
func (f *filesystem) hasDrainReceipt() (bool, error) {
	for _, name := range []string{"drain.json", ".drain.json.next"} {
		yes, e := f.exists(runtimeDrainRoot + "/" + name)
		if e != nil {
			return false, e
		}
		if yes {
			return true, nil
		}
	}
	return false, nil
}

// Fixed real kernel executable/argv/placement and manager proof in production.
// Test-only private adapter below models these independently, never WAL/CAS,
// private socket, pidfd, state lock ownership, durability or installed bytes.
func (s *runtimeScope) maintain(ctx context.Context, base, operation string, c *nodecontrol.PinnedClient, m systemManager) (runtimeMaintenanceResult, error) {
	return s.maintainWithProof(ctx, base, operation, c, m, runtimeProcessProof)
}
func (s *runtimeScope) maintainWithProof(ctx context.Context, base, operation string, c *nodecontrol.PinnedClient, m systemManager, process func(context.Context, transaction, string, nodecontrol.ProcessIdentity) error) (runtimeMaintenanceResult, error) {
	var result runtimeMaintenanceResult
	if !digestPattern.MatchString(base) || !requestPattern.MatchString(operation) || c == nil || !c.Identity().Valid() || process == nil {
		return result, ErrPolicy
	}
	err := s.run(ctx, func(f *filesystem) error {
		if m.fs != f {
			return ErrPolicy
		}
		var p runtimeDrainIntent
		var tx transaction
		var pending bool
		lockedBase := func() error {
			if e := f.runtimeDrainBase(ctx, base, c); e != nil {
				return e
			}
			var e error
			tx, e = f.runtimeBase(base)
			return e
		}
		if e := f.runtimeDrainLocked(ctx, func() error {
			if e := lockedBase(); e != nil {
				return e
			}
			var e error
			p, pending, e = f.readMaintenanceIntent()
			if e != nil {
				return e
			}
			if pending && (p.Base != base || p.Request != operation || p.Process != c.Identity()) {
				return ErrConflict
			}
			if pending {
				return f.runtimeDrainInventory(&p)
			}
			return f.runtimeDrainInventory(nil)
		}); e != nil {
			return e
		}
		verifyPeer := func() error {
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
		if e := verifyPeer(); e != nil {
			return e
		}
		if !pending {
			// Capability/status ONLY. Legacy endpoints fail BEFORE namespace creation;
			// there is no fallback to ordinary drain or operator-selected process.
			r, e := c.MaintenanceStatus(ctx)
			if e != nil {
				return e
			}
			if r.Record != nil || !runtimeDrainStatus(r.Control, r.Control.Committed) {
				return ErrConflict
			}
			p = runtimeDrainIntent{Version: 2, Base: base, Request: operation, Process: c.Identity(), Before: r.Control.Committed}
			p.Maintenance = &nodecontrol.MaintenanceRecord{Version: 1, Before: p.Before, Request: nodecontrol.MaintenanceRequest{Version: 1, Owner: nodecontrol.MaintenanceOwner{Version: 1, InstallCommitSHA256: base, OperationID: operation}, Command: nodecontrol.Command{Version: 1, Epoch: p.Before.Epoch, ExpectedRevision: p.Before.Revision, RequestID: maintenanceCommandID(p)}}}
			if !validRuntimeDrain(p) {
				return ErrPolicy
			}
		}
		if e := f.runtimeDrainLocked(ctx, func() error {
			if e := lockedBase(); e != nil {
				return e
			}
			if e := f.runtimeDrainInventory(&p); e != nil {
				return e
			}
			if e := f.mkdir(runtimeDrainRoot, 0700); e != nil {
				return e
			}
			return f.runtimeRecord(runtimeDrainRoot+"/intent.json", nil, encode(p), "runtime-maintenance-intent")
		}); e != nil {
			return e
		}
		// The original namespace and full intent are durable BEFORE any node write.
		// Thus even a node write failing before any byte cannot bypass cap0 startup.
		if e := verifyPeer(); e != nil {
			return e
		}
		reply, e := c.MaintenanceStatus(ctx)
		if e != nil {
			return e
		}
		if !maintenanceReady(reply, p) {
			exists, e := f.hasDrainReceipt()
			if e != nil {
				return e
			}
			if exists {
				return ErrConflict
			}
			if reply.Record == nil {
				if !runtimeDrainStatus(reply.Control, p.Before) {
					return ErrConflict
				}
			} else if *reply.Record != *p.Maintenance {
				return ErrConflict
			}
			if e = f.point("runtime-maintenance-before-rpc"); e != nil {
				return e
			}
			if e = verifyPeer(); e != nil {
				return e
			}
			reply, e = c.BeginMaintenance(ctx, p.Before, p.Maintenance.Request)
			if e != nil {
				return e
			}
			if e = f.point("runtime-maintenance-after-rpc"); e != nil {
				return e
			}
		}
		if !maintenanceReady(reply, p) {
			return ErrConflict
		}
		if e = verifyPeer(); e != nil {
			return e
		}
		reply, e = c.MaintenanceStatus(ctx)
		if e != nil {
			return e
		}
		if !maintenanceReady(reply, p) {
			return ErrConflict
		}
		if e = f.runtimeDrainLocked(ctx, func() error {
			if e := lockedBase(); e != nil {
				return e
			}
			if e := f.runtimeDrainInventory(&p); e != nil {
				return e
			}
			if e := f.exact(runtimeDrainRoot+"/intent.json", encode(p), 0600); e != nil {
				return e
			}
			return f.runtimeRecord(runtimeDrainRoot+"/drain.json", nil, encode(runtimeDrainReceipt{Version: 1, Input: digest(encode(p)), After: drainedRuntimeState(p)}), "runtime-maintenance-receipt")
		}); e != nil {
			return e
		}
		if e = verifyPeer(); e != nil {
			return e
		}
		if e = runtimeLiveDrain(ctx, p, c); e != nil {
			return e
		}
		result = runtimeMaintenanceResult{runtimeDrainResult: runtimeDrainResult{AdmissionDrained: true, WasOpen: p.Before.Mode == nodecontrol.ModeOpen, Revision: drainedRuntimeState(p).Revision}, MaintenanceHeld: true}
		return nil
	})
	if err != nil {
		return runtimeMaintenanceResult{}, err
	}
	return result, nil
}
