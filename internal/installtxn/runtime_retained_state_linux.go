//go:build linux

package installtxn

import (
	"context"
	"os"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
)

// A comparison of complete CURRENT disk bytes to supplied format observations,
// NOT proof that those observations came from a live actor/operation. The future
// installed consumer must additionally join its original operation/state FDs,
// process-pinned V2 close WAL, Stop, source/candidate/retained-self compatibility,
// managed budgets and backend absence. No activation path consumes this value.
type runtimeRetainedStateInventory struct {
	State                                 runtimeStateFootprint
	Core                                  runtimeCoreInventory
	CoreTerminal                          sandbox.ClosureObservation
	SessionTerminal                       session.ClosureObservation
	Results                               sandbox.ResultClosureObservation
	DiskResultBytesMatched                bool
	ResourcesReclaimed, ActivationAllowed bool
}

type retainedRootPolicy struct {
	owners  map[sandbox.Ref]sandbox.Record
	results sandbox.ResultClosureObservation
}

func (r *stateInventoryReader) retainedResults(root *os.File, policy *retainedRootPolicy) error {
	p := sandbox.NewResultInspectionProjection()
	e := r.directory(root, "results", "results", sandbox.MaxResultRecords, func(dir *os.File, names []string) error {
		// Reject the entire bounded namespace BEFORE opening any result payload.
		last := ""
		for _, name := range names {
			if len(name) != 37 || name[32:] != ".json" || !requestPattern.MatchString(name[:32]) || name <= last {
				return ErrInventory
			}
			last = name
		}
		for _, name := range names {
			raw, e := r.file(dir, name, "results/"+name, sandbox.MaxResultRecordBytes, false)
			if e != nil {
				return e
			}
			row, e := p.Add(name[:32], raw)
			if e != nil {
				return e
			}
			h := row.Reservation
			owner, ok := policy.owners[h.Ref]
			if !ok || owner.State != sandbox.Destroyed || owner.Backend != "firecracker" || owner.TenantID != h.TenantID || owner.Limits.MaxOutputBytes != h.MaxOutputBytes {
				return ErrConflict
			}
		}
		return r.ctx.Err()
	})
	if e != nil {
		return e
	}
	policy.results, e = p.Observation()
	return e
}

func retainedLedgerOwners(ctx context.Context, root *os.File) (map[sandbox.Ref]sandbox.Record, sandbox.ClosureObservation, error) {
	owners := map[sandbox.Ref]sandbox.Record{}
	p := newTerminalProjection(true)
	e := stableBackendDirectory(ctx, &filesystem{root: root}, "/ledger", sandbox.MaxLedgerRecords, func(dir *os.File, names []string) error {
		last := ""
		for _, name := range names {
			if len(name) != 37 || name[32:] != ".json" || !requestPattern.MatchString(name[:32]) || name <= last {
				return ErrInventory
			}
			last = name
		}
		for _, name := range names {
			raw, e := readCoreRecord(ctx, dir, name, sandbox.MaxLedgerRecordBytes)
			if e != nil {
				return e
			}
			r, e := sandbox.DecodePersistedRecord(raw)
			if e != nil || r.ID != name[:32] || r.Backend != "firecracker" || r.State != sandbox.Destroyed {
				return ErrInventory
			}
			if _, exists := owners[r.Ref]; exists {
				return ErrConflict
			}
			if e = p.add(name[:32], raw); e != nil {
				return e
			}
			owners[r.Ref] = r
		}
		return ctx.Err()
	})
	if e != nil {
		return nil, sandbox.ClosureObservation{}, e
	}
	n, h := p.observation()
	o := sandbox.ClosureObservation{Version: 1, Records: n, RecordsSHA256: h}
	if !o.Valid() {
		return nil, sandbox.ClosureObservation{}, ErrInventory
	}
	return owners, o, nil
}

// Exclusive original state ownership is a CALLER precondition, not established
// by this reader. A bounded context cannot interrupt an in-flight kernel IO.
func readClosedRetainedStateRoot(ctx context.Context, root *os.File, cfg firecracker.Config, metrics bool, lease nodecontrol.MaintenanceRecord, expected sandbox.ResultBoundClosureObservation, sessions session.ClosureObservation) (runtimeRetainedStateInventory, error) {
	return readClosedRetainedStateRootWithCut(ctx, root, cfg, metrics, lease, expected, sessions, nil)
}

// Private TEST cut between full scans only. Never call a callback after the
// final scan, and never treat this seam or a supplied observation as authority.
func readClosedRetainedStateRootWithCut(ctx context.Context, root *os.File, cfg firecracker.Config, metrics bool, lease nodecontrol.MaintenanceRecord, expected sandbox.ResultBoundClosureObservation, sessions session.ClosureObservation, cut func() error) (runtimeRetainedStateInventory, error) {
	var zero runtimeRetainedStateInventory
	if _, bounded := ctx.Deadline(); !bounded || root == nil || cfg.Snapshot != nil || !lease.Valid() || !expected.Valid() || !sessions.Valid() {
		return zero, ErrPolicy
	}
	if e := ctx.Err(); e != nil {
		return zero, e
	}
	pass := func() (runtimeRetainedStateInventory, error) {
		before, _, e := readCoreAuthorityWithMaintenance(ctx, root, lease.After(), &lease)
		if e != nil {
			return zero, e
		}
		if before.LedgerNonterminal != 0 || before.SessionNonterminal != 0 {
			return zero, ErrConflict
		}
		owners, core, e := retainedLedgerOwners(ctx, root)
		if e != nil {
			return zero, e
		}
		s, e := readTerminalProjection(ctx, &filesystem{root: root}, false)
		if e != nil {
			return zero, e
		}
		n, h := s.observation()
		terminal := session.ClosureObservation{Version: 1, Records: n, RecordsSHA256: h}
		if core != expected.Core || terminal != sessions || core.Records != before.LedgerRecords || terminal.Records != before.SessionRecords {
			return zero, ErrConflict
		}
		after, _, e := readCoreAuthorityWithMaintenance(ctx, root, lease.After(), &lease)
		if e != nil {
			return zero, e
		}
		if before != after {
			return zero, ErrConflict
		}
		policy := &retainedRootPolicy{owners: owners}
		// This is the LAST IO stage in a pass: complete root/raw/stat bytes,
		// including every result. No manager/backend callback or repair follows.
		state, e := readClosedStateRootWithResults(ctx, root, cfg, metrics, policy)
		if e != nil {
			return zero, e
		}
		if policy.results != expected.Results {
			return zero, ErrConflict
		}
		return runtimeRetainedStateInventory{State: state, Core: after, CoreTerminal: core, SessionTerminal: terminal, Results: policy.results, DiskResultBytesMatched: true}, nil
	}
	before, e := pass()
	if e != nil {
		return zero, e
	}
	if cut != nil {
		if e = cut(); e != nil {
			return zero, e
		}
	}
	after, e := pass()
	if e != nil {
		return zero, e
	}
	if before != after {
		return zero, ErrConflict
	}
	if e = ctx.Err(); e != nil {
		return zero, e
	}
	return after, nil
}
