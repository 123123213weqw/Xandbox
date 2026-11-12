//go:build linux

package installtxn

import (
	"context"
	"os"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
)

// A read-only component report inside the SAME live original scope. This is
// neither raw result retention/delivery, all-state-root/backend inventory nor
// file-selection/activation permission. Never persist or transfer it as such.
type runtimeTerminalInventory struct {
	Core                                  runtimeCoreInventory
	CoreTerminal                          sandbox.ClosureObservation
	SessionTerminal                       session.ClosureObservation
	RawTerminalMatched                    bool
	ResourcesReclaimed, ActivationAllowed bool
}

// No ordinary Load/constructor, repair, new lock or unbounded aggregate of raw
// record bodies. Sort a bounded complete name set, then read one bounded file.
func readTerminalProjection(ctx context.Context, state *filesystem, core bool) (*terminalProjection, error) {
	path, max, limit := "/sessions", session.MaxRecords, session.MaxRecordBytes
	if core {
		path, max, limit = "/ledger", sandbox.MaxLedgerRecords, sandbox.MaxLedgerRecordBytes
	}
	p := newTerminalProjection(core)
	err := stableBackendDirectory(ctx, state, path, max, func(dir *os.File, names []string) error {
		last := ""
		for _, name := range names {
			if len(name) != 37 || name[32:] != ".json" || !requestPattern.MatchString(name[:32]) || name <= last {
				return ErrInventory
			}
			last = name
			raw, e := readCoreRecord(ctx, dir, name, limit)
			if e != nil {
				return e
			}
			if e = p.add(name[:32], raw); e != nil {
				return e
			}
		}
		return ctx.Err()
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (s *runtimeScope) inspectClosedTerminal(ctx context.Context, base, operation string, stopped *runtimeStoppedWorkProof, m systemManager) (runtimeTerminalInventory, error) {
	return s.inspectClosedTerminalWithProof(ctx, base, operation, stopped, m, m.fs.unitExecutionEmpty)
}

// The existing private model seam varies ONLY manager/kernel-domain absence.
// Original operation/state FDs, exact v4 source/work/close/Stop/anchors and all
// record/path/byte joins remain real. No caller supplies a digest or projection.
func (s *runtimeScope) inspectClosedTerminalWithProof(ctx context.Context, base, operation string, stopped *runtimeStoppedWorkProof, m systemManager, empty func(string) error) (runtimeTerminalInventory, error) {
	var out runtimeTerminalInventory
	if _, bounded := ctx.Deadline(); !bounded || !digestPattern.MatchString(base) || !requestPattern.MatchString(operation) || stopped == nil || stopped.scope != s || empty == nil {
		return out, ErrPolicy
	}
	err := s.run(ctx, func(f *filesystem) error {
		return s.inspectClosedTerminalLocked(ctx, base, operation, stopped, m, empty, f, &out)
	})
	if err != nil {
		return runtimeTerminalInventory{}, err // Never publish a partial report.
	}
	return out, nil
}

// Caller holds s.mu through s.run; no lease reacquisition or manager callback under a file flock.
func (s *runtimeScope) inspectClosedTerminalLocked(ctx context.Context, base, operation string, stopped *runtimeStoppedWorkProof, m systemManager, empty func(string) error, f *filesystem, out *runtimeTerminalInventory) error {
	if s.state == nil || stopped.state != s.state.id || m.fs != f {
		return ErrConflict
	}
	// Re-read every original source/WAL/anchor and kernel/manager absence;
	// neither the live opaque proof nor a matching Stop file is sufficient.
	readBound := func() (runtimeDrainIntent, runtimeCloseCompletion, error) {
		var drain runtimeDrainIntent
		var close runtimeCloseCompletion
		stop, e := s.stoppedStateProof(ctx, base, operation, m, empty)
		if e != nil {
			return drain, close, e
		}
		if stop.Version != 4 || digest(encode(stop)) != stopped.stop || stop.State == nil || *stop.State != s.state.id {
			return drain, close, ErrConflict
		}
		e = f.runtimeDrainLocked(ctx, func() error {
			if e := f.closeStopLink(stop); e != nil {
				return e
			}
			var intent runtimeCloseIntent
			if ok, e := f.readCloseRecord("intent.json", &intent); e != nil || !ok {
				return ErrInventory
			}
			work, completion, e := f.closeWorkLink(intent)
			if e != nil {
				return e
			}
			if ok, e := f.readCloseRecord("complete.json", &close); e != nil || !ok {
				return ErrInventory
			}
			if !close.valid(intent, completion) || digest(encode(work)) != stopped.intent || digest(encode(completion)) != stopped.completion || digest(encode(close)) != stopped.closure {
				return ErrConflict
			}
			drain = work.Drain
			return nil
		})
		return drain, close, e
	}
	drain, closed, e := readBound()
	if e != nil {
		return e
	}
	before, _, e := readCoreAuthorityForDrain(ctx, s.state.root, drain)
	if e != nil {
		return e
	}
	if before.LedgerNonterminal != 0 || before.SessionNonterminal != 0 {
		return ErrConflict
	}
	if e = f.point("runtime-terminal-after-before"); e != nil {
		return e
	}
	state := &filesystem{root: s.state.root}
	core, e := readTerminalProjection(ctx, state, true)
	if e != nil {
		return e
	}
	if e = f.point("runtime-terminal-after-core"); e != nil {
		return e
	}
	sessions, e := readTerminalProjection(ctx, state, false)
	if e != nil {
		return e
	}
	if e = f.point("runtime-terminal-after-sessions"); e != nil {
		return e
	}
	cn, ch := core.observation()
	sn, sh := sessions.observation()
	coreEnd := sandbox.ClosureObservation{Version: 1, Records: cn, RecordsSHA256: ch}
	sessionEnd := session.ClosureObservation{Version: 1, Records: sn, RecordsSHA256: sh}
	if coreEnd != closed.Core || sessionEnd != closed.Sessions || cn != before.LedgerRecords || sn != before.SessionRecords {
		return ErrConflict
	}
	if e = f.point("runtime-terminal-after-projection"); e != nil {
		return e
	}
	drainAfter, closeAfter, e := readBound()
	if e != nil {
		return e
	}
	if digest(encode(drainAfter)) != digest(encode(drain)) || closeAfter != closed {
		return ErrConflict
	}
	if e = f.point("runtime-terminal-after-bound"); e != nil {
		return e
	}
	// Read the full byte set AFTER final manager/source callbacks as well.
	after, _, e := readCoreAuthorityForDrain(ctx, s.state.root, drain)
	if e != nil {
		return e
	}
	if after != before { // Includes complete original raw admission/ledger/session set.
		return ErrConflict
	}
	after.CoreAuthorityParsed = true
	*out = runtimeTerminalInventory{Core: after, CoreTerminal: coreEnd, SessionTerminal: sessionEnd, RawTerminalMatched: true}
	return nil
}
