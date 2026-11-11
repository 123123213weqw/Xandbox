//go:build linux

package installtxn

import (
	"context"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
)

// Bound to ONE original OFD operation scope and original daemon/state identity.
// This certifies known anchored actor/work closure, NEVER physical Stop, a BSD
// state lease held by this operator, backend reclaim or file activation. It has
// no serialization/constructor/old Stop conversion or public caller bypass.
type runtimeResultsClosedWorkProof struct {
	scope                 *runtimeScope
	intent, work, closure string
	state                 runtimeStateIdentity
	observation           runtimeResultsCloseCompletion
}

func (s *runtimeScope) finishAndCloseResults(ctx context.Context, base, operation string, c *nodecontrol.PinnedClient, m systemManager) (*runtimeResultsClosedWorkProof, error) {
	return s.finishAndCloseResultsWithProofs(ctx, base, operation, c, m, runtimeStopProofs{process: runtimeProcessProof, empty: m.fs.unitExecutionEmpty})
}

// The private seam varies only manager/image/placement/kernel domains; the real
// pinned Unix peer, process incarnation, state ownership, source/WAL/anchors and
// actual Broker/Core/FileResultStore remain required. No Stats/report callback.
func (s *runtimeScope) finishAndCloseResultsWithProofs(ctx context.Context, base, operation string, c *nodecontrol.PinnedClient, m systemManager, proof runtimeStopProofs) (*runtimeResultsClosedWorkProof, error) {
	p, w, e := s.finishKnownAcceptedWork(ctx, base, operation, c, m, proof)
	if e != nil {
		return nil, e
	}
	r, e := s.closeBoundResultsRuntime(ctx, p, w, c, m, proof)
	if e != nil {
		return nil, e
	}
	intent := resultsCloseIntent(p, w)
	var out *runtimeResultsClosedWorkProof
	e = s.run(ctx, func(f *filesystem) error {
		return f.runtimeDrainLocked(ctx, func() error {
			if _, _, e := f.runtimeStopBase(ctx, base, operation); e != nil {
				return e
			}
			if e := f.resultsCloseLink(intent, r); e != nil {
				return e
			}
			if s.state != nil && s.state.id != *p.Stop.State {
				return ErrConflict
			}
			out = &runtimeResultsClosedWorkProof{scope: s, intent: digest(encode(p)), work: digest(encode(w)), closure: digest(encode(r)), state: *p.Stop.State, observation: r}
			return nil
		})
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}

// Rejoin the SAME still-held operation FD and every original source/work/close
// final/anchor before returning a known receipt. Cached fields alone do not
// suffice. This is still NOT a physical Stop/state-lease/activation permission.
func (s *runtimeScope) resultsClosedWorkReceipt(ctx context.Context, base, operation string, p *runtimeResultsClosedWorkProof) (runtimeResultsCloseCompletion, error) {
	var zero runtimeResultsCloseCompletion
	if _, bounded := ctx.Deadline(); !bounded || !digestPattern.MatchString(base) || !requestPattern.MatchString(operation) || p == nil || p.scope != s {
		return zero, ErrPolicy
	}
	var out runtimeResultsCloseCompletion
	e := s.run(ctx, func(f *filesystem) error {
		return f.runtimeDrainLocked(ctx, func() error {
			if _, _, e := f.runtimeStopBase(ctx, base, operation); e != nil {
				return e
			}
			var intent runtimeResultsCloseIntent
			var r runtimeResultsCloseCompletion
			if ok, e := f.readResultsCloseRecord("intent.json", &intent); e != nil || !ok {
				return ErrInventory
			}
			if ok, e := f.readResultsCloseRecord("complete.json", &r); e != nil || !ok {
				return ErrInventory
			}
			work, w, e := f.resultsCloseWorkLink(intent)
			if e != nil {
				return e
			}
			if digest(encode(work)) != p.intent || digest(encode(w)) != p.work || digest(encode(r)) != p.closure || r != p.observation || *work.Stop.State != p.state || s.state != nil && s.state.id != p.state {
				return ErrConflict
			}
			if e = f.resultsCloseLink(intent, r); e != nil {
				return e
			}
			out = r
			return nil
		})
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}
