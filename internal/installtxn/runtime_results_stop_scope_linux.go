//go:build linux

package installtxn

import (
	"context"
	"errors"
	"os"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"golang.org/x/sys/unix"
)

// Original live operation scope, known V2 actor/work closure, physical service
// Stop and ORIGINAL retained BSD state FD only. No legacy conversion, public
// constructor/serialization, backend reclaim, file activation or release right.
type runtimeResultsStoppedWorkProof struct {
	scope  *runtimeScope
	closed runtimeResultsClosedWorkProof
	stop   string
	state  runtimeStateIdentity
}

func resultsStopPolicy(ctx context.Context, base, operation string, proof runtimeStopProofs) error {
	if _, bounded := ctx.Deadline(); !bounded || !digestPattern.MatchString(base) || !requestPattern.MatchString(operation) || proof.process == nil || proof.empty == nil {
		return ErrPolicy
	}
	return nil
}
func (s *runtimeScope) finishCloseAndStopResults(ctx context.Context, base, operation string, c *nodecontrol.PinnedClient, m systemManager) (*runtimeResultsStoppedWorkProof, error) {
	return s.finishCloseAndStopResultsWithProofs(ctx, base, operation, c, m, runtimeStopProofs{process: runtimeProcessProof, empty: m.fs.unitExecutionEmpty})
}
func (s *runtimeScope) finishCloseAndStopResultsWithProofs(ctx context.Context, base, operation string, c *nodecontrol.PinnedClient, m systemManager, proof runtimeStopProofs) (*runtimeResultsStoppedWorkProof, error) {
	if e := resultsStopPolicy(ctx, base, operation, proof); e != nil {
		return nil, e
	}
	// Unknown/orphan Stop prefixes must refuse BEFORE work or close actuation.
	if e := s.run(ctx, func(f *filesystem) error {
		if m.fs != f {
			return ErrPolicy
		}
		return f.runtimeDrainLocked(ctx, func() error {
			if yes, e := f.exists(runtimeResultsStopRoot); e != nil {
				return e
			} else if !yes {
				return nil
			}
			var p runtimeResultsStopIntent
			ok, e := f.readResultsStopRecord("intent.json", &p)
			if e != nil {
				return e
			}
			if !ok || p.Plan.Base != base || p.Plan.Request != operation {
				return ErrConflict
			}
			return f.resultsStopInventory(ctx, p)
		})
	}); e != nil {
		return nil, e
	}
	closed, e := s.finishAndCloseResultsWithProofs(ctx, base, operation, c, m, proof)
	if e != nil {
		return nil, e
	}
	return s.stopClosedResultsWithProofs(ctx, base, operation, closed, c, m, proof)
}
func (s *runtimeScope) stopClosedResultsWithProofs(ctx context.Context, base, operation string, closed *runtimeResultsClosedWorkProof, c *nodecontrol.PinnedClient, m systemManager, proof runtimeStopProofs) (*runtimeResultsStoppedWorkProof, error) {
	if e := resultsStopPolicy(ctx, base, operation, proof); e != nil {
		return nil, e
	}
	if _, e := s.resultsClosedWorkReceipt(ctx, base, operation, closed); e != nil {
		return nil, e
	}
	var intent runtimeResultsStopIntent
	e := s.run(ctx, func(f *filesystem) error {
		if m.fs != f {
			return ErrPolicy
		}
		return f.runtimeDrainLocked(ctx, func() error {
			var ci runtimeResultsCloseIntent
			var cr runtimeResultsCloseCompletion
			if ok, e := f.readResultsCloseRecord("intent.json", &ci); e != nil || !ok {
				return ErrInventory
			}
			if ok, e := f.readResultsCloseRecord("complete.json", &cr); e != nil || !ok {
				return ErrInventory
			}
			work, w, e := f.resultsCloseWorkLink(ci)
			if e != nil {
				return e
			}
			if closed.scope != s || closed.intent != digest(encode(work)) || closed.work != digest(encode(w)) || closed.closure != digest(encode(cr)) || closed.observation != cr || closed.state != *work.Stop.State {
				return ErrConflict
			}
			intent = resultsStopIntent(work, w, ci, cr)
			if e = f.resultsStopInventory(ctx, intent); e != nil {
				return e
			}
			if e = f.mkdir(runtimeResultsStopRoot, 0700); e != nil {
				return e
			}
			return f.runtimeRecord(runtimeResultsStopRoot+"/intent.json", nil, encode(intent), "runtime-results-stop-intent")
		})
	})
	if e != nil {
		return nil, e
	}
	// The durable new intent is required even when both originals already died.
	// ONE original Stop algorithm; its projected v2 plan never becomes a legacy
	// stored receipt or a work/closure certificate. No callbacks across flock.
	if _, e = s.stopJournalWithProofs(ctx, base, operation, c, m, proof, runtimePhysicalStopJournal{bound: &intent}); e != nil {
		return nil, e
	}
	if e = s.ownResultsStoppedState(ctx, intent, m, proof.empty); e != nil {
		return nil, e
	}
	out := &runtimeResultsStoppedWorkProof{scope: s, closed: *closed, stop: digest(encode(intent)), state: closed.state}
	if _, e = s.resultsStoppedWorkReceiptWithProof(ctx, base, operation, out, m, proof.empty); e != nil {
		return nil, e
	}
	return out, nil
}

// Fresh source/known work+result closure/physical journal/manager+kernel absence
// proof. No file flock spans manager or kernel-model callbacks, and files are
// re-read AFTER them. A zero manager PID is never accepted for a still-live or
// reused original numeric PID. No actor outcome is inferred from process death.
func (s *runtimeScope) resultsStoppedStateProof(ctx context.Context, p runtimeResultsStopIntent, m systemManager, empty func(string) error) error {
	if m.fs != s.fs || empty == nil {
		return ErrPolicy
	}
	read := func() error {
		return s.fs.runtimeDrainLocked(ctx, func() error {
			if e := s.fs.resultsStopInventory(ctx, p); e != nil {
				return e
			}
			if e := s.fs.exact(runtimeResultsStopRoot+"/intent.json", encode(p), 0600); e != nil {
				return e
			}
			return s.fs.exact(runtimeResultsStopRoot+"/stopped.json", encode(runtimeResultsStopReceipt{Version: 1, Input: digest(encode(p))}), 0600)
		})
	}
	if e := read(); e != nil {
		return e
	}
	if e := m.enabledLinks(); e != nil {
		return e
	}
	for _, u := range []string{IngressUnit, MainUnit} {
		o, e := m.observe(ctx, u)
		if e != nil {
			return e
		}
		if !validManagedUnit(o, u) || o.pid != 0 || o.active != "inactive" && o.active != "failed" {
			return ErrConflict
		}
		if e = empty(u); e != nil {
			return e
		}
	}
	for _, id := range []*nodecontrol.ProcessIdentity{&p.Plan.Main, p.Plan.Ingress} {
		if id == nil {
			continue
		}
		w, e := nodecontrol.NewProcessWatch(id.PID)
		if errors.Is(e, unix.ESRCH) {
			continue
		}
		if w != nil {
			w.Close()
		}
		if e != nil {
			return e
		}
		return ErrConflict
	}
	if e := s.valid(ctx); e != nil {
		return e
	}
	return read()
}

// POSITIVE ownership uses the original retained FD's process-local lock record,
// not merely a successful earlier flock or a global /proc/locks row count.
// Unlocked/shared/alias/foreign/waiter/format uncertainty refuses. This opens no
// second controller.lock FD and never reacquires or repairs a missing lock.
func (s *runtimeScope) resultsStateLeaseHeld(ctx context.Context, id runtimeStateIdentity) error {
	if s.state == nil || s.state.id != id {
		return ErrConflict
	}
	if e := s.state.verify(s.fs); e != nil {
		return e
	}
	if e := stateOriginalFDLock(ctx, id, os.Getpid()); e != nil {
		return e
	}
	raw, e := boundedProcessFile("/proc/locks", 4<<20)
	if e != nil {
		return e
	}
	if e = stateKernelLockVeto(raw, id, os.Getpid()); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	return s.state.verify(s.fs)
}
func (s *runtimeScope) ownResultsStoppedState(ctx context.Context, p runtimeResultsStopIntent, m systemManager, empty func(string) error) error {
	return s.run(ctx, func(f *filesystem) error {
		if e := s.resultsStoppedStateProof(ctx, p, m, empty); e != nil {
			return e
		}
		if s.state != nil {
			return s.resultsStateLeaseHeld(ctx, *p.Plan.State)
		}
		lease, e := f.openRuntimeState()
		if e != nil {
			return e
		}
		keep := false
		defer func() {
			if !keep {
				lease.close()
			}
		}()
		if lease.id != *p.Plan.State {
			return ErrConflict
		}
		if e = acquireRuntimeState(lease); e != nil {
			return e
		}
		if e = f.point("runtime-results-state-locked"); e != nil {
			return e
		}
		if e = lease.verify(f); e != nil {
			return e
		}
		if e = s.resultsStoppedStateProof(ctx, p, m, empty); e != nil {
			return e
		}
		if e = lease.verify(f); e != nil {
			return e
		}
		// This temporary ownership is erased on ANY final FD-local veto.
		s.state = lease
		if e = s.resultsStateLeaseHeld(ctx, *p.Plan.State); e != nil {
			s.state = nil
			return e
		}
		keep = true
		return nil
	})
}
func (s *runtimeScope) resultsStoppedWorkReceipt(ctx context.Context, base, operation string, p *runtimeResultsStoppedWorkProof, m systemManager) (runtimeResultsCloseCompletion, error) {
	return s.resultsStoppedWorkReceiptWithProof(ctx, base, operation, p, m, m.fs.unitExecutionEmpty)
}
func (s *runtimeScope) resultsStoppedWorkReceiptWithProof(ctx context.Context, base, operation string, p *runtimeResultsStoppedWorkProof, m systemManager, empty func(string) error) (runtimeResultsCloseCompletion, error) {
	var zero, out runtimeResultsCloseCompletion
	if _, bounded := ctx.Deadline(); !bounded || !digestPattern.MatchString(base) || !requestPattern.MatchString(operation) || p == nil || p.scope != s || p.closed.scope != s || empty == nil {
		return zero, ErrPolicy
	}
	e := s.run(ctx, func(f *filesystem) error {
		var intent runtimeResultsStopIntent
		read := func() error {
			return f.runtimeDrainLocked(ctx, func() error {
				var e error
				if ok, err := f.readResultsStopRecord("intent.json", &intent); err != nil || !ok {
					return ErrInventory
				}
				if !intent.valid() || intent.Plan.Base != base || intent.Plan.Request != operation || intent.Plan.State == nil || *intent.Plan.State != p.state || intent.WorkIntent != p.closed.intent || intent.Work != p.closed.work || intent.Closure != p.closed.closure || digest(encode(intent)) != p.stop {
					return ErrConflict
				}
				if e = f.resultsStopInventory(ctx, intent); e != nil {
					return e
				}
				var r runtimeResultsCloseCompletion
				if ok, err := f.readResultsCloseRecord("complete.json", &r); err != nil || !ok {
					return ErrInventory
				}
				if r != p.closed.observation || p.closed.state != p.state {
					return ErrConflict
				}
				out = r
				return nil
			})
		}
		if e := read(); e != nil {
			return e
		}
		if e := s.resultsStateLeaseHeld(ctx, p.state); e != nil {
			return e
		}
		if e := s.resultsStoppedStateProof(ctx, intent, m, empty); e != nil {
			return e
		}
		if e := s.resultsStateLeaseHeld(ctx, p.state); e != nil {
			return e
		}
		return read() // No model callback or mutator after final raw/source link.
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}
