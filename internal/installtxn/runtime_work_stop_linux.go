//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

const runtimeWorkStopRoot = "/etc/xandbox-runtime-work"
const runtimeWorkStopAnchor = "/etc/xandbox-runtime-work.identity"
const runtimeWorkStopAnchorScratch = "/etc/.xandbox-runtime-work.identity.next"

// The original state/ingress identities are captured while the original daemon
// is alive, BEFORE the work fence or any Stop effect. No new Before/identity is
// inferred from a dead/replacement process or from current pathnames on retry.

func (p runtimeWorkStopIntent) valid() bool {
	return p.Version == 1 && p.Policy == "finish-only-v1" && validRuntimeMaintenance(p.Drain) && validRuntimeDrain(p.Drain) && p.Stop.Version == 2 && validRuntimeStop(p.Stop) && p.Stop.Base == p.Drain.Base && p.Stop.Request == p.Drain.Request && p.Stop.Drain == digest(encode(p.Drain)) && p.Stop.Main == p.Drain.Process
}
func (r runtimeWorkCompletion) valid(p runtimeWorkStopIntent) bool {
	return p.valid() && r.Version == 1 && r.Input == digest(encode(p)) && r.Work.Complete() && r.Work.Succeeded >= 0
}
func (p runtimeWorkStopIntent) stopped(r runtimeWorkCompletion) runtimeStopIntent {
	s := p.Stop
	s.Version, s.Work = 3, digest(encode(r))
	return s
}

// Only COMPLETE canonical finals/scratches are decoded as authority. An unknown
// partial intent/completion is never repaired by inventing old work outcomes.
func (f *filesystem) readWorkStopRecord(name string, value any) (bool, error) {
	final := runtimeWorkStopRoot + "/" + name
	scratch := runtimeWorkStopRoot + "/." + name + ".next"
	b, e := f.read(final, MaxPlan, 0600)
	if e == nil {
		if yes, err := f.exists(scratch); err != nil || yes {
			return false, ErrInventory
		}
	} else if errors.Is(e, unix.ENOENT) {
		b, e = f.read(scratch, MaxPlan, 0600)
		if errors.Is(e, unix.ENOENT) {
			return false, nil
		}
	}
	if e != nil {
		return false, e
	}
	if !decodeCanonicalRuntime(b, value) {
		return false, ErrInventory
	}
	return true, nil
}
func (f *filesystem) workStopInventory(p *runtimeWorkStopIntent, r *runtimeWorkCompletion) error {
	names, e := f.names(runtimeWorkStopRoot)
	if errors.Is(e, unix.ENOENT) {
		for _, n := range []string{runtimeWorkStopAnchor, filepath.Dir(runtimeWorkStopAnchor) + "/." + filepath.Base(runtimeWorkStopAnchor) + ".next"} {
			if yes, err := f.exists(n); err != nil {
				return err
			} else if yes {
				return ErrInventory
			}
		}
		return nil
	}
	if e != nil {
		return e
	}
	if e = f.privateDirectory(runtimeWorkStopRoot, 0700); e != nil {
		return e
	}
	if p == nil {
		return ErrInventory
	}
	if r == nil {
		for _, name := range []string{runtimeWorkStopAnchor, runtimeWorkStopAnchorScratch} {
			if yes, err := f.exists(name); err != nil {
				return err
			} else if yes {
				return ErrInventory
			}
		}
	}
	for _, n := range names {
		var want []byte
		final := n
		switch n {
		case "intent.json", ".intent.json.next":
			if p == nil {
				return ErrInventory
			}
			want = encode(*p)
			final = "intent.json"
		case "complete.json", ".complete.json.next":
			if r == nil {
				return ErrInventory
			}
			want = encode(*r)
			final = "complete.json"
		default:
			return ErrInventory
		}
		if n[0] == '.' {
			if yes, err := f.exists(runtimeWorkStopRoot + "/" + final); err != nil || yes {
				return ErrInventory
			}
		}
		if e = f.exact(runtimeWorkStopRoot+"/"+n, want, 0600); e != nil {
			return e
		}
	}
	return nil
}
func (f *filesystem) workCompletionAnchor(r runtimeWorkCompletion) (bool, error) {
	want := []byte(digest(encode(r)) + "\n")
	b, e := f.read(runtimeWorkStopAnchor, int64(len(want)), 0600)
	if errors.Is(e, unix.ENOENT) {
		b, e = f.read(runtimeWorkStopAnchorScratch, int64(len(want)), 0600)
		if errors.Is(e, unix.ENOENT) {
			return false, nil
		}
	} else if e == nil {
		if yes, err := f.exists(filepath.Dir(runtimeWorkStopAnchor) + "/." + filepath.Base(runtimeWorkStopAnchor) + ".next"); err != nil || yes {
			return false, ErrInventory
		}
	}
	if e != nil {
		return false, e
	}
	if !bytes.Equal(b, want) {
		return false, ErrInventory
	}
	return true, nil
}

// This is also used by the original physical Stop/state reader for explicit v3.
// It is strictly read-only; no ordinary Load/backend constructor or repair.
func (f *filesystem) workStopLink(stop runtimeStopIntent) error {
	var p runtimeWorkStopIntent
	ok, e := f.readWorkStopRecord("intent.json", &p)
	if e != nil {
		return e
	}
	if !ok || !p.valid() {
		return ErrInventory
	}
	var r runtimeWorkCompletion
	ok, e = f.readWorkStopRecord("complete.json", &r)
	if e != nil {
		return e
	}
	if !ok || !r.valid(p) {
		return ErrInventory
	}
	if e = f.workStopInventory(&p, &r); e != nil {
		return e
	}
	if e = f.exact(runtimeWorkStopRoot+"/intent.json", encode(p), 0600); e != nil {
		return e
	}
	if e = f.exact(runtimeWorkStopRoot+"/complete.json", encode(r), 0600); e != nil {
		return e
	}
	if e = f.exact(runtimeWorkStopAnchor, []byte(digest(encode(r))+"\n"), 0600); e != nil {
		return e
	}
	if !bytes.Equal(encode(stop), encode(p.stopped(r))) {
		return ErrConflict
	}
	drain, e := f.runtimeDrainReadIntent()
	if e != nil {
		return e
	}
	if !bytes.Equal(encode(drain), encode(p.Drain)) {
		return ErrConflict
	}
	if e = f.runtimeDrainInventory(&drain); e != nil {
		return e
	}
	if e = f.exact(runtimeDrainRoot+"/drain.json", encode(runtimeDrainReceipt{Version: 1, Input: digest(encode(drain)), After: drainedRuntimeState(drain)}), 0600); e != nil {
		return e
	}
	return nil
}

// Observe each exact original incarnation (or prove its numeric PID absent on
// recovery). Never adopt replacements or signal any PID. Only manager/image/
// placement/cgroup positives can be modeled by the private software test seam.
func (s *runtimeScope) workStopPeers(ctx context.Context, t transaction, p runtimeWorkStopIntent, terminal *sandbox.AcceptedWorkStatus, c *nodecontrol.PinnedClient, m systemManager, proof runtimeStopProofs, allowAbsent bool) error {
	if e := s.valid(ctx); e != nil {
		return e
	}
	if e := s.fs.runtimeStateMatches(*p.Stop.State); e != nil {
		return e
	}
	if e := m.enabledLinks(); e != nil {
		return e
	}
	for _, item := range []struct {
		unit string
		id   *nodecontrol.ProcessIdentity
	}{{MainUnit, &p.Stop.Main}, {IngressUnit, p.Stop.Ingress}} {
		before, e := m.observe(ctx, item.unit)
		if e != nil {
			return e
		}
		if !validManagedUnit(before, item.unit) {
			return ErrInventory
		}
		if before.pid == 0 && (before.active == "inactive" || before.active == "failed") {
			if item.id != nil {
				if !allowAbsent {
					return ErrConflict
				}
				watch, err := nodecontrol.NewProcessWatch(item.id.PID)
				if watch != nil {
					watch.Close()
				}
				if !errors.Is(err, unix.ESRCH) {
					if err != nil {
						return err
					}
					return ErrConflict
				}
			}
		} else {
			if item.id == nil || before.pid != item.id.PID || before.active != "active" {
				return ErrConflict
			}
			watch, e := nodecontrol.NewProcessWatch(item.id.PID)
			if e != nil {
				return e
			}
			check := func() error {
				if watch.Identity() != *item.id {
					return ErrConflict
				}
				if e := watch.Alive(); e != nil {
					return e
				}
				if e := proof.process(ctx, t, item.unit, *item.id); e != nil {
					return e
				}
				if item.unit == MainUnit {
					dir, e := s.fs.directory(stateDir)
					if e != nil {
						return e
					}
					if c == nil {
						dir.Close()
						return ErrConflict
					}
					e = c.VerifyDirectory(dir)
					dir.Close()
					if e != nil {
						return e
					}
					if c == nil || c.Identity() != p.Stop.Main {
						return ErrConflict
					}
					if e := runtimeStateOwnedBy(*p.Stop.State, p.Stop.Main); e != nil {
						return e
					}
					if terminal == nil {
						if e := runtimeLiveDrain(ctx, p.Drain, c); e != nil {
							return e
						}
					} else {
						r, e := c.QuiesceMaintenance(ctx, *p.Drain.Maintenance)
						if e != nil {
							return e
						}
						if !r.Work.Complete() || r.Work != *terminal {
							return errAcceptedWork
						}
					}
				}
				return watch.Alive()
			}
			e = check()
			watch.Close()
			if e != nil {
				return e
			}
		}
		after, e := m.observe(ctx, item.unit)
		if e != nil {
			return e
		}
		if before != after {
			return ErrConflict
		}
	}
	return s.valid(ctx)
}

func (s *runtimeScope) workStopInput(ctx context.Context, base, operation string, c *nodecontrol.PinnedClient, m systemManager, proof runtimeStopProofs) (runtimeWorkStopIntent, error) {
	var p runtimeWorkStopIntent
	e := s.run(ctx, func(f *filesystem) error {
		if m.fs != f {
			return ErrPolicy
		}
		var tx transaction
		var d runtimeDrainIntent
		var exists bool
		if e := f.runtimeDrainLocked(ctx, func() error {
			var e error
			tx, d, e = f.runtimeStopBase(ctx, base, operation)
			if e != nil {
				return e
			}
			if !validRuntimeMaintenance(d) {
				return ErrConflict
			}
			exists, e = f.readWorkStopRecord("intent.json", &p)
			if e != nil {
				return e
			}
			if exists {
				if !p.valid() || !bytes.Equal(encode(p.Drain), encode(d)) {
					return ErrConflict
				}
				return f.runtimeStateMatches(*p.Stop.State)
			}
			if e = f.workStopInventory(nil, nil); e != nil {
				return e
			}
			if yes, e := f.exists(runtimeStopRoot); e != nil {
				return e
			} else if yes {
				return ErrConflict
			}
			return nil
		}); e != nil {
			return e
		}
		if !exists {
			if c == nil || c.Identity() != d.Process {
				return ErrConflict
			}
			dir, e := f.directory(stateDir)
			if e != nil {
				return e
			}
			e = c.VerifyDirectory(dir)
			dir.Close()
			if e != nil {
				return e
			}
			lease, e := f.openRuntimeState()
			if e != nil {
				return e
			}
			id := lease.id
			lease.close()
			p = runtimeWorkStopIntent{Version: 1, Policy: "finish-only-v1", Drain: d, Stop: runtimeStopIntent{Version: 2, Base: base, Request: operation, Drain: digest(encode(d)), Main: d.Process, State: &id}}
			ingress, e := m.observe(ctx, IngressUnit)
			if e != nil {
				return e
			}
			if !validManagedUnit(ingress, IngressUnit) {
				return ErrInventory
			}
			if ingress.pid > 1 {
				watch, e := nodecontrol.NewProcessWatch(ingress.pid)
				if e != nil {
					return e
				}
				id := watch.Identity()
				watch.Close()
				p.Stop.Ingress = &id
			} else if ingress.pid != 0 || ingress.active != "inactive" && ingress.active != "failed" {
				return ErrConflict
			}
			if !p.valid() {
				return ErrInventory
			}
			if e = s.workStopPeers(ctx, tx, p, nil, c, m, proof, false); e != nil {
				return e
			}
		}
		return f.runtimeDrainLocked(ctx, func() error {
			_, current, e := f.runtimeStopBase(ctx, base, operation)
			if e != nil {
				return e
			}
			if !bytes.Equal(encode(current), encode(p.Drain)) {
				return ErrConflict
			}
			var r runtimeWorkCompletion
			has, e := f.readWorkStopRecord("complete.json", &r)
			if e != nil {
				return e
			}
			var known *runtimeWorkCompletion
			if has {
				if !r.valid(p) {
					return ErrInventory
				}
				known = &r
			}
			if e = f.workStopInventory(&p, known); e != nil {
				return e
			}
			if e = f.mkdir(runtimeWorkStopRoot, 0700); e != nil {
				return e
			}
			return f.runtimeRecord(runtimeWorkStopRoot+"/intent.json", nil, encode(p), "runtime-work-stop-intent")
		})
	})
	return p, e
}

// The opaque result certifies known accepted work, physical Stop and currently
// retained ORIGINAL state ownership only. NOT backend reclaim/file activation.
type runtimeStoppedWorkProof struct {
	scope                    *runtimeScope
	intent, completion, stop string
	closure                  string
	state                    runtimeStateIdentity
}

func (s *runtimeScope) finishAndStop(ctx context.Context, base, operation string, c *nodecontrol.PinnedClient, m systemManager) (*runtimeStoppedWorkProof, error) {
	return s.finishAndStopWithProofs(ctx, base, operation, c, m, runtimeStopProofs{process: runtimeProcessProof, empty: m.fs.unitExecutionEmpty})
}
func (s *runtimeScope) finishAndStopWithProofs(ctx context.Context, base, operation string, c *nodecontrol.PinnedClient, m systemManager, proof runtimeStopProofs) (*runtimeStoppedWorkProof, error) {
	if _, ok := ctx.Deadline(); !ok || !digestPattern.MatchString(base) || !requestPattern.MatchString(operation) || proof.process == nil || proof.empty == nil {
		return nil, ErrPolicy
	}
	p, e := s.workStopInput(ctx, base, operation, c, m, proof)
	if e != nil {
		return nil, e
	}
	var r runtimeWorkCompletion
	var anchored bool
	e = s.run(ctx, func(f *filesystem) error {
		return f.runtimeDrainLocked(ctx, func() error {
			has, e := f.readWorkStopRecord("complete.json", &r)
			if e != nil {
				return e
			}
			if has {
				if !r.valid(p) {
					return ErrInventory
				}
				if e = f.workStopInventory(&p, &r); e != nil {
					return e
				}
				anchored, e = f.workCompletionAnchor(r)
				return e
			}
			return f.workStopInventory(&p, nil)
		})
	})
	if e != nil {
		return nil, e
	}
	if !anchored {
		// No accepted-work outcome is inferred from a stopped/replacement node.
		// Reprove the SAME live gate before completing any unanchored record.
		live, e := s.quiesceAcceptedWorkWithProof(ctx, base, operation, c, m, proof.process)
		if e != nil {
			return nil, e
		}
		if live.scope != s || live.intent != digest(encode(p.Drain)) || live.process != p.Stop.Main || live.record != *p.Drain.Maintenance || !live.terminal.Complete() {
			return nil, ErrConflict
		}
		want := runtimeWorkCompletion{Version: 1, Input: digest(encode(p)), Work: live.terminal}
		if r.Version != 0 && !bytes.Equal(encode(r), encode(want)) {
			return nil, ErrConflict
		}
		r = want
		e = s.run(ctx, func(f *filesystem) error {
			var tx transaction
			if e := f.runtimeDrainLocked(ctx, func() error { var e error; tx, _, e = f.runtimeStopBase(ctx, base, operation); return e }); e != nil {
				return e
			}
			if e := s.workStopPeers(ctx, tx, p, &r.Work, c, m, proof, false); e != nil {
				return e
			}
			return f.runtimeDrainLocked(ctx, func() error {
				if e := f.workStopInventory(&p, &r); e != nil {
					return e
				}
				if e := f.exact(runtimeWorkStopRoot+"/intent.json", encode(p), 0600); e != nil {
					return e
				}
				if e := f.runtimeRecord(runtimeWorkStopRoot+"/complete.json", nil, encode(r), "runtime-work-stop-complete"); e != nil {
					return e
				}
				return f.runtimeRecord(runtimeWorkStopAnchor, nil, []byte(digest(encode(r))+"\n"), "runtime-work-stop-anchor")
			})
		})
		if e != nil {
			return nil, e
		}
	}
	// Promote/resync complete known work scratches BEFORE the close intent
	// consumes their exact final link. This never invents an unknown outcome.
	e = s.run(ctx, func(f *filesystem) error {
		var tx transaction
		if e := f.runtimeDrainLocked(ctx, func() error { var e error; tx, _, e = f.runtimeStopBase(ctx, base, operation); return e }); e != nil {
			return e
		}
		if e := s.workStopPeers(ctx, tx, p, &r.Work, c, m, proof, true); e != nil {
			return e
		}
		return f.runtimeDrainLocked(ctx, func() error {
			if _, _, e := f.runtimeStopBase(ctx, base, operation); e != nil {
				return e
			}
			if e := f.workStopInventory(&p, &r); e != nil {
				return e
			}
			if e := f.runtimeRecord(runtimeWorkStopRoot+"/intent.json", nil, encode(p), "runtime-work-stop-intent"); e != nil {
				return e
			}
			if e := f.runtimeRecord(runtimeWorkStopRoot+"/complete.json", nil, encode(r), "runtime-work-stop-complete"); e != nil {
				return e
			}
			if e := f.runtimeRecord(runtimeWorkStopAnchor, nil, []byte(digest(encode(r))+"\n"), "runtime-work-stop-anchor"); e != nil {
				return e
			}
			return f.workStopLink(p.stopped(r))
		})
	})
	if e != nil {
		return nil, e
	}
	// Work completion alone does not authorize killing the runtime. The actual
	// bound Broker/Core closure must be recorded and independently anchored FIRST.
	closed, e := s.closeBoundRuntime(ctx, p, r, c, m, proof)
	if e != nil {
		return nil, e
	}
	stop := p.stopped(r)
	stop.Version, stop.Close = 4, digest(encode(closed))
	// Known, independently anchored work AND closure survive coordinator/daemon
	// death. Unknown/no-anchor closure cannot be inferred from a dead process.
	e = s.run(ctx, func(f *filesystem) error {
		var tx transaction
		if e := f.runtimeDrainLocked(ctx, func() error { var e error; tx, _, e = f.runtimeStopBase(ctx, base, operation); return e }); e != nil {
			return e
		}
		if e := s.workStopPeers(ctx, tx, p, &r.Work, c, m, proof, true); e != nil {
			return e
		}
		return f.runtimeDrainLocked(ctx, func() error {
			if e := f.workStopInventory(&p, &r); e != nil {
				return e
			}
			if e := f.runtimeRecord(runtimeWorkStopRoot+"/intent.json", nil, encode(p), "runtime-work-stop-intent"); e != nil {
				return e
			}
			if e := f.runtimeRecord(runtimeWorkStopRoot+"/complete.json", nil, encode(r), "runtime-work-stop-complete"); e != nil {
				return e
			}
			if e := f.runtimeRecord(runtimeWorkStopAnchor, nil, []byte(digest(encode(r))+"\n"), "runtime-work-stop-anchor"); e != nil {
				return e
			}
			if e := f.closeStopLink(stop); e != nil {
				return e
			}
			if e := f.stopInventory(&stop); e != nil {
				return e
			}
			if e := f.mkdir(runtimeStopRoot, 0700); e != nil {
				return e
			}
			return f.runtimeRecord(runtimeStopRoot+"/intent.json", nil, encode(stop), "runtime-work-stop-publish")
		})
	})
	if e != nil {
		return nil, e
	}
	if _, e = s.stopWithProofs(ctx, base, operation, c, m, proof); e != nil {
		return nil, e
	}
	if e = s.ownStoppedStateWithProof(ctx, base, operation, m, proof.empty); e != nil {
		return nil, e
	}
	var result *runtimeStoppedWorkProof
	e = s.run(ctx, func(f *filesystem) error {
		return f.runtimeDrainLocked(ctx, func() error {
			_, drain, e := f.runtimeStopBase(ctx, base, operation)
			if e != nil {
				return e
			}
			if !bytes.Equal(encode(drain), encode(p.Drain)) {
				return ErrConflict
			}
			if e := f.closeStopLink(stop); e != nil {
				return e
			}
			if e := f.exact(runtimeStopRoot+"/intent.json", encode(stop), 0600); e != nil {
				return e
			}
			if e := f.exact(runtimeStopRoot+"/stopped.json", encode(runtimeStopReceipt{Version: 1, Input: digest(encode(stop))}), 0600); e != nil {
				return e
			}
			if s.state == nil || s.state.id != *stop.State {
				return ErrConflict
			}
			if e := s.state.verify(f); e != nil {
				return e
			}
			result = &runtimeStoppedWorkProof{scope: s, intent: digest(encode(p)), completion: digest(encode(r)), closure: digest(encode(closed)), stop: digest(encode(stop)), state: s.state.id}
			return nil
		})
	})
	if e != nil {
		return nil, e
	}
	return result, nil
}
