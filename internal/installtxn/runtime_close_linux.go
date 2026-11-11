//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"golang.org/x/sys/unix"
	"time"
)

const runtimeCloseRoot = "/etc/xandbox-runtime-close"
const runtimeCloseAnchor = "/etc/xandbox-runtime-close.identity"
const runtimeCloseAnchorScratch = "/etc/.xandbox-runtime-close.identity.next"

var errRuntimeClose = errors.New("bound runtime closure failed or has unknown outcomes; maintenance remains fenced")

// Durable BEFORE the irreversible live RPC. Original v3 Stop transitively binds
// source, Before, owner, process/state and known work; v4 adds closure's anchor.

func closeIntent(p runtimeWorkStopIntent, w runtimeWorkCompletion) runtimeCloseIntent {
	return runtimeCloseIntent{Version: 1, Policy: "close-bound-runtime-v1", Input: digest(encode(p)), Stop: p.stopped(w)}
}
func (p runtimeCloseIntent) valid(work runtimeWorkStopIntent, w runtimeWorkCompletion) bool {
	return w.valid(work) && p.Version == 1 && p.Policy == "close-bound-runtime-v1" && p.Input == digest(encode(work)) && bytes.Equal(encode(p.Stop), encode(work.stopped(w)))
}
func (r runtimeCloseCompletion) valid(p runtimeCloseIntent, w runtimeWorkCompletion) bool {
	return r.Version == 1 && r.Input == digest(encode(p)) && r.Work == w.Work && r.Work.Complete() && r.Core.Valid() && r.Sessions.Valid()
}
func (p runtimeCloseIntent) stopped(r runtimeCloseCompletion) runtimeStopIntent {
	stop := p.Stop
	stop.Version, stop.Close = 4, digest(encode(r))
	return stop
}

// Complete canonical finals/scratches ONLY. Partial outcome bytes are unknown,
// never a prefix from which a successful close can be fabricated.
func (f *filesystem) readCloseRecord(name string, value any) (bool, error) {
	final, scratch := runtimeCloseRoot+"/"+name, runtimeCloseRoot+"/."+name+".next"
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
func (f *filesystem) closeInventory(p *runtimeCloseIntent, r *runtimeCloseCompletion) error {
	names, e := f.names(runtimeCloseRoot)
	missing := errors.Is(e, unix.ENOENT)
	if e != nil && !missing {
		return e
	}
	if missing || r == nil {
		for _, path := range []string{runtimeCloseAnchor, runtimeCloseAnchorScratch} {
			if yes, err := f.exists(path); err != nil {
				return err
			} else if yes {
				return ErrInventory
			}
		}
	}
	if missing {
		if p != nil || r != nil {
			return ErrInventory
		}
		return nil
	}
	if p == nil || f.privateDirectory(runtimeCloseRoot, 0700) != nil {
		return ErrInventory
	}
	for _, name := range names {
		var want []byte
		final := ""
		switch name {
		case "intent.json", ".intent.json.next":
			want, final = encode(*p), "intent.json"
		case "complete.json", ".complete.json.next":
			if r == nil {
				return ErrInventory
			}
			want, final = encode(*r), "complete.json"
		default:
			return ErrInventory
		}
		if name[0] == '.' {
			if yes, err := f.exists(runtimeCloseRoot + "/" + final); err != nil || yes {
				return ErrInventory
			}
		}
		if e = f.exact(runtimeCloseRoot+"/"+name, want, 0600); e != nil {
			return e
		}
	}
	return nil
}
func (f *filesystem) closeCompletionAnchor(r runtimeCloseCompletion) (bool, error) {
	want := []byte(digest(encode(r)) + "\n")
	b, e := f.read(runtimeCloseAnchor, int64(len(want)), 0600)
	if errors.Is(e, unix.ENOENT) {
		b, e = f.read(runtimeCloseAnchorScratch, int64(len(want)), 0600)
		if errors.Is(e, unix.ENOENT) {
			return false, nil
		}
	} else if e == nil {
		if yes, err := f.exists(runtimeCloseAnchorScratch); err != nil || yes {
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
func (f *filesystem) closeWorkLink(p runtimeCloseIntent) (runtimeWorkStopIntent, runtimeWorkCompletion, error) {
	var work runtimeWorkStopIntent
	var w runtimeWorkCompletion
	ok, e := f.readWorkStopRecord("intent.json", &work)
	if e != nil {
		return work, w, e
	}
	if !ok || !work.valid() {
		return work, w, ErrInventory
	}
	ok, e = f.readWorkStopRecord("complete.json", &w)
	if e != nil {
		return work, w, e
	}
	if !ok || !p.valid(work, w) {
		return work, w, ErrConflict
	}
	if e = f.workStopLink(p.Stop); e != nil {
		return work, w, e
	}
	return work, w, nil
}

// Read-only v4 link. Semantic runtime records are NOT raw host/backend/quota
// reclaim. Neither the work-only receipt nor a count/boolean proves closure.
func (f *filesystem) closeStopLink(stop runtimeStopIntent) error {
	if stop.Version != 4 || !validRuntimeStop(stop) {
		return ErrInventory
	}
	var p runtimeCloseIntent
	ok, e := f.readCloseRecord("intent.json", &p)
	if e != nil {
		return e
	}
	if !ok {
		return ErrInventory
	}
	_, w, e := f.closeWorkLink(p)
	if e != nil {
		return e
	}
	var r runtimeCloseCompletion
	ok, e = f.readCloseRecord("complete.json", &r)
	if e != nil {
		return e
	}
	if !ok || !r.valid(p, w) {
		return ErrInventory
	}
	if e = f.closeInventory(&p, &r); e != nil {
		return e
	}
	for _, item := range []struct {
		path string
		data []byte
	}{
		{runtimeCloseRoot + "/intent.json", encode(p)}, {runtimeCloseRoot + "/complete.json", encode(r)}, {runtimeCloseAnchor, []byte(digest(encode(r)) + "\n")},
	} {
		if e = f.exact(item.path, item.data, 0600); e != nil {
			return e
		}
	}
	if !bytes.Equal(encode(stop), encode(p.stopped(r))) {
		return ErrConflict
	}
	return nil
}

// Real pinned actuator in the SAME original OFD scope. No file flock spans RPC
// or manager observations. Unknown/partial/dead-before-known-close is not adopted
// from replacements or empty counts. This does NOT enable files or activation.
func (s *runtimeScope) closeBoundRuntime(ctx context.Context, work runtimeWorkStopIntent, w runtimeWorkCompletion, c *nodecontrol.PinnedClient, m systemManager, proof runtimeStopProofs) (runtimeCloseCompletion, error) {
	var result runtimeCloseCompletion
	if _, ok := ctx.Deadline(); !ok || !w.valid(work) || proof.process == nil || proof.empty == nil {
		return result, ErrPolicy
	}
	p := closeIntent(work, w)
	stage := "input"
	e := s.run(ctx, func(f *filesystem) error {
		if m.fs != f {
			return ErrPolicy
		}
		// A V2 results journal must never be adopted by record-only closure.
		for _, path := range []string{runtimeResultsCloseRoot, runtimeResultsCloseAnchor, runtimeResultsCloseAnchorScratch} {
			if yes, e := f.exists(path); e != nil {
				return e
			} else if yes {
				return ErrInventory
			}
		}
		var tx transaction
		var exists, has, anchored bool
		input := func() error {
			var e error
			tx, _, e = f.runtimeStopBase(ctx, work.Drain.Base, work.Drain.Request)
			if e != nil {
				return e
			}
			_, _, e = f.closeWorkLink(p)
			return e
		}
		if e := f.runtimeDrainLocked(ctx, func() error {
			if e := input(); e != nil {
				return e
			}
			var old runtimeCloseIntent
			var e error
			exists, e = f.readCloseRecord("intent.json", &old)
			if e != nil {
				return e
			}
			if !exists {
				if e = f.closeInventory(nil, nil); e != nil {
					return e
				}
				if yes, err := f.exists(runtimeStopRoot); err != nil {
					return err
				} else if yes {
					return ErrConflict
				} // No upgrade of physical-only Stop.
				return nil
			}
			if !bytes.Equal(encode(old), encode(p)) {
				return ErrConflict
			}
			has, e = f.readCloseRecord("complete.json", &result)
			if e != nil {
				return e
			}
			if has && !result.valid(p, w) {
				return ErrInventory
			}
			var known *runtimeCloseCompletion
			if has {
				known = &result
			}
			if e = f.closeInventory(&p, known); e != nil {
				return e
			}
			if has {
				anchored, e = f.closeCompletionAnchor(result)
			}
			return e
		}); e != nil {
			return e
		}
		stage = "original-peers"
		if e := s.workStopPeers(ctx, tx, work, &w.Work, c, m, proof, anchored); e != nil {
			return e
		}
		stage = "intent-durable"
		if !exists {
			if e := f.runtimeDrainLocked(ctx, func() error {
				if e := input(); e != nil {
					return e
				}
				if e := f.closeInventory(nil, nil); e != nil {
					return e
				}
				if e := f.mkdir(runtimeCloseRoot, 0700); e != nil {
					return e
				}
				return f.runtimeRecord(runtimeCloseRoot+"/intent.json", nil, encode(p), "runtime-close-intent")
			}); e != nil {
				return e
			}
		}
		// A full scratch intent must be made durable BEFORE begin as well.
		if e := f.runtimeDrainLocked(ctx, func() error {
			if e := input(); e != nil {
				return e
			}
			return f.runtimeRecord(runtimeCloseRoot+"/intent.json", nil, encode(p), "runtime-close-intent")
		}); e != nil {
			return e
		}
		if !anchored {
			if c == nil || c.Identity() != work.Stop.Main {
				return ErrConflict
			}
			if e := f.point("runtime-close-before-begin"); e != nil {
				return e
			}
			stage = "begin-peer"
			begin := true
			for {
				stage = "poll-input"
				if e := f.runtimeDrainLocked(ctx, input); e != nil {
					return e
				}
				stage = "poll-peers"
				if e := s.workStopPeers(ctx, tx, work, &w.Work, c, m, proof, false); e != nil {
					return e
				}
				stage = "actuator-reply"
				reply, e := c.RuntimeClose(ctx, *work.Drain.Maintenance, begin)
				if e != nil {
					return e
				}
				begin = false
				if reply.Work != w.Work || reply.Phase == "fenced" || reply.Phase == "idle" {
					return errRuntimeClose
				}
				if reply.Phase == "closed" {
					if e = f.point("runtime-close-after-terminal"); e != nil {
						return e
					}
					stage = "terminal-record-match"
					want := runtimeCloseCompletion{Version: 1, Input: digest(encode(p)), Work: reply.Work, Core: *reply.Core, Sessions: *reply.Sessions}
					if !want.valid(p, w) || has && !bytes.Equal(encode(result), encode(want)) {
						return ErrConflict
					}
					stage = "terminal-input-reproof"
					if e = f.runtimeDrainLocked(ctx, input); e != nil {
						return e
					}
					stage = "terminal-peer-reproof"
					if e = s.workStopPeers(ctx, tx, work, &w.Work, c, m, proof, false); e != nil {
						return e
					}
					stage = "terminal-reply-reproof"
					last, e := c.RuntimeClose(ctx, *work.Drain.Maintenance, false)
					if e != nil {
						return e
					}
					if !bytes.Equal(encode(last), encode(reply)) {
						return ErrConflict
					}
					result = want
					break
				}
				timer := time.NewTimer(10 * time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
			}
		}
		if e := s.workStopPeers(ctx, tx, work, &w.Work, c, m, proof, anchored); e != nil {
			return e
		}
		stage = "completion-durable"
		return f.runtimeDrainLocked(ctx, func() error {
			if e := input(); e != nil {
				return e
			}
			var known *runtimeCloseCompletion
			if has {
				known = &result
			}
			if e := f.closeInventory(&p, known); e != nil {
				return e
			}
			if e := f.exact(runtimeCloseRoot+"/intent.json", encode(p), 0600); e != nil {
				return e
			}
			if e := f.runtimeRecord(runtimeCloseRoot+"/complete.json", nil, encode(result), "runtime-close-complete"); e != nil {
				return e
			}
			if e := f.runtimeRecord(runtimeCloseAnchor, nil, []byte(digest(encode(result))+"\n"), "runtime-close-anchor"); e != nil {
				return e
			}
			return f.closeStopLink(p.stopped(result))
		})
	})
	if e != nil {
		return runtimeCloseCompletion{}, fmt.Errorf("runtime close %s: %w", stage, e)
	}
	return result, nil
}
