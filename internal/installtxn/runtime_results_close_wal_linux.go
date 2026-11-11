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

const runtimeResultsCloseRoot = "/etc/xandbox-runtime-results-close"
const runtimeResultsCloseAnchor = "/etc/xandbox-runtime-results-close.identity"
const runtimeResultsCloseAnchorScratch = "/etc/.xandbox-runtime-results-close.identity.next"

var errRuntimeResultsClose = errors.New("bound result runtime closure failed or has unknown outcomes; maintenance remains fenced")

// Durable BEFORE the irreversible live V2 RPC. The original work-only plan
// binds source/Before/owner/process/state; this separate V2 journal binds all
// retained results. It NEVER converts that plan into a legacy v4 Stop receipt.

func resultsCloseIntent(p runtimeWorkStopIntent, w runtimeWorkCompletion) runtimeResultsCloseIntent {
	return runtimeResultsCloseIntent{Version: 2, Policy: "close-bound-runtime-results-v2", Input: digest(encode(p)), Stop: p.stopped(w)}
}
func (p runtimeResultsCloseIntent) valid(work runtimeWorkStopIntent, w runtimeWorkCompletion) bool {
	return w.valid(work) && p.Version == 2 && p.Policy == "close-bound-runtime-results-v2" && p.Input == digest(encode(work)) && bytes.Equal(encode(p.Stop), encode(work.stopped(w)))
}
func (r runtimeResultsCloseCompletion) valid(p runtimeResultsCloseIntent, w runtimeWorkCompletion) bool {
	return r.Version == 2 && p.Version == 2 && p.Policy == "close-bound-runtime-results-v2" && r.Input == digest(encode(p)) && r.Work == w.Work && r.Work.Complete() && r.Core.Valid() && r.Sessions.Valid()
}

// Complete canonical finals/scratches ONLY. Partial outcome bytes are unknown,
// never a prefix from which a successful close can be fabricated.
func (f *filesystem) readResultsCloseRecord(name string, value any) (bool, error) {
	final, scratch := runtimeResultsCloseRoot+"/"+name, runtimeResultsCloseRoot+"/."+name+".next"
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
func (f *filesystem) resultsCloseInventory(p *runtimeResultsCloseIntent, r *runtimeResultsCloseCompletion) error {
	names, e := f.names(runtimeResultsCloseRoot)
	missing := errors.Is(e, unix.ENOENT)
	if e != nil && !missing {
		return e
	}
	if missing || r == nil {
		for _, path := range []string{runtimeResultsCloseAnchor, runtimeResultsCloseAnchorScratch} {
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
	if p == nil || f.privateDirectory(runtimeResultsCloseRoot, 0700) != nil {
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
			if yes, err := f.exists(runtimeResultsCloseRoot + "/" + final); err != nil || yes {
				return ErrInventory
			}
		}
		if e = f.exact(runtimeResultsCloseRoot+"/"+name, want, 0600); e != nil {
			return e
		}
	}
	return nil
}
func (f *filesystem) resultsCloseCompletionAnchor(r runtimeResultsCloseCompletion) (bool, error) {
	want := []byte(digest(encode(r)) + "\n")
	b, e := f.read(runtimeResultsCloseAnchor, int64(len(want)), 0600)
	if errors.Is(e, unix.ENOENT) {
		b, e = f.read(runtimeResultsCloseAnchorScratch, int64(len(want)), 0600)
		if errors.Is(e, unix.ENOENT) {
			return false, nil
		}
	} else if e == nil {
		if yes, err := f.exists(runtimeResultsCloseAnchorScratch); err != nil || yes {
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
func (f *filesystem) resultsCloseWorkLink(p runtimeResultsCloseIntent) (runtimeWorkStopIntent, runtimeWorkCompletion, error) {
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

// Exact final V2 closure link, not an old v4 Stop conversion. No legacy
// completion/report or partial scratch can serve as this anchored authority.
func (f *filesystem) resultsCloseLink(p runtimeResultsCloseIntent, r runtimeResultsCloseCompletion) error {
	_, w, e := f.resultsCloseWorkLink(p)
	if e != nil {
		return e
	}
	if !r.valid(p, w) {
		return ErrConflict
	}
	if e = f.resultsCloseExclusive(); e != nil {
		return e
	}
	if e = f.resultsCloseInventory(&p, &r); e != nil {
		return e
	}
	for _, item := range []struct {
		path string
		data []byte
	}{
		{runtimeResultsCloseRoot + "/intent.json", encode(p)},
		{runtimeResultsCloseRoot + "/complete.json", encode(r)},
		{runtimeResultsCloseAnchor, []byte(digest(encode(r)) + "\n")},
	} {
		if e = f.exact(item.path, item.data, 0600); e != nil {
			return e
		}
	}
	return nil
}

// No conversion/adoption of any legacy record-only closure or physical Stop.
func (f *filesystem) resultsCloseExclusive() error {
	for _, path := range []string{runtimeCloseRoot, runtimeCloseAnchor, runtimeCloseAnchorScratch, runtimeStopRoot} {
		if yes, e := f.exists(path); e != nil {
			return e
		} else if yes {
			return ErrInventory
		}
	}
	return nil
}

// Real pinned actuator in the SAME original OFD scope. No file flock spans RPC
// or manager observations. Unknown/partial/dead-before-known-close is not adopted
// from replacements or empty counts. This does NOT enable files or activation.
func (s *runtimeScope) closeBoundResultsRuntime(ctx context.Context, work runtimeWorkStopIntent, w runtimeWorkCompletion, c *nodecontrol.PinnedClient, m systemManager, proof runtimeStopProofs) (runtimeResultsCloseCompletion, error) {
	var result runtimeResultsCloseCompletion
	if _, ok := ctx.Deadline(); !ok || !w.valid(work) || proof.process == nil || proof.empty == nil {
		return result, ErrPolicy
	}
	p := resultsCloseIntent(work, w)
	stage := "input"
	e := s.run(ctx, func(f *filesystem) error {
		if m.fs != f {
			return ErrPolicy
		}
		if e := f.resultsCloseExclusive(); e != nil {
			return e
		}
		var tx transaction
		var exists, has, anchored bool
		input := func() error {
			if e := f.resultsCloseExclusive(); e != nil {
				return e
			}
			var e error
			tx, _, e = f.runtimeStopBase(ctx, work.Drain.Base, work.Drain.Request)
			if e != nil {
				return e
			}
			_, _, e = f.resultsCloseWorkLink(p)
			return e
		}
		if e := f.runtimeDrainLocked(ctx, func() error {
			if e := input(); e != nil {
				return e
			}
			var old runtimeResultsCloseIntent
			var e error
			exists, e = f.readResultsCloseRecord("intent.json", &old)
			if e != nil {
				return e
			}
			if !exists {
				if e = f.resultsCloseInventory(nil, nil); e != nil {
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
			has, e = f.readResultsCloseRecord("complete.json", &result)
			if e != nil {
				return e
			}
			if has && !result.valid(p, w) {
				return ErrInventory
			}
			var known *runtimeResultsCloseCompletion
			if has {
				known = &result
			}
			if e = f.resultsCloseInventory(&p, known); e != nil {
				return e
			}
			if has {
				anchored, e = f.resultsCloseCompletionAnchor(result)
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
				if e := f.resultsCloseInventory(nil, nil); e != nil {
					return e
				}
				if e := f.mkdir(runtimeResultsCloseRoot, 0700); e != nil {
					return e
				}
				return f.runtimeRecord(runtimeResultsCloseRoot+"/intent.json", nil, encode(p), "runtime-results-close-intent")
			}); e != nil {
				return e
			}
		}
		// A full scratch intent must be made durable BEFORE begin as well.
		if e := f.runtimeDrainLocked(ctx, func() error {
			if e := input(); e != nil {
				return e
			}
			return f.runtimeRecord(runtimeResultsCloseRoot+"/intent.json", nil, encode(p), "runtime-results-close-intent")
		}); e != nil {
			return e
		}
		if !anchored {
			if c == nil || c.Identity() != work.Stop.Main {
				return ErrConflict
			}
			if e := f.point("runtime-results-close-before-begin"); e != nil {
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
				stage = "poll-input-after-peers"
				if e := f.runtimeDrainLocked(ctx, input); e != nil {
					return e
				}
				stage = "actuator-reply"
				reply, e := c.RuntimeResultsClose(ctx, *work.Drain.Maintenance, begin)
				if e != nil {
					return e
				}
				begin = false
				if reply.Work != w.Work || reply.Phase == "fenced" || reply.Phase == "idle" {
					return errRuntimeResultsClose
				}
				if reply.Phase == "closed" {
					if e = f.point("runtime-results-close-after-terminal"); e != nil {
						return e
					}
					stage = "terminal-record-match"
					want := runtimeResultsCloseCompletion{Version: 2, Input: digest(encode(p)), Work: reply.Work, Core: *reply.Core, Sessions: *reply.Sessions}
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
					stage = "terminal-input-after-peers"
					if e = f.runtimeDrainLocked(ctx, input); e != nil {
						return e
					}
					stage = "terminal-reply-reproof"
					last, e := c.RuntimeResultsClose(ctx, *work.Drain.Maintenance, false)
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
			var known *runtimeResultsCloseCompletion
			if has {
				known = &result
			}
			if e := f.resultsCloseInventory(&p, known); e != nil {
				return e
			}
			if e := f.exact(runtimeResultsCloseRoot+"/intent.json", encode(p), 0600); e != nil {
				return e
			}
			if e := f.runtimeRecord(runtimeResultsCloseRoot+"/complete.json", nil, encode(result), "runtime-results-close-complete"); e != nil {
				return e
			}
			if e := f.runtimeRecord(runtimeResultsCloseAnchor, nil, []byte(digest(encode(result))+"\n"), "runtime-results-close-anchor"); e != nil {
				return e
			}
			return f.resultsCloseLink(p, result)
		})
	})
	if e != nil {
		return runtimeResultsCloseCompletion{}, fmt.Errorf("runtime close %s: %w", stage, e)
	}
	return result, nil
}
