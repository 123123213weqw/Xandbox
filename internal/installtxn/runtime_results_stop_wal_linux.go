//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"golang.org/x/sys/unix"
)

const runtimeResultsStopRoot = "/etc/xandbox-runtime-results-stop"

func (p runtimeResultsStopIntent) valid() bool {
	return p.Version == 1 && p.Policy == "results-bound-physical-stop-v1" && digestPattern.MatchString(p.WorkIntent) && digestPattern.MatchString(p.Work) && digestPattern.MatchString(p.CloseIntent) && digestPattern.MatchString(p.Closure) && p.Plan.Version == 2 && validRuntimeStop(p.Plan)
}
func resultsStopIntent(work runtimeWorkStopIntent, w runtimeWorkCompletion, close runtimeResultsCloseIntent, r runtimeResultsCloseCompletion) runtimeResultsStopIntent {
	return runtimeResultsStopIntent{Version: 1, Policy: "results-bound-physical-stop-v1", WorkIntent: digest(encode(work)), Work: digest(encode(w)), CloseIntent: digest(encode(close)), Closure: digest(encode(r)), Plan: work.Stop}
}

// Pure source/WAL/state link, no manager/RPC/flock/recovery or repairs. Caller
// holds the original operation scope and the ordinary bounded file lock.
func (f *filesystem) resultsStopLink(ctx context.Context, p runtimeResultsStopIntent) (transaction, error) {
	var zero transaction
	if !p.valid() {
		return zero, ErrInventory
	}
	t, _, e := f.runtimeStopBase(ctx, p.Plan.Base, p.Plan.Request)
	if e != nil {
		return zero, e
	}
	var close runtimeResultsCloseIntent
	var r runtimeResultsCloseCompletion
	if ok, e := f.readResultsCloseRecord("intent.json", &close); e != nil || !ok {
		return zero, ErrInventory
	}
	if ok, e := f.readResultsCloseRecord("complete.json", &r); e != nil || !ok {
		return zero, ErrInventory
	}
	work, w, e := f.resultsCloseWorkLink(close)
	if e != nil {
		return zero, e
	}
	if e = f.resultsCloseLink(close, r); e != nil {
		return zero, e
	}
	if !bytes.Equal(encode(p), encode(resultsStopIntent(work, w, close, r))) {
		return zero, ErrConflict
	}
	if e = f.runtimeStateMatches(*p.Plan.State); e != nil {
		return zero, e
	}
	return t, nil
}
func (f *filesystem) readResultsStopRecord(name string, value any) (bool, error) {
	final, scratch := runtimeResultsStopRoot+"/"+name, runtimeResultsStopRoot+"/."+name+".next"
	b, e := f.read(final, MaxPlan, 0600)
	if e == nil {
		if yes, e := f.exists(scratch); e != nil || yes {
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
func (f *filesystem) resultsStopInventory(ctx context.Context, p runtimeResultsStopIntent) error {
	if _, e := f.resultsStopLink(ctx, p); e != nil {
		return e
	}
	names, e := f.names(runtimeResultsStopRoot)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	if e = f.privateDirectory(runtimeResultsStopRoot, 0700); e != nil {
		return e
	}
	present := map[string]bool{}
	for _, n := range names {
		present[n] = true
	}
	if !present["intent.json"] && !present[".intent.json.next"] {
		return ErrInventory
	}
	for _, n := range names {
		want, final := encode(p), "intent.json"
		switch n {
		case "intent.json", ".intent.json.next":
		case "stopped.json", ".stopped.json.next":
			if !present["intent.json"] {
				return ErrInventory
			}
			want, final = encode(runtimeResultsStopReceipt{Version: 1, Input: digest(encode(p))}), "stopped.json"
		default:
			return ErrInventory
		}
		if n[0] == '.' && present[final] {
			return ErrInventory
		}
		if e = f.exact(runtimeResultsStopRoot+"/"+n, want, 0600); e != nil {
			return e
		}
	}
	return nil
}
