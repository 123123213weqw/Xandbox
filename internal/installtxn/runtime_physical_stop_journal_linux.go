//go:build linux

package installtxn

import "context"

// Closed, private choice of journal bytes, not an actuator/report callback.
// The zero value is exactly the old physical Stop journal. The results mode
// requires an already durable typed intent linked to actual anchored actors.
// Both use ONE unchanged process/state/watch/order/manager/domain algorithm.
type runtimePhysicalStopJournal struct{ bound *runtimeResultsStopIntent }

func (j runtimePhysicalStopJournal) root() string {
	if j.bound == nil {
		return runtimeStopRoot
	}
	return runtimeResultsStopRoot
}
func (j runtimePhysicalStopJournal) prefix() string {
	if j.bound == nil {
		return "runtime-stop"
	}
	return "runtime-results-stop"
}
func (j runtimePhysicalStopJournal) intent(p runtimeStopIntent) []byte {
	if j.bound == nil {
		return encode(p)
	}
	return encode(*j.bound)
}
func (j runtimePhysicalStopJournal) receipt(p runtimeStopIntent) []byte {
	if j.bound == nil {
		return encode(runtimeStopReceipt{Version: 1, Input: digest(encode(p))})
	}
	return encode(runtimeResultsStopReceipt{Version: 1, Input: digest(encode(*j.bound))})
}
func (j runtimePhysicalStopJournal) read(f *filesystem) (runtimeStopIntent, error) {
	if j.bound == nil {
		// Only ADD refusals: old physical-only callers cannot silently select
		// legacy semantics once a result-aware close/Stop prefix exists.
		for _, path := range []string{runtimeResultsCloseRoot, runtimeResultsCloseAnchor, runtimeResultsCloseAnchorScratch, runtimeResultsStopRoot} {
			if yes, e := f.exists(path); e != nil {
				return runtimeStopIntent{}, e
			} else if yes {
				return runtimeStopIntent{}, ErrInventory
			}
		}
		return f.readRuntimeStop()
	}
	var p runtimeResultsStopIntent
	ok, e := f.readResultsStopRecord("intent.json", &p)
	if e != nil {
		return runtimeStopIntent{}, e
	}
	if !ok || !p.valid() || digest(encode(p)) != digest(encode(*j.bound)) {
		return runtimeStopIntent{}, ErrConflict
	}
	return p.Plan, nil
}
func (j runtimePhysicalStopJournal) inventory(ctx context.Context, f *filesystem, p *runtimeStopIntent) error {
	if j.bound == nil {
		return f.stopInventory(p)
	}
	if p == nil || digest(encode(*p)) != digest(encode(j.bound.Plan)) {
		return ErrConflict
	}
	return f.resultsStopInventory(ctx, *j.bound)
}
