//go:build linux && xandbox_host_fixture

package main

import "errors"

// TEST ONLY, closed diagnostic vocabulary. These distinguish the actual
// failing post-window check without exporting private errors or changing any
// acceptance condition, workload, deadline or successful-run result.
type nodeLoadFinalStage uint8

const (
	nodeLoadFinalOfferClock nodeLoadFinalStage = iota
	nodeLoadFinalPostOfferEmpty
	nodeLoadFinalTail
	nodeLoadFinalPostTailEmpty
	nodeLoadFinalAcceptance
	nodeLoadFinalFDDrain
	nodeLoadFinalSample
	nodeLoadFinalSamplesValid
	nodeLoadFinalInventory
	nodeLoadFinalCheckpoint
)

func (stage nodeLoadFinalStage) name() string {
	names := [...]string{
		"load_offered_clock", "load_post_offer_empty", "load_quota_tail",
		"load_post_tail_empty", "load_acceptance", "load_fd_drain",
		"load_final_sample", "load_sample_validation", "load_inventory_commit",
		"load_checkpoint_commit",
	}
	if int(stage) >= len(names) {
		return "load_invalid_final_stage"
	}
	return names[stage]
}

// Preserve the actual cause privately; the summary exposes only a fixed stage.
// fail is first-writer-wins, so a worker/tail row is never replaced by this
// fallback or the generic deferred setup/finalization handler.
func (s *nodeLoadState) finalFailure(stage nodeLoadFinalStage, cause error) error {
	if stage > nodeLoadFinalCheckpoint {
		cause = errors.New("invalid closed finalization diagnostic stage")
	}
	s.fail(nodeLoadRow{Stage: stage.name()}, cause)
	return cause
}
