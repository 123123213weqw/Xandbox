package installtxn

import (
	"errors"
	"strings"
)

// Fixed-stage provenance only. Never format an underlying path, process ID,
// record, arbitrary error message or local variable. Unwrap preserves existing
// errors.Is/As contracts; no retry, fallback or proof decision is added here.
type runtimeProofStage uint8

const (
	proofUnknown runtimeProofStage = iota
	proofStopScope
	proofStopInput
	proofStopEnabledLinks
	proofStopMainObservation
	proofStopIngressObservation
	proofStopDrainPeer
	proofStopStateOpen
	proofStopOriginalStateOwner
	proofStopIngressWatch
	proofStopOriginalPeers
	proofStopExistingReceipt
	proofStopPrepublishDrain
	proofStopPrepublishStateOwner
	proofStopIntentPersist
	proofStopUnitObservation
	proofStopUnitPeer
	proofStopUnitProcess
	proofStopUnitDrain
	proofStopOtherPeers
	proofStopOperationScope
	proofStopPresignalStateOwner
	proofStopPresignalLinks
	proofStopPresignalAuthority
	proofStopBeforeSignalCut
	proofStopManagerStop
	proofStopAfterSignalCut
	proofStopExitObservation
	proofStopExitWatch
	proofStopEmptyDomain
	proofStopEmptyCut
	proofStopReceiptPersist
	proofStopFinalDomains
	proofStateWatchOpen
	proofStateIncarnation
	proofStateLocksRead
	proofStateLockRecordSyntax
	proofStateLockOwnerMismatch
	proofStateLockOwnerMissing
	proofStateLockOwnerAmbiguous
	proofStateWatchLive
)

var runtimeProofLabels = [...]string{
	"unknown",
	"stop-scope",
	"stop-input",
	"stop-enabled-links",
	"stop-main-observation",
	"stop-ingress-observation",
	"stop-drain-peer",
	"stop-state-open",
	"stop-original-state-owner",
	"stop-ingress-watch",
	"stop-original-peers",
	"stop-existing-receipt",
	"stop-prepublish-drain",
	"stop-prepublish-state-owner",
	"stop-intent-persist",
	"stop-unit-observation",
	"stop-unit-peer",
	"stop-unit-process",
	"stop-unit-drain",
	"stop-other-peers",
	"stop-operation-scope",
	"stop-presignal-state-owner",
	"stop-presignal-links",
	"stop-presignal-authority",
	"stop-before-signal-cut",
	"stop-manager-stop",
	"stop-after-signal-cut",
	"stop-exit-observation",
	"stop-exit-watch",
	"stop-empty-domain",
	"stop-empty-cut",
	"stop-receipt-persist",
	"stop-final-domains",
	"state-watch-open",
	"state-incarnation",
	"state-locks-read",
	"state-lock-record-syntax",
	"state-lock-owner-mismatch",
	"state-lock-owner-missing",
	"state-lock-owner-ambiguous",
	"state-watch-live",
}

type runtimeProofError struct {
	stage runtimeProofStage
	cause error
	lock  runtimeLockAmbiguity
}

func runtimeProofFailure(stage runtimeProofStage, err error) error {
	if err == nil {
		return nil
	}
	return &runtimeProofError{stage: stage, cause: err}
}
func (e *runtimeProofError) Error() string {
	var b strings.Builder
	b.WriteString("runtime proof:")
	var current error = e
	for n := 0; current != nil && n < 16; n++ {
		if item, ok := current.(*runtimeProofError); ok && item != nil {
			label := "unknown"
			if int(item.stage) < len(runtimeProofLabels) {
				label = runtimeProofLabels[item.stage]
			}
			b.WriteByte('/')
			b.WriteString(label)
			if item.stage == proofStateLockOwnerAmbiguous {
				item.lock.appendTo(&b)
			}
		}
		current = errors.Unwrap(current)
	}
	return b.String()
}
func (e *runtimeProofError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}
