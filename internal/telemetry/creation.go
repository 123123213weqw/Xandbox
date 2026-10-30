package telemetry

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CreationPhase is a closed vocabulary, not a tenant-provided tracing label.
// Nested spans overlap: core_driver includes the more specific driver spans.
type CreationPhase uint8

const (
	CoreAdmission CreationPhase = iota
	CoreOwnershipCommit
	CoreDriver
	CoreReadyCommit
	DriverPrepareSlot
	DriverOwnership
	DriverQuotaReserve
	DriverAssetCopy
	DriverQuotaVerify
	DriverActivation
	SessionIntentCommit
	SessionPreparedCommit
	SessionActiveCommit
	creationPhaseCount
)

var creationNames = [...]string{
	"xa_core_admission", "xa_core_owner_commit", "xa_core_driver", "xa_core_ready_commit",
	"xa_driver_slot", "xa_driver_owner", "xa_driver_quota_reserve", "xa_driver_copy",
	"xa_driver_quota_verify", "xa_driver_activation", "xa_session_intent_commit",
	"xa_session_prepared_commit", "xa_session_active_commit",
}

type creationKey struct{}
type creationObservation struct {
	calls uint64
	total time.Duration
}
type creationTrace struct {
	mu               sync.Mutex // Independent, bounded memory only; never a lifecycle lock.
	values           [creationPhaseCount]creationObservation
	activityRegistry *Registry
	kind             CreationKind
	requestCounter   *atomic.Int64
	finished         atomic.Bool
}

// WithCreationTrace starts a fresh, fixed-size request-local observation. It
// preserves the exact parent cancellation/deadline. There is no global history,
// incoming trace selector, wall-clock timestamp, identity or durable record.
func WithCreationTrace(ctx context.Context) context.Context {
	return context.WithValue(ctx, creationKey{}, &creationTrace{})
}

// CarryCreationTrace transfers ONLY this observer onto an existing lifecycle
// context. In particular it does not copy caller cancellation/deadlines/values:
// the original post-fence transaction and shutdown semantics remain unchanged.
func CarryCreationTrace(destination, source context.Context) context.Context {
	if trace, ok := source.Value(creationKey{}).(*creationTrace); ok && trace != nil {
		return context.WithValue(destination, creationKey{}, trace)
	}
	return destination
}

// CreationSpan has one fixed phase, no payload and no callbacks. End is safe to
// defer AND call at the boundary; it records at most once, even concurrently.
type CreationSpan struct {
	trace           *creationTrace
	phase           CreationPhase
	start           time.Time
	ended           atomic.Bool
	activityCounter *atomic.Int64
}

// StartCreation is allocation-free when no request observer is installed.
// Invalid phases disable the observation; they never affect the operation.
func StartCreation(ctx context.Context, phase CreationPhase) *CreationSpan {
	trace, ok := ctx.Value(creationKey{}).(*creationTrace)
	if !ok || trace == nil || phase >= creationPhaseCount {
		return nil
	}
	counter := startCreationActivityCounter(trace, CreationActivityPhase(phase))
	return &CreationSpan{trace: trace, phase: phase, start: time.Now(), activityCounter: counter}
}

func (span *CreationSpan) End() {
	if span == nil || span.trace == nil || span.phase >= creationPhaseCount || !span.ended.CompareAndSwap(false, true) {
		return
	}
	elapsed := time.Since(span.start) // Monotonic duration, not a wall-clock delta.
	span.trace.activityRegistry.endCreationCounter(span.activityCounter)
	if elapsed < 0 {
		return
	}
	span.trace.mu.Lock()
	v := &span.trace.values[span.phase]
	if v.calls != math.MaxUint64 {
		v.calls++
	}
	if elapsed <= time.Duration(math.MaxInt64)-v.total {
		v.total += elapsed
	} else {
		v.total = time.Duration(math.MaxInt64)
	}
	span.trace.mu.Unlock()
}

// CreationServerTiming returns only closed metric names, elapsed milliseconds
// and call counts. No identifiers, errors, paths, argv or request data can enter
// the header. Absence means unobserved, NOT zero. It is not an acknowledgment of
// successful execution, durability, physical Stop or complete reclamation.
//
// The HTTP handler calls this AFTER its synchronous lifecycle call returns.
// Spans are aggregated per phase; nested durations must not be added together.
func CreationServerTiming(ctx context.Context) string {
	trace, ok := ctx.Value(creationKey{}).(*creationTrace)
	if !ok || trace == nil {
		return ""
	}
	trace.mu.Lock()
	values := trace.values
	trace.mu.Unlock()
	var header strings.Builder
	for phase, v := range values {
		if v.calls == 0 {
			continue
		}
		if header.Len() != 0 {
			header.WriteString(", ")
		}
		fmt.Fprintf(&header, "%s;dur=%.3f;desc=\"n%d\"", creationNames[phase], float64(v.total)/float64(time.Millisecond), v.calls)
	}
	return header.String()
}
