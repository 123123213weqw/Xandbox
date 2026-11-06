package telemetry

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"sync/atomic"
)

// CreationKind is chosen by the authenticated handler, never an input label.
type CreationKind uint8

const (
	CreationRaw CreationKind = iota
	CreationSessionOpen
	CreationSessionSwitch
	creationKindCount
)

var creationKindNames = [...]string{"raw_create", "session_open", "session_switch"}

// Activity phases include the unchanged thirteen response-timing boundaries.
// The two extra gauges disambiguate the composite driver_slot observation;
// they do NOT add response-header entries or change that span's definition.
type CreationActivityPhase uint8

const (
	CreationPermitWait CreationActivityPhase = CreationActivityPhase(creationPhaseCount) + iota
	CreationNodeCheck
	creationActivityPhaseCount
)

var creationActivityNames = [...]string{
	"xa_core_admission", "xa_core_owner_commit", "xa_core_driver", "xa_core_ready_commit",
	"xa_driver_slot", "xa_driver_owner", "xa_driver_quota_reserve", "xa_driver_copy",
	"xa_driver_quota_verify", "xa_driver_activation", "xa_session_intent_commit",
	"xa_session_prepared_commit", "xa_session_active_commit",
	"xa_driver_permit_wait", "xa_driver_node_check",
}

type creationActivityRegistry struct {
	enabled  atomic.Bool
	invalid  atomic.Bool // Sticky: invalid observations must never look like zero.
	requests [creationKindCount]atomic.Int64
	phases   [creationKindCount][creationActivityPhaseCount]atomic.Int64
}

// No I/O, callbacks, queue, worker, labels, clock or request history. Atomic
// observations are independent, NOT a transactional census of one request.
func (r *Registry) beginCreationCounter(c *atomic.Int64) *atomic.Int64 {
	if r == nil || c == nil {
		return nil
	}
	for {
		n := c.Load()
		if n < 0 || n == math.MaxInt64 {
			r.creation.invalid.Store(true)
			return nil
		}
		if c.CompareAndSwap(n, n+1) {
			return c
		}
	}
}

func (r *Registry) endCreationCounter(c *atomic.Int64) {
	if r == nil || c == nil {
		return
	}
	for {
		n := c.Load()
		if n <= 0 {
			r.creation.invalid.Store(true)
			return
		}
		if c.CompareAndSwap(n, n-1) {
			return
		}
	}
}

// WithCreationTraceKind preserves the original parent lifetime and thirteen
// timings, adding only fixed-cardinality active gauges in this registry.
// EndCreationTrace MUST run after the handler returns, NOT on ctx.Done():
// cancellation is not proof that the real operation or a blocking I/O ended.
func WithCreationTraceKind(ctx context.Context, r *Registry, kind CreationKind) context.Context {
	trace := &creationTrace{}
	if r != nil {
		if kind >= creationKindCount {
			r.creation.invalid.Store(true)
		} else {
			trace.activityRegistry, trace.kind = r, kind
			trace.requestCounter = r.beginCreationCounter(&r.creation.requests[kind])
			if trace.requestCounter == nil {
				trace.activityRegistry = nil
			} else {
				r.creation.enabled.Store(true)
			}
		}
	}
	return context.WithValue(ctx, creationKey{}, trace)
}

func EndCreationTrace(ctx context.Context) {
	trace, _ := ctx.Value(creationKey{}).(*creationTrace)
	if trace != nil && trace.finished.CompareAndSwap(false, true) {
		trace.activityRegistry.endCreationCounter(trace.requestCounter)
	}
}

func startCreationActivityCounter(trace *creationTrace, phase CreationActivityPhase) *atomic.Int64 {
	if trace == nil || trace.activityRegistry == nil {
		return nil
	}
	if phase >= creationActivityPhaseCount {
		trace.activityRegistry.creation.invalid.Store(true)
		return nil
	}
	return trace.activityRegistry.beginCreationCounter(&trace.activityRegistry.creation.phases[trace.kind][phase])
}

type CreationActivitySpan struct {
	registry *Registry
	counter  *atomic.Int64
	ended    atomic.Bool
}

// StartCreationActivity is a gauge only: no duration, completion, identity or
// response-header field. No observer means no allocation or other behavior.
func StartCreationActivity(ctx context.Context, phase CreationActivityPhase) *CreationActivitySpan {
	trace, _ := ctx.Value(creationKey{}).(*creationTrace)
	counter := startCreationActivityCounter(trace, phase)
	if counter == nil {
		return nil
	}
	return &CreationActivitySpan{registry: trace.activityRegistry, counter: counter}
}

func (s *CreationActivitySpan) End() {
	if s != nil && s.ended.CompareAndSwap(false, true) {
		s.registry.endCreationCounter(s.counter)
	}
}

func (r *Registry) renderCreationActivity(b *bytes.Buffer) {
	var requests [creationKindCount]int64
	var phases [creationKindCount][creationActivityPhaseCount]int64
	enabled, invalid := 0, 0
	if r != nil {
		if r.creation.enabled.Load() {
			enabled = 1
		}
		for kind := range requests {
			requests[kind] = r.creation.requests[kind].Load()
			for phase := range phases[kind] {
				phases[kind][phase] = r.creation.phases[kind][phase].Load()
			}
		}
		if r.creation.invalid.Load() {
			invalid = 1
		}
	}
	fmt.Fprintf(b, "# HELP xandbox_creation_activity_enabled A handler has activated fixed process-local creation observations; not durable audit.\n# TYPE xandbox_creation_activity_enabled gauge\nxandbox_creation_activity_enabled %d\n", enabled)
	fmt.Fprintf(b, "# TYPE xandbox_creation_activity_invalid gauge\nxandbox_creation_activity_invalid %d\n", invalid)
	b.WriteString("# HELP xandbox_creation_requests_active Handler scopes, including response work; not an atomic snapshot or task identity.\n# TYPE xandbox_creation_requests_active gauge\n")
	for kind, count := range requests {
		fmt.Fprintf(b, "xandbox_creation_requests_active{operation=%q} %d\n", creationKindNames[kind], count)
	}
	b.WriteString("# HELP xandbox_creation_phases_active Real entered but not ended boundaries; nested phases overlap and cancellation does not end a span.\n# TYPE xandbox_creation_phases_active gauge\n")
	for kind, values := range phases {
		for phase, count := range values {
			fmt.Fprintf(b, "xandbox_creation_phases_active{operation=%q,phase=%q} %d\n", creationKindNames[kind], creationActivityNames[phase], count)
		}
	}
}
