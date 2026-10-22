// Package telemetry provides fixed-cardinality, process-local observations.
// Writers perform only atomic additions: no I/O, callbacks or lifecycle locks.
package telemetry

import (
	"bytes"
	"fmt"
	"sync/atomic"
	"time"
)

type Operation uint8

const (
	CreateCall Operation = iota
	StopAttempt
	CleanupAttempt
	SessionOpenCall
	SessionSwitchCall
	CandidateReadyOffset
	AdmissionRevokedOffset
	FenceToCommit
	RoutePublishedOffset
	operationCount
)

var names = [...]string{"create_call", "stop_attempt", "cleanup_attempt", "session_open_call", "session_switch_call", "candidate_ready_offset", "admission_revoked_offset", "fence_to_commit", "route_published_offset"}
var bounds = [...]time.Duration{time.Millisecond, 5 * time.Millisecond, 10 * time.Millisecond, 25 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second, 60 * time.Second}

type histogram struct {
	bins  [len(bounds) + 1]atomic.Uint64 // One disjoint bin increment per observation.
	sumUS atomic.Uint64                  // Microsecond precision, not nanosecond uptime wrap.
}

type Registry struct{ operations [operationCount][2]histogram }

// Observe ignores invalid/negative observations. A nil registry is disabled.
// Labels are sealed enums; no tenant, Ref, path, key, argv or error string enters it.
func (r *Registry) Observe(op Operation, elapsed time.Duration, failed bool) {
	if r == nil || op >= operationCount || elapsed < 0 {
		return
	}
	outcome := 0
	if failed {
		outcome = 1
	}
	h := &r.operations[op][outcome]
	n := len(bounds)
	for i, limit := range bounds {
		if elapsed <= limit {
			n = i
			break
		}
	}
	h.sumUS.Add(uint64(elapsed / time.Microsecond))
	h.bins[n].Add(1)
}

type Gauges struct {
	Records, RecordCapacity, Allocated, Capacity           int64
	StopQueued, CleanupQueued, StopRunning, CleanupRunning int64
	StopWorkers, CleanupWorkers, QueueCapacity             int64
	Sessions, SessionCapacity                              int64
}

// Render takes independent atomic observations, not a transactional snapshot.
// Histogram count is derived from the same sampled bins as +Inf so those agree
// even during writes. Sums/gauges can describe slightly different instants.
func (r *Registry) Render(g Gauges) []byte {
	var b bytes.Buffer
	b.WriteString("# HELP xandbox_operation_seconds Process-local call/attempt durations; not durable events or client completion proof.\n# TYPE xandbox_operation_seconds histogram\n")
	if r != nil {
		for op := Operation(0); op < operationCount; op++ {
			for outcome, label := range [...]string{"success", "error"} {
				h := &r.operations[op][outcome]
				var count uint64
				for i := range h.bins {
					count += h.bins[i].Load()
					le := "+Inf"
					if i < len(bounds) {
						le = fmt.Sprintf("%g", bounds[i].Seconds())
					}
					fmt.Fprintf(&b, "xandbox_operation_seconds_bucket{operation=%q,outcome=%q,le=%q} %d\n", names[op], label, le, count)
				}
				fmt.Fprintf(&b, "xandbox_operation_seconds_count{operation=%q,outcome=%q} %d\n", names[op], label, count)
				fmt.Fprintf(&b, "xandbox_operation_seconds_sum{operation=%q,outcome=%q} %.6f\n", names[op], label, float64(h.sumUS.Load())/1e6)
			}
		}
	}
	values := [...]struct {
		name  string
		value int64
	}{
		{"records", g.Records}, {"record_capacity", g.RecordCapacity}, {"allocated", g.Allocated}, {"instance_capacity", g.Capacity},
		{"stop_queued", g.StopQueued}, {"cleanup_queued", g.CleanupQueued}, {"stop_running", g.StopRunning}, {"cleanup_running", g.CleanupRunning},
		{"stop_workers", g.StopWorkers}, {"cleanup_workers", g.CleanupWorkers}, {"queue_capacity_per_pool", g.QueueCapacity},
		{"session_records", g.Sessions}, {"session_capacity", g.SessionCapacity},
	}
	for _, v := range values {
		fmt.Fprintf(&b, "# TYPE xandbox_%s gauge\nxandbox_%s %d\n", v.name, v.name, v.value)
	}
	return b.Bytes()
}
