//go:build linux && xandbox_host_fixture

package main

// TEST ONLY. The actual entry point always uses this fixed 40-minute offered
// schedule. No CLI/RPC duration, rate, worker, target or budget selectors exist.
import (
	"context"
	"errors"
	"math"
	"sort"
	"time"
)

const (
	nodeLoadDuration        = 40 * time.Minute
	nodeLoadRunBudget       = 55 * time.Minute
	nodeLoadOuterBudget     = time.Hour
	nodeLoadWorkers         = 4 // Per tenant, fixed ahead of time; never auto-scale clients.
	nodeLoadQueue           = 16
	nodeLoadRawTotal        = 6360
	nodeLoadCanaryTotal     = 240
	nodeLoadTailTotal       = 100
	nodeLoadSampleLimit     = 244
	nodeLoadReplyMax        = 1 << 20
	nodeLoadInventoryMax    = 2 << 20
	nodeLoadCheckpointPhase = "node-open-arrival-healthy-checkpoint"
)

type nodeLoadPhase struct{ Duration, Interval time.Duration }
type nodeLoadArrival struct {
	Index, Phase, Tenant int
	Offset               time.Duration
	Interval             time.Duration
}

func nodeLoadPlan() []nodeLoadPhase {
	return []nodeLoadPhase{{10 * time.Minute, 10 * time.Second}, {10 * time.Minute, 2 * time.Second}, {10 * time.Minute, 500 * time.Millisecond}, {10 * time.Minute, 125 * time.Millisecond}}
}

func nodeLoadArrivals(phases []nodeLoadPhase) ([]nodeLoadArrival, error) {
	var out []nodeLoadArrival
	var offset time.Duration
	for phase, p := range phases {
		if p.Duration <= 0 || p.Interval <= 0 || p.Duration%p.Interval != 0 || p.Duration > nodeLoadDuration || offset > nodeLoadDuration-p.Duration || int64(p.Duration/p.Interval) > nodeLoadRawTotal-int64(len(out)) {
			return nil, errors.New("bounded evenly spaced arrival plan required")
		}
		for t := time.Duration(0); t < p.Duration; t += p.Interval {
			i := len(out)
			out = append(out, nodeLoadArrival{Index: i, Phase: phase, Tenant: i % 2, Offset: offset + t, Interval: p.Interval})
		}
		offset += p.Duration
	}
	if len(out) == 0 {
		return nil, errors.New("nonempty arrival plan required")
	}
	return out, nil
}

type nodeLoadClock interface {
	Now() time.Time
	WaitUntil(context.Context, time.Time) error
}
type nodeLoadRealClock struct{}

func (nodeLoadRealClock) Now() time.Time { return time.Now() }
func (nodeLoadRealClock) WaitUntil(ctx context.Context, due time.Time) error {
	d := time.Until(due)
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// A completion cannot change a future due time. Generator lateness and a full
// finite client queue are explicit outcomes, never silently omitted or retried.
func nodeLoadSchedule(ctx context.Context, clock nodeLoadClock, start time.Time, plan []nodeLoadArrival, enqueue func(nodeLoadArrival, time.Time) bool, drop func(nodeLoadArrival, time.Time, string)) error {
	for _, a := range plan {
		due := start.Add(a.Offset)
		if e := clock.WaitUntil(ctx, due); e != nil {
			return e
		}
		now := clock.Now()
		if !now.Before(due) && now.Sub(due) > a.Interval {
			drop(a, now, "generator_late_drop")
			continue
		}
		if now.Before(due) {
			return errors.New("arrival clock dispatched before its due time")
		}
		if !enqueue(a, now) {
			drop(a, now, "generator_queue_drop")
		}
	}
	return nil
}

type nodeLoadQuantile struct {
	N   int     `json:"n"`
	P50 float64 `json:"p50_ms"`
	P95 float64 `json:"p95_ms"`
	P99 float64 `json:"p99_ms"`
	Max float64 `json:"max_ms"`
}

func nodeLoadQuantiles(values []float64) (nodeLoadQuantile, error) {
	if len(values) > nodeLoadRawTotal+nodeLoadCanaryTotal+nodeLoadTailTotal+32 {
		return nodeLoadQuantile{}, errors.New("bounded samples required")
	}
	copyValues := append([]float64(nil), values...)
	for _, v := range copyValues {
		if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			return nodeLoadQuantile{}, errors.New("finite nonnegative observation required")
		}
	}
	if len(values) == 0 {
		return nodeLoadQuantile{}, nil
	}
	sort.Float64s(copyValues)
	at := func(p int) float64 { return copyValues[(len(copyValues)*p+99)/100-1] }
	return nodeLoadQuantile{len(copyValues), at(50), at(95), at(99), copyValues[len(copyValues)-1]}, nil
}

func nodeLoadFair(a, b int) bool {
	// Predeclared coarse equal-offer progress guard, NOT a scheduling guarantee.
	return a > 0 && b > 0 && a <= nodeLoadRawTotal && b <= nodeLoadRawTotal && int64(min(a, b))*5 >= int64(a)+int64(b)
}

func nodeLoadOutcomeValid(s string) bool {
	switch s {
	case "completed", "service_unavailable503", "tenant_quota", "generator_late_drop", "generator_queue_drop", "failed":
		return true
	}
	return false
}
