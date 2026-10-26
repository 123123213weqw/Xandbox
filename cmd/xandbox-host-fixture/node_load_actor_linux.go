//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: bounded observations of the existing actor, never a new timeout,
// capacity policy or measured result. All snapshots stay in the private capsule.
import (
	"context"
	"errors"
	"sync"
	"time"
)

const nodeLoadActorSlots = 2*nodeLoadWorkers + 2
const nodeLoadActorPhaseLimit = 16

type nodeLoadActorPhase uint8

const (
	loadActorRawCreate nodeLoadActorPhase = iota
	loadActorRotateClose
	loadActorOpenHTTP
	loadActorOpenVerify
	loadActorOpenFresh
	loadActorOpenWork
	loadActorBusyPrepare
	loadActorBusyStart
	loadActorBusyProgress
	loadActorBusyVerify
	loadActorSwitch
	loadActorNewFresh
	loadActorNewWork
	loadActorRelease
)

func (p nodeLoadActorPhase) name() string {
	names := [...]string{"raw_create", "canary_rotate_close", "canary_open_http", "canary_open_verify", "canary_open_fresh", "canary_open_work", "busy_prepare", "busy_start", "busy_progress", "busy_verify", "canary_switch_http", "canary_new_fresh", "canary_new_work", "canary_release"}
	if int(p) >= len(names) {
		return "invalid"
	}
	return names[p]
}

func nodeLoadActorError(e error) string {
	switch {
	case e == nil:
		return "ok"
	case errors.Is(e, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(e, context.Canceled):
		return "cancelled"
	default:
		return "other"
	}
}

func nodeLoadActorStage(stage string) bool {
	switch stage {
	case "raw_create", "raw_fresh", "raw_work", "raw_busy", "raw_stop", "raw_empty", "raw_destroy", "raw_replay", "canary_open", "canary_start", "canary_switch", "canary_release", "canary_new", "canary_old_gc", "canary_replay":
		return true
	}
	return false
}

// Outcome is the closed Go error class. "ok" does NOT assert a successful
// lifecycle: an ordinary503 refusal also returns a nil Go error.
type nodeLoadActorPoint struct {
	Phase   string  `json:"phase"`
	BeginMS float64 `json:"begin_ms"`
	EndMS   float64 `json:"end_ms"`
	Ended   bool    `json:"ended"`
	Outcome string  `json:"outcome"`
}

type nodeLoadActorSnapshot struct {
	Kind        int                  `json:"kind"`
	Index       int                  `json:"intent_index"`
	Tenant      int                  `json:"tenant"`
	Worker      int                  `json:"worker"`
	ElapsedMS   float64              `json:"elapsed_ms"`
	BudgetKnown bool                 `json:"budget_known"`
	BudgetMS    float64              `json:"budget_ms"`
	Done        bool                 `json:"done"`
	ResultStage string               `json:"result_stage"`
	Outcome     string               `json:"outcome"`
	Invalid     bool                 `json:"invalid"`
	Phases      []nodeLoadActorPoint `json:"phases"`
	Server      []nodeLoadServerCall `json:"server"`
}

type nodeLoadActorsSnapshot struct {
	Version int                     `json:"version"`
	Invalid bool                    `json:"invalid"`
	Latest  []nodeLoadActorSnapshot `json:"latest"`
	Failure *nodeLoadActorSnapshot  `json:"failure"`
}

type nodeLoadActor struct {
	mu    sync.Mutex
	start time.Time
	now   func() time.Time
	value nodeLoadActorSnapshot
	seen  [loadActorRelease + 1]bool
	last  nodeLoadActorPhase
}

type nodeLoadActors struct {
	mu      sync.Mutex
	latest  [nodeLoadActorSlots]*nodeLoadActor
	failure *nodeLoadActorSnapshot
	invalid bool
}

type nodeLoadActorContextKey struct{}

func nodeLoadActorSlot(kind, index, tenant, worker int) (int, bool) {
	if tenant < 0 || tenant > 1 || index < 0 || index%2 != tenant {
		return 0, false
	}
	if kind == 0 && index < nodeLoadRawTotal && worker >= 0 && worker < nodeLoadWorkers {
		return tenant*nodeLoadWorkers + worker, true
	}
	if kind == 1 && index < nodeLoadCanaryTotal && worker == 0 {
		return 2*nodeLoadWorkers + tenant, true
	}
	return 0, false
}

// now is a unit-test clock seam only. The run's only call site passes nil;
// neither CLI, environment nor tenant input can select a clock or trace target.
func (actors *nodeLoadActors) begin(ctx context.Context, kind, index, tenant, worker int, now func() time.Time) (context.Context, *nodeLoadActor) {
	slot, valid := nodeLoadActorSlot(kind, index, tenant, worker)
	actors.mu.Lock()
	defer actors.mu.Unlock()
	if !valid {
		actors.invalid = true
		return ctx, nil
	}
	if now == nil {
		now = time.Now
	}
	a := &nodeLoadActor{start: now(), now: now}
	a.value = nodeLoadActorSnapshot{Kind: kind, Index: index, Tenant: tenant, Worker: worker, Outcome: "pending", Phases: []nodeLoadActorPoint{}, Server: []nodeLoadServerCall{}}
	if deadline, ok := ctx.Deadline(); ok {
		a.value.BudgetKnown = true
		a.value.BudgetMS = max(0, nodeLoadMS(deadline.Sub(a.start)))
	}
	if previous := actors.latest[slot]; previous != nil {
		previous.mu.Lock()
		if !previous.value.Done {
			actors.invalid = true // Never silently replace a still-running actor.
		}
		previous.mu.Unlock()
	}
	actors.latest[slot] = a
	return context.WithValue(ctx, nodeLoadActorContextKey{}, a), a
}

func (s *nodeLoadState) beginActor(ctx context.Context, kind, index, tenant, worker int) (context.Context, *nodeLoadActor) {
	s.mu.Lock()
	enabled := s.observe != nil
	s.mu.Unlock()
	if !enabled {
		return ctx, nil
	}
	return s.actors.begin(ctx, kind, index, tenant, worker, nil)
}

func (a *nodeLoadActor) beginPhase(phase nodeLoadActorPhase) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := len(a.value.Phases)
	if phase > loadActorRelease || a.value.Done || n >= nodeLoadActorPhaseLimit || a.seen[phase] || n > 0 && (!a.value.Phases[n-1].Ended || phase <= a.last) || a.value.Kind == 0 && phase != loadActorRawCreate && (phase < loadActorBusyPrepare || phase > loadActorBusyVerify) || a.value.Kind == 1 && phase == loadActorRawCreate || phase == loadActorRelease && (!a.seen[loadActorSwitch] || a.seen[loadActorNewFresh] || a.seen[loadActorNewWork]) {
		a.value.Invalid = true
		return -1
	}
	at := nodeLoadMS(a.now().Sub(a.start))
	if at < 0 || n > 0 && at < a.value.Phases[n-1].EndMS {
		a.value.Invalid = true
	}
	a.seen[phase] = true
	a.last = phase
	a.value.Phases = append(a.value.Phases, nodeLoadActorPoint{Phase: phase.name(), BeginMS: at, Outcome: "pending"})
	return n
}

func (a *nodeLoadActor) endPhase(n int, e error) {
	if n < 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if n >= len(a.value.Phases) || a.value.Phases[n].Ended || n != len(a.value.Phases)-1 || a.value.Done {
		a.value.Invalid = true
		return
	}
	point := &a.value.Phases[n]
	point.EndMS = nodeLoadMS(a.now().Sub(a.start))
	point.Ended, point.Outcome = true, nodeLoadActorError(e)
	if point.EndMS < point.BeginMS {
		a.value.Invalid = true
	}
}

func nodeLoadTraced[T any](ctx context.Context, phase nodeLoadActorPhase, call func() (T, error)) (T, error) {
	a, _ := ctx.Value(nodeLoadActorContextKey{}).(*nodeLoadActor)
	if a == nil {
		return call()
	}
	n := a.beginPhase(phase)
	value, e := call() // Always the original call, once, with the original context.
	a.endPhase(n, e)
	return value, e
}

func nodeLoadTraceError(ctx context.Context, phase nodeLoadActorPhase, call func() error) error {
	_, e := nodeLoadTraced(ctx, phase, func() (struct{}, error) { return struct{}{}, call() })
	return e
}

func (a *nodeLoadActor) finish(row nodeLoadRow, e error) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.value.Done || row.Kind != a.value.Kind || row.Index != a.value.Index || row.Tenant != a.value.Tenant || !nodeLoadActorStage(row.Stage) || len(a.value.Phases) > 0 && !a.value.Phases[len(a.value.Phases)-1].Ended {
		a.value.Invalid = true
	}
	a.value.Done, a.value.ResultStage, a.value.Outcome = true, row.Stage, nodeLoadActorError(e)
	a.value.ElapsedMS = nodeLoadMS(a.now().Sub(a.start))
	if a.value.ElapsedMS < 0 || len(a.value.Phases) > 0 && a.value.ElapsedMS < a.value.Phases[len(a.value.Phases)-1].EndMS {
		a.value.Invalid = true
	}
}

func (a *nodeLoadActor) snapshot() nodeLoadActorSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	v := nodeLoadActorClone(a.value)
	if !v.Done {
		v.ElapsedMS = nodeLoadMS(a.now().Sub(a.start))
	}
	return v
}

func (actors *nodeLoadActors) freezeFailure(row nodeLoadRow, cause error) {
	actors.mu.Lock()
	defer actors.mu.Unlock()
	if actors.failure != nil || cause == nil || !nodeLoadActorStage(row.Stage) {
		return
	}
	for _, a := range actors.latest {
		if a == nil {
			continue
		}
		v := a.snapshot()
		if v.Done && v.Kind == row.Kind && v.Index == row.Index && v.Tenant == row.Tenant && v.ResultStage == row.Stage {
			// record validation can fail after the call returned nil. Preserve the
			// actual first worker error, not a fabricated failed HTTP phase.
			v.Outcome = nodeLoadActorError(cause)
			actors.failure = &v // Deep snapshot; later actors/cancellation cannot replace it.
			return
		}
	}
}

func (actors *nodeLoadActors) snapshot() nodeLoadActorsSnapshot {
	actors.mu.Lock()
	defer actors.mu.Unlock()
	v := nodeLoadActorsSnapshot{Version: 2, Invalid: actors.invalid, Latest: []nodeLoadActorSnapshot{}}
	for _, a := range actors.latest {
		if a != nil {
			v.Latest = append(v.Latest, a.snapshot())
		}
	}
	if actors.failure != nil {
		f := nodeLoadActorClone(*actors.failure)
		v.Failure = &f
	}
	return v
}
