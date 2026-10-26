//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/session"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

const nodeLoadInventoryPath = "/srv/fixture/node-load-inventory.json"

func (n *node) nodeLoadAllGone(ctx context.Context) error {
	if e := requireNode(); e != nil {
		return e
	}
	if !n.nodeLoad {
		return errors.New("fixed load profile required")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if e := waitNode(bounded, func() (bool, error) {
		g, e := switchGauges(ctx)
		if e != nil {
			return false, e
		}
		return g["allocated"] == 0 && g["stop_queued"] == 0 && g["cleanup_queued"] == 0 && g["stop_running"] == 0 && g["cleanup_running"] == 0, nil
	}); e != nil {
		return e
	}
	entries, e := os.ReadDir(nodeBudgetInstances)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return errors.New("load retained an execution cgroup")
		}
	}
	owners, e := os.ReadDir("/srv/state/firecracker")
	if e != nil {
		return e
	}
	for _, entry := range owners {
		if hashPattern.MatchString(strings.TrimSuffix(entry.Name(), ".json")) {
			return errors.New("load retained a generation owner")
		}
	}
	return driverQuotaAllClear()
}

func (n *node) nodeLoadRun(ctx context.Context) (out map[string]any, retErr error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.nodeLoad || !n.nodeBudget || !n.quotaDriver || n.nodeSnapshot || n.process != nil {
		return nil, errors.New("fresh exclusive long-load L1 required")
	}
	if _, e := fixedNodeLoadConfig(); e != nil {
		return nil, e
	}
	if e := n.start(ctx); e != nil {
		return nil, e
	}
	state := &nodeLoadState{}
	var measuredStart time.Time
	defer func() {
		if retErr != nil {
			state.fail(nodeLoadRow{Stage: "load_setup_or_finalization"}, retErr)
		}
		if retErr != nil {
			state.captureFailure(ctx)
		}
		partial, e := state.summary()
		if e != nil {
			retErr = e
			return
		}
		partial["full_offered_window_ms"] = int64(nodeLoadDuration / time.Millisecond)
		partial["fixed_workers_each_tenant"] = nodeLoadWorkers
		partial["fixed_client_queue_each_tenant"] = nodeLoadQueue
		partial["production_slo_claim"] = false
		partial["full_production_acceptance"] = false
		partial["load_window_completed"] = !measuredStart.IsZero() && time.Since(measuredStart) >= nodeLoadDuration
		partial["run_passed"] = retErr == nil
		if retErr == nil {
			for _, flag := range []string{"real_nested_kvm", "pid1_preflight_census_clean", "reused_guest_heartbeat_preflight_passed", "checkpoint_receipt_fsynced", "all_raw_and_canary_intents_accounted", "fixed_offered_clock_not_completion_paced", "cross_tenant_lookup404_checked", "coarse_one_fifth_equal_offer_progress_guard_passed", "high_rate_service_refusal_observed", "all_pools_and_private_namespaces_empty", "quiescent_exact_project_clear_tail_passed", "accepted_private_replay_inventory_fsynced", "cold_distinct_phase_armed", "no_operator_quota_sync_in_offered_window", "post_drain_controller_fd_guard_passed"} {
				partial[flag] = true
			}
		}
		out = partial
		encoded, e := json.Marshal(out)
		if e != nil || len(encoded) > nodeLoadReplyMax-1024 {
			retErr = errors.New("bounded numeric load report exceeded fixed frame")
			out = nil
		}
	}()
	identity, e := processStart(n.process.Process.Pid)
	if e != nil {
		return nil, e
	}
	state.observe = func(ctx context.Context, tenant int, key string) nodeLoadObservation {
		return n.nodeLoadObserve(ctx, tenant, key, identity, measuredStart)
	}
	captureCensus := func(before bool) error {
		bounded, cancel := context.WithTimeout(ctx, nodeLoadProbeBudget)
		census := n.nodeLoadPID1Census(bounded, identity)
		cancel()
		stage := "pid1_preflight_after"
		if before {
			stage = "pid1_preflight_before"
			state.privateDiagnostics.PreflightBefore = &census
		} else {
			state.privateDiagnostics.PreflightAfter = &census
		}
		if e := nodeLoadPreflightCensusValid(census); e != nil {
			state.fail(nodeLoadRow{Kind: 3, Index: -1, Tenant: -1, Phase: 4, Stage: stage, Outcome: "failed"}, e)
			return e
		}
		return nil
	}
	if e = captureCensus(true); e != nil {
		return nil, e
	}
	tokens := [2]string{n.token, n.loadTokenB}
	// Eight serial preflight lifecycles exercise the exact guest/Stop/quota wire
	// contracts BEFORE the long window; none are added to its percentile rows.
	for i := 0; i < 8; i++ {
		api := newSwitchAPI("/srv/state/api.sock", tokens[i%2])
		actor, cancel := context.WithTimeout(ctx, 35*time.Second)
		// Kind3 is private preflight identity only; it is never recorded as a
		// measured result row. Join its probe before setting measuredStart.
		row, e := nodeLoadRaw(actor, api, state, time.Now(), nodeLoadArrival{Index: i, Phase: 4, Tenant: i % 2}, 3, true)
		cancel()
		api.close()
		if e != nil || row.Outcome != "completed" {
			if e == nil {
				e = errors.New("preflight unexpectedly admission refused")
			}
			state.fail(row, e)
			return nil, e
		}
	}
	// A retained adopted zombie is a failed resource preflight, never a
	// shortened passing load run. No wait/reap or budget adjustment is done.
	if e = captureCensus(false); e != nil {
		return nil, e
	}
	canaries := [2]*nodeLoadCanary{{}, {}}
	canaryAPI := [2]*switchAPI{newSwitchAPI("/srv/state/api.sock", tokens[0]), newSwitchAPI("/srv/state/api.sock", tokens[1])}
	defer canaryAPI[0].close()
	defer canaryAPI[1].close()
	for tenant := 0; tenant < 2; tenant++ {
		actor, cancel := context.WithTimeout(ctx, 35*time.Second)
		outcome, e := canaries[tenant].open(actor, canaryAPI[tenant], state, tenant)
		cancel()
		if e != nil {
			return nil, e
		}
		if outcome != "completed" {
			return nil, errors.New("idle canary preflight admission failed")
		}
		// Deliberately reuse one assigned guest after ordinary release, so a
		// stale sequence exists on the next attempt. This is preflight only,
		// not Stop evidence and not a shortened replacement for the40min run.
		for attempt := 0; attempt < 3; attempt++ {
			actor, cancel := context.WithTimeout(ctx, 35*time.Second)
			job, deadline, e := nodeLoadBusy(actor, canaryAPI[tenant], canaries[tenant].binding.Current, &canaries[tenant].binding)
			if e == nil {
				e = nodeLoadReleaseBusy(actor, canaryAPI[tenant], canaries[tenant].binding, job)
			}
			if e == nil && !time.Now().Before(deadline) {
				e = errors.New("reused heartbeat preflight exceeded original deadline")
			}
			cancel()
			if e != nil {
				state.fail(nodeLoadRow{Kind: 1, Tenant: tenant, Stage: "reused_heartbeat_preflight"}, e)
				return nil, e
			}
		}
		if e = canaryAPI[1-tenant].call(ctx, "GET", switchPath(canaries[tenant].binding.Current), "", nil, nil, 404); e != nil {
			return nil, e
		}
	}
	measuredStart = time.Now()
	baseline, e := n.nodeLoadSample(ctx, measuredStart, identity)
	if e != nil {
		return nil, e
	}
	if baseline.Allocated != 2 {
		return nil, errors.New("two real canary guests required at load origin")
	}
	state.samples = append(state.samples, baseline)
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	plan, e := nodeLoadArrivals(nodeLoadPlan())
	if e != nil {
		return nil, e
	}
	if len(plan) != nodeLoadRawTotal {
		return nil, errors.New("fixed complete raw plan changed")
	}
	var workers, schedulers, sampler sync.WaitGroup
	rawQueue := [2]chan nodeLoadArrival{make(chan nodeLoadArrival, nodeLoadQueue), make(chan nodeLoadArrival, nodeLoadQueue)}
	canaryQueue := [2]chan nodeLoadArrival{make(chan nodeLoadArrival, nodeLoadQueue), make(chan nodeLoadArrival, nodeLoadQueue)}
	fail := func(row nodeLoadRow, err error) {
		if err != nil {
			if state.fail(row, err) {
				state.captureFailure(ctx)
			}
			nodeLoadWorkerFailure(row.Tenant, row, err)
			cancelRun()
		}
	}
	record := func(row nodeLoadRow, err error) {
		if err != nil {
			row.Outcome = "failed"
		}
		if e := state.record(row); e != nil && err == nil {
			err = e
		}
		fail(row, err)
	}
	for tenant := 0; tenant < 2; tenant++ {
		for worker := 0; worker < nodeLoadWorkers; worker++ {
			workers.Add(1)
			go func(tenant int) {
				defer workers.Done()
				api := newSwitchAPI("/srv/state/api.sock", tokens[tenant])
				defer api.close()
				for arrival := range rawQueue[tenant] {
					actor, cancel := context.WithTimeout(runCtx, 35*time.Second)
					row, e := nodeLoadRaw(actor, api, state, measuredStart, arrival, 0, false)
					cancel()
					record(row, e)
				}
			}(tenant)
		}
		workers.Add(1)
		go func(tenant int) {
			defer workers.Done()
			for arrival := range canaryQueue[tenant] {
				actor, cancel := context.WithTimeout(runCtx, 35*time.Second)
				row, e := canaries[tenant].tick(actor, canaryAPI[tenant], state, measuredStart, arrival)
				cancel()
				record(row, e)
			}
			actor, cancel := context.WithTimeout(ctx, 35*time.Second)
			e := canaries[tenant].close(actor, canaryAPI[tenant])
			cancel()
			fail(nodeLoadRow{Kind: 1, Tenant: tenant, Stage: "canary_revoke"}, e)
		}(tenant)
	}
	schedule := func(kind int, arrivals []nodeLoadArrival, queue [2]chan nodeLoadArrival) {
		defer schedulers.Done()
		err := nodeLoadSchedule(runCtx, nodeLoadRealClock{}, measuredStart, arrivals, func(a nodeLoadArrival, _ time.Time) bool {
			select {
			case queue[a.Tenant] <- a:
				return true
			default:
				return false
			}
		}, func(a nodeLoadArrival, now time.Time, status string) {
			record(nodeLoadRow{Kind: kind, Index: a.Index, Phase: a.Phase, Tenant: a.Tenant, Outcome: status, QueueMS: nodeLoadMS(now.Sub(measuredStart.Add(a.Offset))), FinishedMS: nodeLoadMS(now.Sub(measuredStart))}, nil)
		})
		if err == nil {
			err = (nodeLoadRealClock{}).WaitUntil(runCtx, measuredStart.Add(nodeLoadDuration))
		}
		if err != nil {
			fail(nodeLoadRow{Kind: kind, Stage: "scheduler"}, err)
		}
		if kind == 0 {
			close(queue[0])
			close(queue[1])
		} else {
			for tenant := 0; tenant < 2; tenant++ {
				if queue[tenant] != nil {
					close(queue[tenant])
				}
			}
		}
	}
	schedulers.Add(1)
	go schedule(0, plan, rawQueue)
	for tenant := 0; tenant < 2; tenant++ {
		arrivals := make([]nodeLoadArrival, 0, 120)
		for i := 0; i < 120; i++ {
			offset := time.Duration(i)*20*time.Second + time.Duration(tenant)*5*time.Second
			arrivals = append(arrivals, nodeLoadArrival{Index: i*2 + tenant, Phase: int(offset / (10 * time.Minute)), Tenant: tenant, Offset: offset, Interval: 20 * time.Second})
		}
		queues := [2]chan nodeLoadArrival{}
		queues[tenant] = canaryQueue[tenant]
		schedulers.Add(1)
		go schedule(1, arrivals, queues)
	}
	samplerCtx, stopSampler := context.WithCancel(runCtx)
	sampler.Add(1)
	go func() {
		defer sampler.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-samplerCtx.Done():
				return
			case <-ticker.C:
				if time.Since(measuredStart) > nodeLoadDuration {
					return
				}
				actor, cancel := context.WithTimeout(samplerCtx, 5*time.Second)
				row, e := n.nodeLoadSample(actor, measuredStart, identity)
				cancel()
				if e != nil {
					if samplerCtx.Err() != nil {
						return
					}
					fail(nodeLoadRow{Stage: "sampler"}, e)
					return
				}
				state.mu.Lock()
				if len(state.samples) >= nodeLoadSampleLimit {
					state.mu.Unlock()
					fail(nodeLoadRow{Stage: "sampler"}, errors.New("fixed sample count exceeded"))
					return
				}
				state.samples = append(state.samples, row)
				state.mu.Unlock()
			}
		}
	}()
	schedulers.Wait()
	drained := make(chan struct{})
	go func() { workers.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(180 * time.Second):
		fail(nodeLoadRow{Stage: "drain"}, errors.New("bounded generator drain exceeded"))
		<-drained
	}
	stopSampler()
	sampler.Wait()
	state.mu.Lock()
	failure := state.first
	state.mu.Unlock()
	if failure != nil {
		return nil, failure
	}
	if time.Since(measuredStart) < nodeLoadDuration {
		return nil, errors.New("long offered interval ended early")
	}
	if e = n.nodeLoadAllGone(ctx); e != nil {
		return nil, e
	}
	// No new competing producers remain. Full project-zero timing is now
	// attributable in the separate100-cycle serial tail, not in active reuse.
	for i := 0; i < nodeLoadTailTotal; i++ {
		api := newSwitchAPI("/srv/state/api.sock", tokens[i%2])
		actor, cancel := context.WithTimeout(ctx, 35*time.Second)
		row, e := nodeLoadRaw(actor, api, state, time.Now(), nodeLoadArrival{Index: i, Phase: 4, Tenant: i % 2}, 2, true)
		cancel()
		api.close()
		if e == nil && row.Outcome != "completed" {
			e = errors.New("quiescent tail refused despite free slots")
		}
		record(row, e)
		if e != nil {
			return nil, e
		}
	}
	if e = n.nodeLoadAllGone(ctx); e != nil {
		return nil, e
	}
	if e = nodeLoadAcceptance(state); e != nil {
		return nil, e
	}
	fdCtx, stopFDWait := context.WithTimeout(ctx, 10*time.Second)
	defer stopFDWait()
	if e = waitNode(fdCtx, func() (bool, error) {
		fds, e := os.ReadDir(fmt.Sprintf("/proc/%d/fd", n.process.Process.Pid))
		return e == nil && len(fds) <= baseline.ControllerFDs+4, e
	}); e != nil {
		return nil, e
	}
	final, e := n.nodeLoadSample(ctx, measuredStart, identity)
	if e != nil {
		return nil, e
	}
	state.samples = append(state.samples, final)
	if e = nodeLoadSamplesValid(state.samples); e != nil {
		return nil, e
	}
	if e = n.nodeLoadWriteInventory(state); e != nil {
		return nil, e
	}
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	defer api.close()
	if e = n.budgetFreshCheckpoint(ctx, api, nil, nodeLoadCheckpointPhase); e != nil {
		return nil, e
	}
	return nil, nil
}

func nodeLoadAcceptance(s *nodeLoadState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var raw [4][2]int
	var canaryCompleted [4][2]int
	var offered [4]int
	var canaries, tail int
	var highRefused int
	for _, row := range s.rows {
		if row.Outcome == "failed" {
			return errors.New("failed load result cannot pass")
		}
		switch row.Kind {
		case 0:
			offered[row.Phase]++
			if row.Outcome == "completed" {
				raw[row.Phase][row.Tenant]++
			}
			if row.Phase == 3 && (row.Outcome == "service_unavailable503" || row.Outcome == "tenant_quota") {
				highRefused++
			}
		case 1:
			canaries++
			if row.Outcome == "completed" {
				canaryCompleted[row.Phase][row.Tenant]++
			}
		case 2:
			if row.Outcome != "completed" || row.FullQuotaMS < row.NamespaceMS {
				return errors.New("quiescent exact GC proof missing")
			}
			tail++
		}
	}
	if offered != [4]int{60, 300, 1200, 4800} || canaries != nodeLoadCanaryTotal || tail != nodeLoadTailTotal || len(s.rows) != nodeLoadRawTotal+nodeLoadCanaryTotal+nodeLoadTailTotal {
		return errors.New("every planned arrival/drop/result must be accounted")
	}
	for _, count := range raw {
		if !nodeLoadFair(count[0], count[1]) {
			return errors.New("predeclared equal-offer one-fifth progress guard failed")
		}
	}
	for _, counts := range canaryCompleted {
		if counts[0] == 0 || counts[1] == 0 {
			return errors.New("a canary made no successful switch in one whole phase")
		}
	}
	if highRefused == 0 {
		return errors.New("high-rate phase did not exercise actual service backpressure")
	}
	return nil
}

func (n *node) nodeLoadWriteInventory(state *nodeLoadState) error {
	if e := requireNode(); e != nil {
		return e
	}
	state.mu.Lock()
	inventory := nodeLoadInventory{Version: 1, Keys: append([]nodeLoadKey(nil), state.keys...)}
	state.mu.Unlock()
	if e := validateNodeLoadInventory(inventory); e != nil {
		return e
	}
	b, e := json.Marshal(inventory)
	if e != nil || len(b) > nodeLoadInventoryMax {
		return errors.New("bounded private replay inventory exceeded")
	}
	return privateWrite(nodeLoadInventoryPath, inventory)
}

func validateNodeLoadInventory(v nodeLoadInventory) error {
	if v.Version != 1 || len(v.Keys) < nodeLoadTailTotal+8 || len(v.Keys) > nodeLoadInventoryLimit {
		return errors.New("complete bounded load inventory required")
	}
	seen := map[string]bool{}
	for _, k := range v.Keys {
		if !nodeLoadKeyValid(k) || seen[k.Key] {
			return errors.New("invalid or duplicate private replay capability")
		}
		seen[k.Key] = true
	}
	return nil
}

func (n *node) nodeLoadReplayInventory(ctx context.Context, alpha *switchAPI) error {
	if e := requireNode(); e != nil {
		return e
	}
	if !n.nodeLoad {
		return errors.New("fixed load recovery required")
	}
	b, e := privatefile.Read(nodeLoadInventoryPath, nodeLoadInventoryMax)
	if e != nil {
		return e
	}
	var v nodeLoadInventory
	if e = strictjson.Decode(b, &v); e != nil {
		return e
	}
	if e = validateNodeLoadInventory(v); e != nil {
		return e
	}
	beta := newSwitchAPI("/srv/state/api.sock", n.loadTokenB)
	defer beta.close()
	api := [2]*switchAPI{alpha, beta}
	for _, k := range v.Keys {
		switch k.Kind {
		case 0:
			e = api[k.Tenant].call(ctx, "POST", "/v1/sandboxes", k.Key, nodeSpec(), nil, 410)
		case 1:
			e = api[k.Tenant].call(ctx, "POST", "/v1/sessions", k.Key, nodeSpec(), nil, 410)
		case 2:
			e = api[k.Tenant].call(ctx, "POST", "/v1/sessions/"+k.Session+"/switch", k.Key, session.SwitchRequest{ExpectedRevision: k.Revision, Create: nodeSpec()}, nil, 410)
		}
		if e != nil {
			return e
		}
	}
	return n.nodeLoadAllGone(ctx)
}

func (n *node) nodeLoadRecover(ctx context.Context) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.nodeLoad {
		return nil, errors.New("fixed load cold profile required")
	}
	out, e := n.recoverBudgetCheckpoint(ctx, nodeLoadCheckpointPhase)
	if e != nil {
		return nil, e
	}
	out["all_accepted_raw_and_session_keys_cold_replayed410_before_new_guest"] = true
	out["private_load_inventory_validated_without_restoration"] = true
	return out, nil
}
