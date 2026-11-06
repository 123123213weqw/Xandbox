//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

const nodeLoadInventoryLimit = 7200

// No Ref, credential, PID, path, guest output or raw error enters a load row.
type nodeLoadRow struct {
	Kind, Index, Phase, Tenant                                                                                           int
	Outcome, Stage                                                                                                       string
	APIObserved                                                                                                          bool
	QueueMS, ReplyMS, DueReplyMS, FirstMS, StopReplyMS, EmptyMS, NamespaceMS, FullQuotaMS, RevokeMS, TotalMS, FinishedMS float64
}
type nodeLoadKey struct {
	Kind, Tenant int
	Key, Session string
	Revision     uint64
	Ref          sandbox.Ref
}
type nodeLoadInventory struct {
	Version int
	Keys    []nodeLoadKey
}
type nodeLoadState struct {
	mu                           sync.Mutex
	rows                         []nodeLoadRow
	keys                         []nodeLoadKey
	seen                         map[int]bool
	seenKeys                     map[string]bool
	first                        error
	firstRow                     *nodeLoadRow
	observe                      func(context.Context, int, string) nodeLoadObservation
	probesStarted, probesOmitted int
	privateDiagnostics           nodeLoadPrivateDiagnostics
	actors                       nodeLoadActors

	samples []nodeLoadResource
}

func (s *nodeLoadState) record(row nodeLoadRow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[int]bool{}
	}
	id := row.Kind*10000 + row.Index
	if row.Kind == 1 && row.Index >= nodeLoadCanaryTotal || row.Kind == 2 && row.Index >= nodeLoadTailTotal || row.Kind < 2 && row.Phase >= 4 || row.Kind == 2 && row.Phase != 4 {
		return errors.New("result ordinal/phase exceeded its fixed stream")
	}
	if row.Kind < 0 || row.Kind > 2 || row.Index < 0 || row.Index >= nodeLoadRawTotal || row.Tenant < 0 || row.Tenant > 1 || row.Phase < 0 || row.Phase > 4 || !nodeLoadOutcomeValid(row.Outcome) || s.seen[id] || len(s.rows) >= nodeLoadRawTotal+nodeLoadCanaryTotal+nodeLoadTailTotal {
		return errors.New("bounded unique closed load result required")
	}
	for _, v := range []float64{row.QueueMS, row.ReplyMS, row.DueReplyMS, row.FirstMS, row.StopReplyMS, row.EmptyMS, row.NamespaceMS, row.FullQuotaMS, row.RevokeMS, row.TotalMS, row.FinishedMS} {
		if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			return errors.New("invalid load timing observation")
		}
	}
	if row.Outcome == "completed" && (!row.APIObserved || row.EmptyMS > row.NamespaceMS || row.Kind == 2 && row.FullQuotaMS < row.NamespaceMS) {
		return errors.New("completed load row lacks ordered API/kernel/reclamation evidence")
	}
	s.seen[id] = true
	s.rows = append(s.rows, row)
	return nil
}
func (s *nodeLoadState) fail(row nodeLoadRow, e error) bool {
	if e == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.first == nil {
		s.first = e
		copy := row
		s.firstRow = &copy
		s.actors.freezeFailure(row, e)
		return true
	}
	return false
}
func (s *nodeLoadState) addKey(k nodeLoadKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.keys) >= nodeLoadInventoryLimit || !nodeLoadKeyValid(k) {
		return errors.New("invalid bounded private load replay inventory")
	}
	if s.seenKeys == nil {
		s.seenKeys = map[string]bool{}
	}
	if s.seenKeys[k.Key] {
		return errors.New("duplicate private load replay capability")
	}
	s.seenKeys[k.Key] = true
	s.keys = append(s.keys, k)
	return nil
}
func nodeLoadKeyValid(k nodeLoadKey) bool {
	if k.Tenant < 0 || k.Tenant > 1 || !hashPattern.MatchString(k.Key) || !switchRefValid(k.Ref) {
		return false
	}
	switch k.Kind {
	case 0:
		return k.Session == "" && k.Revision == 0
	case 1:
		return hex32Pattern(k.Session) && k.Revision == 0
	case 2:
		return hex32Pattern(k.Session) && k.Revision > 0 && k.Revision < 64
	}
	return false
}
func (s *nodeLoadState) summary() (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	groups := make([]map[string]any, 0, 10)
	for kind := 0; kind < 3; kind++ {
		phases := 4
		if kind == 2 {
			phases = 1
		}
		for phase := 0; phase < phases; phase++ {
			for tenant := 0; tenant < 2; tenant++ {
				counts := map[string]int{"completed": 0, "service_unavailable503": 0, "tenant_quota": 0, "generator_late_drop": 0, "generator_queue_drop": 0, "failed": 0}
				values := map[string][]float64{}
				offered, afterWindowIntents := 0, 0
				for _, row := range s.rows {
					if row.Kind != kind || row.Tenant != tenant || (kind != 2 && row.Phase != phase) {
						continue
					}
					offered++
					counts[row.Outcome]++
					if row.FinishedMS > float64(nodeLoadDuration/time.Millisecond) {
						afterWindowIntents++
					}
					if row.Outcome == "generator_late_drop" || row.Outcome == "generator_queue_drop" {
						continue
					}
					values["client_queue_delay_ms"] = append(values["client_queue_delay_ms"], row.QueueMS)
					if !row.APIObserved {
						continue
					}
					values["api_reply_ms_all_started_outcomes"] = append(values["api_reply_ms_all_started_outcomes"], row.ReplyMS)
					values["scheduled_due_to_reply_ms_all_started_outcomes"] = append(values["scheduled_due_to_reply_ms_all_started_outcomes"], row.DueReplyMS)
					if row.Outcome != "completed" {
						continue
					}
					for name, v := range map[string]float64{"first_fresh_guest_command_ms": row.FirstMS, "stop_or_switch_reply_ms": row.StopReplyMS, "execution_domain_empty_ms": row.EmptyMS, "old_private_namespace_destroyed_ms": row.NamespaceMS, "total_iteration_ms": row.TotalMS} {
						values[name] = append(values[name], v)
					}
					if kind == 1 {
						values["server_measured_revocation_ms"] = append(values["server_measured_revocation_ms"], row.RevokeMS)
					}
					if kind == 2 {
						values["quiescent_full_project_clear_ms"] = append(values["quiescent_full_project_clear_ms"], row.FullQuotaMS)
					}
				}
				quantiles := map[string]nodeLoadQuantile{}
				for name, v := range values {
					q, e := nodeLoadQuantiles(v)
					if e != nil {
						return nil, e
					}
					quantiles[name] = q
				}
				groups = append(groups, map[string]any{"kind": kind, "phase": phase, "tenant": tenant, "observed_intents": offered, "outcomes": counts, "finished_after_offered_window": afterWindowIntents, "quantiles": quantiles})
			}
		}
	}
	out := map[string]any{"planned_raw_intents": nodeLoadRawTotal, "planned_canary_intents": nodeLoadCanaryTotal, "planned_quiescent_tail": nodeLoadTailTotal, "observed_result_rows": len(s.rows), "accepted_replay_inventory_count": len(s.keys), "groups": groups, "resource_samples": append([]nodeLoadResource(nil), s.samples...), "nearest_rank_no_zero_latency_for_drops": true, "quotas_checked_only_quiescent_not_attributed_across_active_reuse": true}
	out["slow_create_probes_started"], out["slow_create_probes_omitted"] = s.probesStarted, s.probesOmitted
	s.privateDiagnostics.Omitted = s.probesOmitted
	s.privateDiagnostics.CreationActivityVersion = 1
	s.privateDiagnostics.Actors = s.actors.snapshot()
	if len(s.privateDiagnostics.Slow) > 0 || s.privateDiagnostics.Failure != nil || s.privateDiagnostics.PreflightBefore != nil || s.privateDiagnostics.PreflightAfter != nil {
		if e := nodeLoadPrivateBound(s.privateDiagnostics); e != nil {
			return nil, e
		}
		out["private_load_diagnostics"] = s.privateDiagnostics
	}
	if s.firstRow != nil {
		out["first_failure"] = *s.firstRow
	}
	return out, nil
}

type nodeLoadResource struct {
	Kernel                                                          map[string]uint64 `json:"kernel"`
	ElapsedMS                                                       float64           `json:"elapsed_ms"`
	DurationMS                                                      float64           `json:"observation_ms"`
	Allocated, Records                                              uint64
	StopQueued, CleanupQueued, StopRunning, CleanupRunning          uint64
	NodeCurrent, NodePeak, ControlCurrent, ControlPeak              uint64
	NodeMaxEvents, NodeOOM, NodeOOMKills, NodeOOMGroups             uint64
	ControlMaxEvents, ControlOOM, ControlOOMKills, ControlOOMGroups uint64
	ControllerRSS                                                   uint64
	ControllerFDs                                                   int
	RootFree, QuotaSpace, QuotaInodes                               uint64
	QuotaNonempty                                                   int
}

func nodeLoadMetric(text, name string) (uint64, error) {
	var value uint64
	count := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, name+" ") {
			v, e := strconv.ParseUint(strings.TrimPrefix(line, name+" "), 10, 64)
			if e != nil {
				return 0, e
			}
			value = v
			count++
		}
	}
	if count != 1 {
		return 0, errors.New("missing or duplicate exact load metric")
	}
	return value, nil
}
func (n *node) nodeLoadSample(ctx context.Context, start time.Time, identity string) (nodeLoadResource, error) {
	var row nodeLoadResource
	if e := requireNode(); e != nil {
		return row, e
	}
	if !n.nodeLoad || n.process == nil {
		return row, errors.New("fixed load controller required")
	}
	if e := n.loadInit.healthy(ctx); e != nil {
		return row, e
	}
	observed := time.Now()
	row.ElapsedMS = switchMS(start)
	got, e := processStart(n.process.Process.Pid)
	if e != nil || got != identity {
		return row, errors.New("load controller incarnation changed")
	}
	g, e := switchGauges(ctx)
	if e != nil {
		return row, e
	}
	row.Allocated, row.StopQueued, row.CleanupQueued, row.StopRunning, row.CleanupRunning = g["allocated"], g["stop_queued"], g["cleanup_queued"], g["stop_running"], g["cleanup_running"]
	if row.Allocated > 4 || row.StopQueued > 4 || row.CleanupQueued > 4 || row.StopRunning > 4 || row.CleanupRunning > 2 {
		return row, errors.New("ordinary load pools exceeded their configured bounds")
	}
	c := newSwitchAPI("/srv/state/metrics.sock", "")
	defer c.close()
	req, e := httpRequestMetrics(ctx)
	if e != nil {
		return row, e
	}
	resp, e := c.http.Do(req)
	if e != nil {
		return row, e
	}
	b, e := readSwitchMetrics(resp.Body)
	resp.Body.Close()
	if e != nil || resp.StatusCode != 200 {
		return row, errors.New("load metrics unavailable")
	}
	row.Kernel, e = n.nodeLoadKernelCounters(b)
	if e != nil {
		return row, e
	}
	if row.Kernel["node_pids"] > 384 || row.Kernel["control_pids"] > 128 || row.Kernel["node_pids_max_events"] != 0 || row.Kernel["control_pids_max_events"] != 0 {
		return row, errors.New("node/control PID policy hit during non-fault load")
	}
	row.Records, e = nodeLoadMetric(string(b), "xandbox_records")
	if e != nil || row.Records > 10000 {
		return row, errors.New("retained load record bound invalid")
	}
	// Read each current before its corresponding monotonic peak. Iterating a
	// map could read peak first and create a spurious current>peak observation.
	for _, item := range []struct {
		path        string
		destination *uint64
	}{
		{nodeGroup + "/memory.current", &row.NodeCurrent}, {nodeGroup + "/memory.peak", &row.NodePeak},
		{nodeGroup + "/control/memory.current", &row.ControlCurrent}, {nodeGroup + "/control/memory.peak", &row.ControlPeak},
	} {
		b, e := os.ReadFile(item.path)
		if e != nil {
			return row, e
		}
		*item.destination, e = switchUint(string(b))
		if e != nil {
			return row, e
		}
	}
	for _, item := range []struct {
		group                       string
		want                        uint64
		maximum, oom, kills, groups *uint64
	}{
		{nodeGroup, nodeLoadPolicy().MemoryMax, &row.NodeMaxEvents, &row.NodeOOM, &row.NodeOOMKills, &row.NodeOOMGroups},
		{nodeGroup + "/control", nodeLoadPolicy().ControllerMemoryMax, &row.ControlMaxEvents, &row.ControlOOM, &row.ControlOOMKills, &row.ControlOOMGroups},
	} {
		b, e := os.ReadFile(item.group + "/memory.max")
		if e != nil || strings.TrimSpace(string(b)) != strconv.FormatUint(item.want, 10) {
			return row, errors.New("load memory policy changed")
		}
		f, e := nodeOOMOpen(item.group + "/memory.events")
		if e != nil {
			return row, e
		}
		v, e := nodeOOMReadEvents(f)
		f.Close()
		if e != nil || v.OOM != 0 || v.Kills != 0 || v.Groups != 0 {
			return row, errors.New("OOM during sustained non-OOM experiment")
		}
		*item.maximum, *item.oom, *item.kills, *item.groups = v.Max, v.OOM, v.Kills, v.Groups
	}
	b, e = os.ReadFile(fmt.Sprintf("/proc/%d/status", n.process.Process.Pid))
	if e != nil {
		return row, e
	}
	found := false
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "VmRSS:" && f[2] == "kB" {
			v, err := strconv.ParseUint(f[1], 10, 64)
			if err != nil || found {
				return row, errors.New("invalid load RSS")
			}
			row.ControllerRSS = v * 1024
			found = true
		}
	}
	if !found {
		return row, errors.New("missing actual load controller RSS")
	}
	fds, e := os.ReadDir(fmt.Sprintf("/proc/%d/fd", n.process.Process.Pid))
	if e != nil {
		return row, e
	}
	row.ControllerFDs = len(fds)
	if row.ControllerFDs > 128 {
		return row, errors.New("predeclared observed controller FD guard exceeded")
	}
	var fs unix.Statfs_t
	if e = unix.Statfs("/srv", &fs); e != nil {
		return row, e
	}
	row.RootFree = fs.Bavail * uint64(fs.Bsize)
	if row.RootFree < 256<<20 {
		return row, errors.New("fixed free-space runway exhausted")
	}
	for id := driverProjectFirst; id < driverProjectFirst+4; id++ {
		q, e := driverQuotaRead(id)
		if e != nil {
			return row, e
		}
		if !switchKnown(q) {
			return row, errors.New("load kernel quota policy drift")
		}
		row.QuotaSpace += q.Space
		row.QuotaInodes += q.Inodes
		if !quotaEmpty(q) {
			row.QuotaNonempty++
		}
	}
	got, e = processStart(n.process.Process.Pid)
	if e != nil || got != identity {
		return row, errors.New("controller changed during load sample")
	}
	row.DurationMS = switchMS(observed)
	return row, nil
}

// Coverage is checked before declaring a successful run, not inferred from a
// forty-minute timer plus a handful of samples. The quiescent tail/final sample
// is separate and may follow a longer gap than the ten-second offered samples.
func nodeLoadSamplesValid(samples []nodeLoadResource) error {
	bad := func() error { return errors.New("incomplete or invalid sustained resource series") }
	if len(samples) < 240 || len(samples) > nodeLoadSampleLimit {
		return bad()
	}
	first, final := samples[0], samples[len(samples)-1]
	if first.ElapsedMS >= 5000 || first.Allocated != 2 || final.ElapsedMS < nodeLoadMS(nodeLoadDuration) || final.ControllerFDs > first.ControllerFDs+4 || final.Allocated != 0 || final.QuotaSpace != 0 || final.QuotaInodes != 0 || final.QuotaNonempty != 0 || final.StopQueued != 0 || final.CleanupQueued != 0 || final.StopRunning != 0 || final.CleanupRunning != 0 {
		return bad()
	}
	if samples[len(samples)-2].ElapsedMS < nodeLoadMS(nodeLoadDuration-20*time.Second) {
		return bad()
	}
	for i, row := range samples {
		if math.IsNaN(row.ElapsedMS) || math.IsInf(row.ElapsedMS, 0) || row.ElapsedMS < 0 || math.IsNaN(row.DurationMS) || math.IsInf(row.DurationMS, 0) || row.DurationMS < 0 || row.DurationMS > 5000 || row.NodeCurrent > row.NodePeak || row.NodePeak > 7<<30 || row.ControlCurrent > row.ControlPeak || row.ControlPeak > 3840<<20 || row.NodeOOM != 0 || row.NodeOOMKills != 0 || row.NodeOOMGroups != 0 || row.ControlOOM != 0 || row.ControlOOMKills != 0 || row.ControlOOMGroups != 0 {
			return bad()
		}
		if i > 0 {
			gap := row.ElapsedMS - samples[i-1].ElapsedMS
			if gap <= 0 || i < len(samples)-1 && gap > 20000 {
				return bad()
			}
		}
	}
	return nil
}
