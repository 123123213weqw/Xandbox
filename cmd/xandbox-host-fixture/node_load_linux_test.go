//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func TestNodeLoadNamedProfilePreservesEveryOldHardDeadline(t *testing.T) {
	p := testPolicy()
	p.Profile = "node-load-v1"
	memory, disk, outer, e := p.resources()
	if e != nil || p.validate() != nil || memory != 8192 || disk != 12<<30 || outer != 10<<30 || p.cpuCount() != 8 || p.pidCount() != 256 || p.hardLifetime() != time.Hour {
		t.Fatal("new load profile is not exact")
	}
	for _, profile := range []string{"", "node-budget-v1", "node-snapshot-v1", "systemd-ingress-v1", "quota-switch-v1", "quota-copy-v1"} {
		p.Profile = profile
		if p.hardLifetime() != 15*time.Minute {
			t.Fatal("silently enlarged old deadline", profile)
		}
	}
	p.Profile = "node-load-v2"
	if p.validate() == nil || p.arguments() != nil {
		t.Fatal("unknown duration/profile accepted")
	}
	policy := nodeLoadPolicy()
	if policy.MaxInstances != 4 || policy.MaxRecords != 10000 || policy.MaxSessions != 512 || policy.ControllerMemoryMax != 3840<<20 || policy.MemoryMax != 7<<30 || policy.PrepareWorkers != 1 {
		t.Fatal("closed load envelope")
	}
	// Independently recompute the existing production reservation formula; this
	// is planning, not a fake kernel cgroup or a hardware acceptance claim.
	reserve := uint64(128<<20) + 10000*(256<<10) + 512*(1<<20) + 4*(128<<20) + (2 << 20)
	if reserve != 3654<<20 || reserve > policy.ControllerMemoryMax || 4*(768<<20)+policy.ControllerMemoryMax+(2<<20) > policy.MemoryMax {
		t.Fatal("new metadata plan cannot fit unchanged physical node")
	}
	if nodeLoadDuration != 40*time.Minute || nodeLoadRunBudget != 55*time.Minute || nodeLoadRunBudget >= nodeLoadOuterBudget || nodeLoadWorkers != 4 || nodeLoadQueue != 16 || nodeLoadReplyMax != 1<<20 {
		t.Fatal("fixed long profile changed")
	}
}

func TestNodeLoadCannotStartOrMutateOutsideOwnedL1(t *testing.T) {
	n := &node{nodeLoad: true, nodeBudget: true, quotaDriver: true}
	ctx := context.Background()
	if runNodeLoadProfile() == nil || runNodeLoadDaemon() == nil || n.initializeNodeLoad() == nil || n.initializeNodeLoadAuth() == nil || n.nodeLoadAllGone(ctx) == nil {
		t.Fatal("load mode escaped L1 guard")
	}
	if _, e := n.nodeLoadRun(ctx); e == nil {
		t.Fatal("long scheduler ran on L0")
	}
	if _, e := n.nodeLoadRecover(ctx); e == nil {
		t.Fatal("cold recovery escaped L1")
	}
	if n.nodeLoadWriteInventory(&nodeLoadState{}) == nil || n.nodeLoadReplayInventory(ctx, nil) == nil {
		t.Fatal("private capability IO escaped L1")
	}
	ref := sandbox.Ref{ID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}
	if _, e := nodeLoadDomainEmpty(ref); e == nil {
		t.Fatal("kernel observer escaped L1")
	}
	for _, op := range []string{"node-load-run", "node-load-recover"} {
		if (nodeRequest{Version: 1, Operation: op}).validate() != nil || (nodeRequest{Version: 1, Operation: op, Phase: "short"}).validate() == nil || (nodeRequest{Version: 1, Operation: op, Receipt: []byte(`{}`)}).validate() == nil {
			t.Fatal("arbitrary duration/receipt selector")
		}
	}
}

func TestNodeLoadPlanHasExactEqualOfferedCountsAndNoHiddenWarmup(t *testing.T) {
	arrivals, e := nodeLoadArrivals(nodeLoadPlan())
	if e != nil || len(arrivals) != 6360 {
		t.Fatal(len(arrivals), e)
	}
	var counts [4][2]int
	for i, a := range arrivals {
		if a.Index != i || a.Tenant != i%2 || a.Offset < 0 || a.Offset >= nodeLoadDuration || i > 0 && a.Offset <= arrivals[i-1].Offset {
			t.Fatal("arrival identity/clock changed")
		}
		counts[a.Phase][a.Tenant]++
	}
	if counts != [4][2]int{{30, 30}, {150, 150}, {600, 600}, {2400, 2400}} || arrivals[len(arrivals)-1].Offset != nodeLoadDuration-125*time.Millisecond {
		t.Fatal(counts)
	}
	for _, bad := range [][]nodeLoadPhase{nil, {{0, time.Second}}, {{time.Second, 0}}, {{time.Second, -time.Second}}, {{time.Second, 3 * time.Millisecond}}, {{time.Hour, time.Second}}, {{time.Minute, time.Nanosecond}}} {
		if _, e = nodeLoadArrivals(bad); e == nil {
			t.Fatal("unbounded/invalid plan accepted")
		}
	}
}

type nodeLoadTestClock struct{ now time.Time }

func (c *nodeLoadTestClock) Now() time.Time { return c.now }
func (c *nodeLoadTestClock) WaitUntil(ctx context.Context, due time.Time) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if c.now.Before(due) {
		c.now = due
	}
	return nil
}

func TestNodeLoadOpenClockCountsGeneratorDropsWithoutCoordinatedOmission(t *testing.T) {
	plan, e := nodeLoadArrivals([]nodeLoadPhase{{10 * time.Second, time.Second}})
	if e != nil {
		t.Fatal(e)
	}
	start := time.Unix(100, 0)
	clock := &nodeLoadTestClock{start}
	enqueued, dropped := 0, 0
	seen := map[int]bool{}
	e = nodeLoadSchedule(context.Background(), clock, start, plan, func(a nodeLoadArrival, now time.Time) bool {
		if now.Before(start.Add(a.Offset)) || seen[a.Index] {
			t.Fatal("early or repeated arrival")
		}
		seen[a.Index] = true
		if a.Index == 0 {
			clock.now = clock.now.Add(5 * time.Second)
		}
		if a.Index == 6 {
			return false
		}
		enqueued++
		return true
	}, func(a nodeLoadArrival, now time.Time, why string) {
		if why != "generator_late_drop" && why != "generator_queue_drop" {
			t.Fatal("not a closed generator outcome")
		}
		if why == "generator_late_drop" {
			if seen[a.Index] {
				t.Fatal("late drop duplicated an offer")
			}
			seen[a.Index] = true
		}
		dropped++
	})
	if e != nil || enqueued+dropped != 10 || len(seen) != 10 || dropped != 4 {
		t.Fatal(enqueued, dropped, len(seen), e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if nodeLoadSchedule(ctx, clock, start, plan, func(nodeLoadArrival, time.Time) bool { t.Fatal("dispatched canceled schedule"); return false }, func(nodeLoadArrival, time.Time, string) { t.Fatal("invented drops after cancel") }) == nil {
		t.Fatal("canceled scheduler accepted")
	}
}

func TestNodeLoadQuantilesAndProgressGuardAreFiniteAndPredeclared(t *testing.T) {
	values := make([]float64, 100)
	for i := range values {
		values[i] = float64(100 - i)
	}
	q, e := nodeLoadQuantiles(values)
	if e != nil || q.N != 100 || q.P50 != 50 || q.P95 != 95 || q.P99 != 99 || q.Max != 100 || values[0] != 100 {
		t.Fatal(q, e)
	}
	for _, bad := range [][]float64{{-1}, {math.NaN()}, {math.Inf(1)}, make([]float64, 10000)} {
		if _, e = nodeLoadQuantiles(bad); e == nil {
			t.Fatal("bad latency admitted")
		}
	}
	if !nodeLoadFair(20, 80) || nodeLoadFair(19, 81) || nodeLoadFair(0, 1) || nodeLoadFair(1, 0) || nodeLoadFair(math.MaxInt, math.MaxInt) {
		t.Fatal("coarse fairness guard drifted")
	}
}

func TestNodeLoadOnlyInstanceQuotaResponsesAreNonfatal(t *testing.T) {
	for _, test := range []struct {
		status     int
		body, want string
	}{{429, `{"error":{"code":"TENANT_QUOTA"}}`, "tenant_quota"}, {503, `{"error":{"code":"UNAVAILABLE"}}`, "service_unavailable503"}} {
		got, e := nodeLoadReply(test.status, []byte(test.body), 201, nil)
		if e != nil || got != test.want {
			t.Fatal(got, e)
		}
	}
	for _, code := range []string{"METADATA_CAPACITY", "TENANT_METADATA_QUOTA", "SESSION_CAPACITY", "TENANT_SESSION_QUOTA", "SESSION_HISTORY_LIMIT", "SESSION_UNAVAILABLE", "UNAUTHORIZED", "INTERNAL", "NODE_DRAINING", "JOB_LIMIT"} {
		for _, status := range []int{429, 503, 500} {
			if _, e := nodeLoadReply(status, []byte(`{"error":{"code":"`+code+`"}}`), 201, nil); e == nil {
				t.Fatal("masked non-instance failure", code)
			}
		}
	}
	if _, e := nodeLoadReply(503, []byte("broken"), 201, nil); e == nil {
		t.Fatal("invalid error masked")
	}
	if _, e := nodeLoadReply(201, make([]byte, (1<<20)+1), 201, nil); e == nil {
		t.Fatal("unbounded public reply")
	}
}

func TestNodeLoadStateDoesNotLoseFirstFailureOrInventDropLatencies(t *testing.T) {
	s := &nodeLoadState{}
	row := nodeLoadRow{Kind: 0, Index: 0, Phase: 0, Tenant: 0, Outcome: "generator_queue_drop", QueueMS: 1}
	if e := s.record(row); e != nil {
		t.Fatal(e)
	}
	if s.record(row) == nil {
		t.Fatal("double counted planned arrival")
	}
	s.fail(nodeLoadRow{Stage: "raw_fresh"}, errors.New("private-first-diagnostic"))
	s.fail(nodeLoadRow{Stage: "scheduler"}, context.Canceled)
	if s.first.Error() != "private-first-diagnostic" || s.firstRow.Stage != "raw_fresh" {
		t.Fatal("companion cancellation erased cause")
	}
	out, e := s.summary()
	if e != nil {
		t.Fatal(e)
	}
	data, e := json.Marshal(out)
	if e != nil || strings.Contains(string(data), "private-first-diagnostic") {
		t.Fatal("private error escaped")
	}
	for _, group := range out["groups"].([]map[string]any) {
		if len(group["quantiles"].(map[string]nodeLoadQuantile)) != 0 {
			t.Fatal("drop gained a zero-latency success")
		}
	}
	bad := row
	bad.Index = 1
	bad.QueueMS = math.NaN()
	if s.record(bad) == nil {
		t.Fatal("NaN state admitted")
	}
}

func TestNodeLoadPrivateReplayInventoryRejectsCrossKindOrUnboundCapabilities(t *testing.T) {
	ref := sandbox.Ref{ID: strings.Repeat("b", 32), Generation: strings.Repeat("c", 32)}
	key := nodeLoadKey{Kind: 0, Tenant: 0, Key: strings.Repeat("a", 64), Ref: ref}
	if !nodeLoadKeyValid(key) {
		t.Fatal("valid raw capability rejected")
	}
	for _, change := range []func(*nodeLoadKey){func(k *nodeLoadKey) { k.Tenant = 2 }, func(k *nodeLoadKey) { k.Key = "short" }, func(k *nodeLoadKey) { k.Kind = 3 }, func(k *nodeLoadKey) { k.Session = strings.Repeat("a", 32) }, func(k *nodeLoadKey) { k.Revision = 1 }, func(k *nodeLoadKey) { k.Ref.Generation = "invalid" }} {
		bad := key
		change(&bad)
		if nodeLoadKeyValid(bad) {
			t.Fatal("unbound capability accepted")
		}
	}
	key.Kind = 1
	key.Session = strings.Repeat("d", 32)
	if !nodeLoadKeyValid(key) {
		t.Fatal("session create rejected")
	}
	key.Kind = 2
	if nodeLoadKeyValid(key) {
		t.Fatal("switch without revision")
	}
	key.Revision = 1
	if !nodeLoadKeyValid(key) {
		t.Fatal("switch rejected")
	}
	v := nodeLoadInventory{Version: 1, Keys: make([]nodeLoadKey, 108)}
	for i := range v.Keys {
		v.Keys[i] = key
	}
	if validateNodeLoadInventory(v) == nil {
		t.Fatal("duplicate private capabilities accepted")
	}
	if validateNodeLoadInventory(nodeLoadInventory{Version: 1}) == nil || validateNodeLoadInventory(nodeLoadInventory{Version: 2, Keys: v.Keys}) == nil {
		t.Fatal("partial/unknown inventory accepted")
	}
}

func TestNodeLoadGuestHeartbeatQuotesNumericValuesWithoutHostExecution(t *testing.T) {
	busy, progress := nodeLoadBusyCommand(), nodeLoadProgressCommand()
	for _, argv := range [][]string{busy, progress} {
		if len(argv) != 3 || argv[0] != "sh" || argv[1] != "-c" || strings.Contains(argv[2], `\"`) {
			t.Fatal("fixed guest command gained literal escaped quotes")
		}
	}
	if !strings.Contains(busy[2], `printf '%s\n' "$i"`) || !strings.Contains(progress[2], `[ "$next" -gt "$first" ]`) {
		t.Fatal("busy progress is not an advancing numeric observation")
	}
	// This test inspects strings only. Tenant commands are never run on L0.
}

func TestNodeLoadStateRejectsDuplicateAcceptedKeysAndUnprovenSuccess(t *testing.T) {
	s := &nodeLoadState{}
	key := nodeLoadKey{Kind: 0, Tenant: 0, Key: strings.Repeat("a", 64), Ref: sandbox.Ref{ID: strings.Repeat("b", 32), Generation: strings.Repeat("c", 32)}}
	if s.addKey(key) != nil || s.addKey(key) == nil || len(s.keys) != 1 {
		t.Fatal("duplicate accepted inventory capability")
	}
	row := nodeLoadRow{Kind: 0, Outcome: "completed", EmptyMS: 2, NamespaceMS: 3}
	if s.record(row) == nil {
		t.Fatal("invented completed row without API response")
	}
	row.APIObserved = true
	row.EmptyMS = 4
	if s.record(row) == nil {
		t.Fatal("namespace completion before kernel emptiness")
	}
	row.EmptyMS = 2
	if s.record(row) != nil {
		t.Fatal("ordered completed row rejected")
	}
	row.Kind, row.Phase, row.FullQuotaMS = 2, 4, 1
	if s.record(row) == nil {
		t.Fatal("tail quota completion before namespace")
	}
}

func TestNodeLoadResourceCoverageCannotBeReplacedByShortSmoke(t *testing.T) {
	samples := make([]nodeLoadResource, 241)
	for i := range samples {
		samples[i] = nodeLoadResource{ElapsedMS: float64(i) * 10000, DurationMS: 10, Allocated: 2, ControllerFDs: 10, NodeCurrent: 1, NodePeak: 2, ControlCurrent: 1, ControlPeak: 2}
	}
	samples[240].Allocated = 0
	if e := nodeLoadSamplesValid(samples); e != nil {
		t.Fatal(e)
	}
	if nodeLoadSamplesValid(samples[:3]) == nil {
		t.Fatal("three points masqueraded as sustained evidence")
	}
	for _, change := range []func([]nodeLoadResource){func(v []nodeLoadResource) { v[10].ElapsedMS = 100 }, func(v []nodeLoadResource) { v[10].DurationMS = math.NaN() }, func(v []nodeLoadResource) { v[10].NodeOOM = 1 }, func(v []nodeLoadResource) { v[10].ControlPeak = 4 << 30 }, func(v []nodeLoadResource) { v[240].ControllerFDs = 15 }, func(v []nodeLoadResource) { v[240].QuotaSpace = 4096 }, func(v []nodeLoadResource) { v[239].ElapsedMS = 2300000 }} {
		v := append([]nodeLoadResource(nil), samples...)
		change(v)
		if nodeLoadSamplesValid(v) == nil {
			t.Fatal("invalid/partial sustained series accepted")
		}
	}
}
