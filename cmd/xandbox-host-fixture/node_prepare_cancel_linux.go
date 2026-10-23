//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: original queued HTTP cancellation and ordinary independent
// reclamation while a different known partial workspace WRITE is held.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

type nodeCancelTraceState struct {
	Stages [3]int
	Held   int
}

func validateNodeCancelTrace(events []prepareTraceEvent) (nodeCancelTraceState, error) {
	var out nodeCancelTraceState
	roles := make(map[uint64]int)
	var gate uint64
	for _, ev := range events {
		if ev.g == 0 {
			return out, errors.New("zero goroutine identity")
		}
		role, known := roles[ev.g]
		if ev.name == "enter" {
			if known || len(roles) == 3 || ev.ax == 0 || (gate != 0 && gate != ev.ax) {
				return out, errors.New("duplicate/foreign cancel experiment entry")
			}
			role = len(roles)
			roles[ev.g] = role
			gate = ev.ax
			if role > 0 && out.Held != 1 {
				return out, errors.New("queued entry outside holder permit interval")
			}
		} else if !known {
			return out, errors.New("cancel transition without actual entry")
		}
		sequence := []string{"enter", "selected", "ok", "node_ok", "release", "released"}
		if role == 1 {
			sequence = []string{"enter", "selected", "cancel"}
		}
		stage := out.Stages[role]
		if stage >= len(sequence) || ev.name != sequence[stage] {
			return out, errors.New("missing/reordered/foreign cancel transition")
		}
		if ev.name == "selected" {
			if role == 1 {
				if ev.ax != 1 || out.Held != 1 {
					return out, errors.New("cancelled waiter consumed permit")
				}
			} else {
				if ev.ax != 0 || out.Held != 0 {
					return out, errors.New("overlapping acquired preparation permits")
				}
				if role == 2 && out.Stages[1] != 3 {
					return out, errors.New("survivor advanced before queued cancellation")
				}
				out.Held++
			}
		}
		if ev.name == "cancel" && ev.ax == 0 {
			return out, errors.New("cancel branch returned nil error")
		}
		if ev.name == "release" {
			if ev.ax != gate || out.Held != 1 || out.Stages[1] != 3 || out.Stages[2] < 1 {
				return out, errors.New("unexpected gate release before cancelled/waiting witnesses")
			}
			out.Held-- // Before receive, not an exact channel linearization time.
		}
		out.Stages[role]++
	}
	return out, nil
}

func normalizedNodeCancelTrace(events []prepareTraceEvent) []map[string]any {
	rows := normalizedPrepareTransitions(events)
	for i, ev := range events {
		if ev.name == "selected" {
			if ev.ax <= 1 {
				rows[i]["selected_case"] = ev.ax
			} else {
				rows[i]["selected_case_invalid"] = true
			}
		}
	}
	return rows
}
func (t *prepareTrace) nodeCancelState() (nodeCancelTraceState, error) {
	if e := t.daemon(); e != nil {
		return nodeCancelTraceState{}, e
	}
	raw, e := traceRead(prepareTraceInstance + "/trace")
	if e != nil {
		return nodeCancelTraceState{}, e
	}
	events, e := parsePrepareTrace(raw)
	if e != nil {
		return nodeCancelTraceState{}, e
	}
	return validateNodeCancelTrace(events)
}
func (t *prepareTrace) waitNodeCancel(ctx context.Context, want [3]int) error {
	return waitNode(ctx, func() (bool, error) { s, e := t.nodeCancelState(); return s.Stages == want, e })
}
func (t *prepareTrace) finishNodeCancel() (map[string]any, error) {
	events, e := t.collect("cancel")
	if e != nil {
		return nil, e
	}
	s, e := validateNodeCancelTrace(events)
	if e != nil {
		return nil, fmt.Errorf("%w; normalized=%v", e, normalizedNodeCancelTrace(events))
	}
	if len(events) != 15 || s.Stages != [3]int{6, 3, 6} || s.Held != 0 {
		return nil, fmt.Errorf("incomplete cancellation trace; normalized=%v", normalizedNodeCancelTrace(events))
	}
	return map[string]any{"exact_ordinary_elf_sha256": prepareTraceELFSHA, "instruction_entry_probes": 9, "event_count": 15, "completed_preparations": 2, "cancelled_waiters_without_token": 1, "all_eight_cpu_loss_counters_zero": true, "all_nine_probe_hits_equal_trace": true, "live_incarnation_inode_control_event_tgid_checked": true, "normalized_transitions": normalizedNodeCancelTrace(events), "exact_channel_linearization_or_slo_claim": false}, nil
}

// A bounded read-only scan of atomic version1 ledger files; never call the
// production FileStore.Load concurrently with its live writer or adopt owners.
func nodePrepareRecord(key string) (sandbox.Record, bool, error) {
	var zero sandbox.Record
	if e := requireNode(); e != nil {
		return zero, false, e
	}
	if !hashPattern.MatchString(key) {
		return zero, false, errors.New("fixed generated request key required")
	}
	sum := sha256.Sum256([]byte(key))
	hash := hex.EncodeToString(sum[:])
	entries, e := os.ReadDir("/srv/state/ledger")
	if e != nil {
		return zero, false, e
	}
	if len(entries) > 4096 {
		return zero, false, errors.New("bounded ledger scan exceeded")
	}
	var found *sandbox.Record
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".record-") {
			tmp := strings.TrimPrefix(name, ".record-")
			if tmp == "" || len(tmp) > 20 || strings.Trim(tmp, "0123456789") != "" {
				return zero, false, errors.New("unexpected live temp name")
			}
			if _, e = strconv.ParseUint(strings.TrimPrefix(name, ".record-"), 10, 64); e != nil {
				return zero, false, e
			}
			continue
		}
		if len(name) != 37 || !hex32Pattern(name[:32]) || name[32:] != ".json" || !entry.Type().IsRegular() {
			return zero, false, errors.New("unexpected live ledger entry")
		}
		b, err := privatefile.Read(filepath.Join("/srv/state/ledger", name), sandbox.MaxLedgerRecordBytes)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return zero, false, err
		}
		var envelope struct {
			Version int             `json:"version"`
			Record  *sandbox.Record `json:"record"`
		}
		if err = strictjson.Decode(b, &envelope); err != nil {
			return zero, false, err
		}
		if envelope.Version != 1 || envelope.Record == nil || !switchRefValid(envelope.Record.Ref) || envelope.Record.ID != name[:32] || envelope.Record.Backend != "firecracker" || envelope.Record.TenantID == "" {
			return zero, false, errors.New("fixed live ledger identity invalid")
		}
		if envelope.Record.CreateKeyHash == hash {
			if found != nil {
				return zero, false, errors.New("ambiguous original create key")
			}
			found = envelope.Record
		}
	}
	if found == nil {
		return zero, false, nil
	}
	return *found, true, nil
}

func nodePrepareCreating(ctx context.Context, key string) (sandbox.Record, error) {
	var out sandbox.Record
	e := waitNode(ctx, func() (bool, error) {
		r, ok, e := nodePrepareRecord(key)
		if e != nil {
			return false, e
		}
		if !ok {
			return false, nil
		}
		if r.State != sandbox.Creating {
			return false, errors.New("original queued record no longer Creating")
		}
		out = r
		return true, nil
	})
	if e == nil {
		e = budgetAbsent(out.Ref)
	}
	return out, e
}
func nodePrepareDurableDestroyed(key string, ref sandbox.Ref) error {
	r, ok, e := nodePrepareRecord(key)
	if e != nil {
		return e
	}
	if !ok || r.Ref != ref || r.State != sandbox.Destroyed || r.DestroyedAt.IsZero() {
		return errors.New("actual durable destroyed record required")
	}
	return budgetAbsent(ref)
}

func (n *node) nodePrepareCancel(ctx context.Context) (result map[string]any, err error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.nodeSnapshot || n.process == nil || !hashPattern.MatchString(n.switchTemplate) {
		return nil, errors.New("fresh schema3 snapshot node required")
	}
	observedActive := true
	o, e := n.startNodePrepareObserved(ctx)
	if e != nil {
		return nil, e
	}
	defer func() {
		if observedActive && n.process != nil && err != nil {
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = errors.Join(err, n.stopNodePrepareObserved(c, o, true))
		}
	}()
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	defer api.close()
	keeper, keeperKey, keeperBoot, e := n.nodeSnapshotGuest(ctx, api)
	if e != nil {
		return nil, e
	}
	t, e := startPrepareTrace(n.process.Process.Pid)
	if e != nil {
		return nil, e
	}
	defer func() {
		if err != nil && t != nil {
			if raw, e := traceRead(prepareTraceInstance + "/trace"); e == nil {
				if events, e := parsePrepareTrace(raw); e == nil {
					fmt.Fprintln(os.Stderr, "private normalized cancel transitions:", normalizedNodeCancelTrace(events))
				}
			}
		}
		if t != nil {
			err = errors.Join(err, t.close())
		}
	}()
	type reply struct {
		r sandbox.Record
		e error
	}
	holderReplies, queuedReplies, cancelledReplies := make(chan reply, 1), make(chan reply, 1), make(chan reply, 1)
	requests, cancelRequests := context.WithCancel(ctx)
	defer cancelRequests()
	holderKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	cancelKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	queuedKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	o.arm()
	holderIssued := time.Now()
	go func() { r, e := api.create(requests, holderKey); holderReplies <- reply{r, e} }()
	var boundary copyBoundary
	select {
	case boundary = <-o.held:
	case <-time.After(10 * time.Second):
		return nil, errors.New("actual held16MiB workspace boundary not reached")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	critical, cancelCritical := context.WithTimeout(ctx, 18*time.Second)
	defer cancelCritical()
	if e = t.waitNodeCancel(critical, [3]int{4, 0, 0}); e != nil {
		return nil, e
	}
	if e = o.heldValid(); e != nil {
		return nil, e
	}
	cancelledContext, cancelOriginal := context.WithCancel(requests)
	defer cancelOriginal()
	go func() { r, e := api.create(cancelledContext, cancelKey); cancelledReplies <- reply{r, e} }()
	if e = t.waitNodeCancel(critical, [3]int{4, 1, 0}); e != nil {
		return nil, e
	}
	cancelled, e := nodePrepareCreating(critical, cancelKey)
	if e != nil {
		return nil, e
	}
	queuedIssued := time.Now()
	go func() { r, e := api.create(requests, queuedKey); queuedReplies <- reply{r, e} }()
	if e = t.waitNodeCancel(critical, [3]int{4, 1, 1}); e != nil {
		return nil, e
	}
	queued, e := nodePrepareCreating(critical, queuedKey)
	if e != nil {
		return nil, e
	}
	if cancelled.Ref == queued.Ref || cancelled.Ref == boundary.Ref || queued.Ref == boundary.Ref || keeper.Ref == boundary.Ref {
		return nil, errors.New("independent generation identities required")
	}
	g, e := switchGauges(critical)
	if e != nil {
		return nil, e
	}
	if g["allocated"] != 4 {
		return nil, errors.New("keeper holder two queued must consume all four frontend slots")
	}
	fifth, e := randomKey()
	if e != nil {
		return nil, e
	}
	if e = api.call(critical, "POST", "/v1/sandboxes", fifth, switchGuestSpec(), nil, 503); e != nil {
		return nil, e
	}
	if e = budgetAbsent(cancelled.Ref); e != nil {
		return nil, e
	}
	if e = budgetAbsent(queued.Ref); e != nil {
		return nil, e
	}
	cancelOriginal()
	select {
	case c := <-cancelledReplies:
		if !errors.Is(c.e, context.Canceled) {
			return nil, errors.New("original HTTP client did not observe its own explicit cancellation")
		}
	case <-critical.Done():
		return nil, critical.Err()
	}
	if e = t.waitNodeCancel(critical, [3]int{4, 3, 1}); e != nil {
		return nil, e
	}
	if e = budgetDestroyed(critical, api, cancelled.Ref); e != nil {
		return nil, e
	}
	if e = nodePrepareDurableDestroyed(cancelKey, cancelled.Ref); e != nil {
		return nil, e
	}
	if e = api.call(critical, "POST", "/v1/sandboxes", cancelKey, switchGuestSpec(), nil, 410); e != nil {
		return nil, e
	}
	if e = waitNode(critical, func() (bool, error) {
		g, e := switchGauges(critical)
		return g["allocated"] == 3 && g["stop_queued"] == 0 && g["stop_running"] == 0 && g["cleanup_queued"] == 0 && g["cleanup_running"] == 0, e
	}); e != nil {
		return nil, e
	}
	if e = budgetAbsent(queued.Ref); e != nil {
		return nil, e
	}
	if e = o.heldValid(); e != nil {
		return nil, e
	}
	beforeOther, _ := o.counts()
	ko, _, e := nodeSnapshotOwner(keeper.Ref)
	if e != nil {
		return nil, e
	}
	keeperDeleteIssued := time.Now()
	if e = api.call(critical, "DELETE", switchPath(keeper.Ref), "", generationBody(keeper.Ref), nil, 202); e != nil {
		return nil, e
	}
	if e = waitNode(critical, func() (bool, error) {
		empty, e := nodePrepareGroupEmpty(keeper.Ref)
		if os.IsNotExist(e) {
			return true, nil
		} // exact known domain removal also requires kernel-empty.
		return empty, e
	}); e != nil {
		return nil, e
	}
	keeperStopObserved := time.Since(keeperDeleteIssued)
	if e = budgetDestroyed(critical, api, keeper.Ref); e != nil {
		return nil, e
	}
	qr, e := driverQuotaRead(ko.ProjectID)
	if e != nil {
		return nil, e
	}
	if !quotaEmpty(qr) {
		return nil, errors.New("keeper project not cleared")
	}
	if e = nodePrepareDurableDestroyed(keeperKey, keeper.Ref); e != nil {
		return nil, e
	}
	keeperReclaimObserved := time.Since(keeperDeleteIssued)
	if e = o.heldValid(); e != nil {
		return nil, e
	}
	if e = t.waitNodeCancel(critical, [3]int{4, 3, 1}); e != nil {
		return nil, e
	}
	if e = budgetAbsent(queued.Ref); e != nil {
		return nil, e
	}
	afterOther, releases := o.counts()
	if afterOther <= beforeOther || releases != 0 {
		return nil, errors.New("keeper cleanup did not coexist with other CONTINUE replies and an unreleased hold")
	}
	close(o.release)
	var h, q reply
	select {
	case h = <-holderReplies:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	holderReadyObserved := time.Since(holderIssued)
	if h.e != nil {
		return nil, h.e
	}
	select {
	case q = <-queuedReplies:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	queuedReadyObserved := time.Since(queuedIssued)
	if q.e != nil {
		return nil, q.e
	}
	if h.r.Ref != boundary.Ref || q.r.Ref != queued.Ref {
		return nil, errors.New("surviving original request identities changed")
	}
	hBoot, e := n.nodeSnapshotVerifyGuest(ctx, api, h.r)
	if e != nil {
		return nil, e
	}
	qBoot, e := n.nodeSnapshotVerifyGuest(ctx, api, q.r)
	if e != nil {
		return nil, e
	}
	if hBoot == qBoot || hBoot == keeperBoot || qBoot == keeperBoot {
		return nil, errors.New("fresh actual guest boots not independent")
	}
	if e = nodeSnapshotPins(ctx, n.switchTemplate, 2); e != nil {
		return nil, e
	}
	trace, e := t.finishNodeCancel()
	if e != nil {
		return nil, e
	}
	if e = t.close(); e != nil {
		return nil, e
	}
	t = nil
	if e = nodeSnapshotDelete(ctx, api, h.r.Ref); e != nil {
		return nil, e
	}
	if e = nodeSnapshotDelete(ctx, api, q.r.Ref); e != nil {
		return nil, e
	}
	for _, k := range []struct {
		key string
		ref sandbox.Ref
	}{{holderKey, h.r.Ref}, {queuedKey, q.r.Ref}} {
		if e = nodePrepareDurableDestroyed(k.key, k.ref); e != nil {
			return nil, e
		}
	}
	if e = nodeSnapshotPins(ctx, n.switchTemplate, 0); e != nil {
		return nil, e
	}
	for project := driverProjectFirst; project < driverProjectFirst+4; project++ {
		qr, e := driverQuotaRead(project)
		if e != nil {
			return nil, e
		}
		if !quotaEmpty(qr) {
			return nil, errors.New("project quota retained after cancellation case")
		}
	}
	_, _, e = o.snapshot()
	if e != nil {
		return nil, e
	}
	other, releases := o.counts()
	if releases != 1 || other == 0 {
		return nil, errors.New("exactly one held CONTINUE response required")
	}
	if e = waitNode(ctx, func() (bool, error) {
		g, e := switchGauges(ctx)
		return g["allocated"] == 0 && g["stop_queued"] == 0 && g["stop_running"] == 0 && g["cleanup_queued"] == 0 && g["cleanup_running"] == 0, e
	}); e != nil {
		return nil, e
	}
	if e = n.stopNodePrepareObserved(ctx, o, false); e != nil {
		return nil, e
	}
	observedActive = false
	o.holdMu.Lock()
	holdObserved := o.releasedAt.Sub(o.heldAt)
	o.holdMu.Unlock()
	if holdObserved <= 0 || holdObserved >= nodePrepareHoldMax {
		return nil, errors.New("actual held duration outside fixed bound")
	}
	return map[string]any{"real_nested_kvm": true, "keeper_delete_to_execution_domain_empty_observed_ms": float64(keeperStopObserved) / float64(time.Millisecond), "keeper_delete_to_full_reclaim_observed_ms": float64(keeperReclaimObserved) / float64(time.Millisecond), "held_write_to_continue_reply_observed_ms": float64(holdObserved) / float64(time.Millisecond), "holder_request_to_ready_observed_ms": float64(holderReadyObserved) / float64(time.Millisecond), "survivor_request_to_ready_observed_ms": float64(queuedReadyObserved) / float64(time.Millisecond), "schema3_exact_prepare_workers_one": true, "keeper_holder_and_two_queued_frontend_allocated_four_fifth503": true, "two_queued_actual_gate_entries_no_backend_owner_jail_group": true, "original_queued_http_cancelled_without_token": true, "cancelled_key410_durable_destroyed_pools_baseline_no_backend_resources": true, "keeper_stop_cleanup_durable_destroyed_project_zero_while_write_still_held": true, "other_continue_replies_during_keeper_cleanup": afterOther - beforeOther, "held_workspace_prefix_bytes": copyPrefix, "hold_deadline_ms": nodePrepareHoldMax.Milliseconds(), "prepare_timeout_ms_unchanged": 30000, "http_budget_ms_unchanged": 40000, "held_continue_response_count": releases, "continue_is_not_write_completion": true, "survivor_original_requests_ready_real_guests_independent_boots_clean_workspace": true, "all_four_projects_zero_pins_zero_pools_idle": true, "observed_daemon_reaped_and_ordinary_daemon_restarted": true, "trace": trace, "filesystem_D_or_physical_media_fault_claim": false, "exact_copy_stage_timing_scheduler_fairness_or_slo_claim": false}, nil
}
