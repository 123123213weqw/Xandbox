//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: actual initial session Store.Sync held before Core reservation,
// a separately ACKed operator drain, then the accepted one-shot ticket resumes.
import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

const sessionTicketReceipt = "/srv/fixture/session-ticket-receipt.json"

type sessionTicketSaved struct {
	Version                                       int
	L1Boot, Config                                string
	Before, Committed                             nodecontrol.State
	Raw                                           sandbox.Ref
	Existing, Accepted                            session.Result
	RawKey, ExistingKey, AcceptedKey, RejectedKey string
	RawBoot, ExistingBoot, AcceptedBoot           string
}

func sessionTicketStatus(ctx context.Context, c *nodecontrol.Client, committed nodecontrol.State, active, pending, records int) error {
	v, e := operatorStoreShortStatus(ctx, c)
	if e != nil {
		return e
	}
	s, r := v.Control, v.ResourceObservation
	if s.Phase != "ready" || s.Committed != committed || s.AdmissionOpen != (committed.Mode == nodecontrol.ModeOpen) || s.PendingSessionReservations != pending || r.Active != active || r.Records != records || r.StopQueued != 0 || r.StopRunning != 0 || r.CleanupQueued != 0 || r.CleanupRunning != 0 {
		return fmt.Errorf("ticket baseline phase=%s mode=%s revision=%d pending=%d active=%d records=%d pools=%d/%d/%d/%d", s.Phase, s.Committed.Mode, s.Committed.Revision, s.PendingSessionReservations, r.Active, r.Records, r.StopQueued, r.StopRunning, r.CleanupQueued, r.CleanupRunning)
	}
	return nil
}
func sessionTicketBackend(refs []sandbox.Ref) error {
	if e := requireNode(); e != nil {
		return e
	}
	wantDirs := []string{}
	wantOwners := []string{"config.json"}
	var slots [4]bool
	for _, ref := range refs {
		if !switchRefValid(ref) {
			return errors.New("invalid ticket baseline ref")
		}
		name := ref.ID + ref.Generation
		wantDirs = append(wantDirs, name)
		wantOwners = append(wantOwners, name+".json")
		owner, _, e := budgetOwner(ref)
		if e != nil {
			return e
		}
		slot := owner.ProjectID - driverProjectFirst
		if slot >= 4 || slots[slot] {
			return errors.New("ticket baseline quota slot collision")
		}
		slots[slot] = true
	}
	sort.Strings(wantDirs)
	sort.Strings(wantOwners)
	owners, e := operatorFileNames("/srv/state/firecracker")
	if e != nil || strings.Join(owners, ",") != strings.Join(wantOwners, ",") {
		return errors.New("ticket acquired unexpected backend owner")
	}
	for _, dir := range []string{nodeBudgetInstances, "/srv/r/j/firecracker"} {
		entries, e := os.ReadDir(dir)
		if e != nil {
			return e
		}
		names := []string{}
		for _, entry := range entries {
			if entry.IsDir() {
				names = append(names, entry.Name())
			} else if dir == nodeBudgetInstances {
				continue
			} else {
				return errors.New("unexpected ticket jail entry")
			}
		}
		sort.Strings(names)
		if strings.Join(names, ",") != strings.Join(wantDirs, ",") {
			return errors.New("ticket acquired unexpected cgroup or jail")
		}
	}
	for slot, used := range slots {
		q, e := driverQuotaRead(driverProjectFirst + uint32(slot))
		if e != nil {
			return e
		}
		if used {
			if q.BHard != 192<<10 || q.IHard != 128 || quotaEmpty(q) {
				return errors.New("existing ticket baseline quota drift")
			}
		} else if !quotaEmpty(q) {
			return errors.New("pre-Core ticket reserved a quota slot")
		}
	}
	return nil
}
func sessionTicketHeldInventory(o *operatorStoreObserver, ledger []string, oldID string, oldJournal []byte) error {
	if e := o.heldValid(); e != nil {
		return e
	}
	id, temp := o.sessionTicketIdentity()
	if !hex32Pattern(id) || !sessionTicketTempPattern.MatchString(temp) {
		return errors.New("initial session target not identified")
	}
	names, e := operatorFileNames("/srv/state/ledger")
	if e != nil || strings.Join(names, ",") != strings.Join(ledger, ",") {
		return errors.New("pre-Core ticket changed Core record names")
	}
	current, e := operatorSessionBytes(oldID)
	if e != nil || !bytes.Equal(current, oldJournal) {
		return errors.New("drain changed existing session history")
	}
	entries, e := os.ReadDir("/srv/state/sessions")
	if e != nil {
		return e
	}
	if len(entries) != 2 {
		return errors.New("drained admission added session metadata")
	}
	for _, entry := range entries {
		if entry.IsDir() || (entry.Name() != oldID+".json" && entry.Name() != temp) {
			return errors.New("unexpected initial ticket journal name")
		}
	}
	if _, e = os.Lstat("/srv/state/sessions/" + id + ".json"); !os.IsNotExist(e) {
		return errors.New("initial session renamed while Sync held")
	}
	return nil
}
func sessionTicketRecordHash(key string, data []byte) error {
	var env struct {
		Version int            `json:"version"`
		Record  session.Record `json:"record"`
	}
	if e := strictjson.Decode(data, &env); e != nil {
		return e
	}
	kh, sh, e := sessionTicketHashes(key)
	if e != nil {
		return e
	}
	if env.Version != 1 || env.Record.TenantID != "nested-fixture" || env.Record.CreateKeyHash != kh || env.Record.CreateSpecHash != sh {
		return errors.New("test request hashing differs from ordinary session store")
	}
	return nil
}
func (n *node) nodeSessionTicketCheckpoint(ctx context.Context) (out map[string]any, err error) {
	if e := n.operatorProfile(); e != nil {
		return nil, e
	}
	if e := n.start(ctx); e != nil {
		return nil, e
	}
	c, e := nodecontrol.NewClient("/srv/state")
	if e != nil {
		return nil, e
	}
	initial, e := c.Status(ctx)
	c.Close()
	if e != nil || !initial.Control.AdmissionOpen || initial.Control.Committed.Revision != 1 || initial.ResourceObservation.Records != 0 {
		return nil, errors.New("fresh ordinary initial admission authority required")
	}
	if e = n.stopOperatorDaemon(ctx); e != nil {
		return nil, e
	}
	observer, e := n.startOperatorStoreObserved(ctx)
	if e != nil {
		return nil, e
	}
	defer func() {
		if n.process != nil {
			n.process.Process.Kill()
			select {
			case <-n.exited:
				n.process = nil
			case <-time.After(2 * time.Second):
			}
		}
		err = errors.Join(err, observer.close())
	}()
	c, e = nodecontrol.NewClient("/srv/state")
	if e != nil {
		return nil, e
	}
	defer c.Close()
	before := initial.Control.Committed
	if e = sessionTicketStatus(ctx, c, before, 0, 0, 0); e != nil {
		return nil, e
	}
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	defer api.close()
	rawKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	raw, e := api.create(ctx, rawKey)
	if e != nil {
		return nil, e
	}
	rawBoot, e := operatorGuest(ctx, n, api, raw.Ref, "raw", nil)
	if e != nil {
		return nil, e
	}
	existingKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	bound, e := api.openSession(ctx, existingKey)
	if e != nil {
		return nil, e
	}
	existingBoot, e := operatorGuest(ctx, n, api, bound.Current, "session", &bound)
	if e != nil {
		return nil, e
	}
	if rawBoot == existingBoot {
		return nil, errors.New("independent existing guests required")
	}
	rawOwner, _, e := budgetOwner(raw.Ref)
	if e != nil {
		return nil, e
	}
	busy, e := n.submit(ctx, raw.Ref, []string{"sh", "-c", "i=0; while :; do i=$((i+1)); printf '%s\\n' \"$i\" > ticket-progress.tmp; mv ticket-progress.tmp ticket-progress; sleep 0.05; done"})
	if e != nil {
		return nil, e
	}
	progress := func() (int, error) {
		v, e := api.executeVM(ctx, raw.Ref, []string{"sh", "-c", "cat ticket-progress 2>/dev/null || echo 0"})
		if e != nil {
			return 0, e
		}
		return strconv.Atoi(strings.TrimSpace(v.Stdout))
	}
	first := 0
	if e = waitNode(ctx, func() (bool, error) { var e error; first, e = progress(); return first > 0, e }); e != nil {
		return nil, e
	}
	ledger, e := operatorFileNames("/srv/state/ledger")
	if e != nil || len(ledger) != 2 {
		return nil, errors.New("two existing Core records required")
	}
	journal, e := operatorSessionBytes(bound.ID)
	if e != nil {
		return nil, e
	}
	if e = sessionTicketRecordHash(existingKey, journal); e != nil {
		return nil, e
	}
	if e = sessionTicketStatus(ctx, c, before, 2, 0, 2); e != nil {
		return nil, e
	}
	acceptedKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	if e = observer.armSessionTicket(acceptedKey, bound.ID); e != nil {
		return nil, e
	}
	requestCtx, cancelRequest := context.WithTimeout(ctx, 40*time.Second)
	defer cancelRequest()
	type reply struct {
		Result session.Result
		Err    error
	}
	finished := make(chan reply, 1)
	requestIssued := time.Now()
	go func() { r, e := api.openSession(requestCtx, acceptedKey); finished <- reply{r, e} }()
	select {
	case <-observer.held:
	case <-observer.done:
		return nil, errors.Join(errors.New("ticket observer ended before target"), observer.snapshot().Err)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if e = sessionTicketHeldInventory(observer, ledger, bound.ID, journal); e != nil {
		return nil, e
	}
	if e = sessionTicketStatus(ctx, c, before, 2, 1, 2); e != nil {
		return nil, e
	}
	if e = sessionTicketBackend([]sandbox.Ref{raw.Ref, bound.Current}); e != nil {
		return nil, e
	}
	command, e := operatorCommand(before)
	if e != nil {
		return nil, e
	}
	drained, e := c.Change(ctx, nodecontrol.ModeDrained, command)
	if e != nil {
		return nil, e
	}
	next := nodecontrol.State{Version: 1, Epoch: before.Epoch, Revision: 2, Mode: nodecontrol.ModeDrained, LastRequestID: command.RequestID, LastExpectedRevision: 1}
	if drained.Control.Committed != next || drained.Control.AdmissionOpen || drained.Control.PendingSessionReservations != 1 {
		return nil, errors.New("drain ACK did not coexist with accepted pre-Core ticket")
	}
	if disk, e := operatorState(); e != nil || disk != next {
		return nil, errors.New("actual drain disk commit missing while session held")
	}
	if e = sessionTicketStatus(ctx, c, next, 2, 1, 2); e != nil {
		return nil, e
	}
	rejectedKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	rejectedSession, e := randomKey()
	if e != nil {
		return nil, e
	}
	rejectedSwitch, e := randomKey()
	if e != nil {
		return nil, e
	}
	for _, a := range []struct {
		path, key string
		body      any
	}{{"/v1/sandboxes", rejectedKey, nodeSpec()}, {"/v1/sessions", rejectedSession, nodeSpec()}, {"/v1/sessions/" + bound.ID + "/switch", rejectedSwitch, session.SwitchRequest{ExpectedRevision: bound.Revision, Create: nodeSpec()}}} {
		if e = operatorDenied(ctx, api, a.path, a.key, a.body); e != nil {
			return nil, e
		}
	}
	if e = sessionTicketHeldInventory(observer, ledger, bound.ID, journal); e != nil {
		return nil, e
	}
	if e = sessionTicketBackend([]sandbox.Ref{raw.Ref, bound.Current}); e != nil {
		return nil, e
	}
	if e = waitNode(ctx, func() (bool, error) { v, e := progress(); return v > first, e }); e != nil {
		return nil, e
	}
	job, e := n.job(ctx, raw.Ref, busy)
	if e != nil || job.Status != "RUNNING" {
		return nil, errors.New("old raw progress stopped behind accepted session Sync")
	}
	value, e := api.sessionExec(ctx, bound, []string{"cat", "operator-marker"})
	if e != nil || value.Stdout != "session" {
		return nil, errors.New("old session exec stalled behind accepted ticket")
	}
	if e = api.call(ctx, "GET", "/readyz", "", nil, nil, 503); e != nil {
		return nil, e
	}
	began := time.Now()
	if e = api.call(ctx, "DELETE", switchPath(raw.Ref), "", generationBody(raw.Ref), nil, 202); e != nil {
		return nil, e
	}
	if e = waitNode(ctx, func() (bool, error) {
		empty, e := nodePrepareGroupEmpty(raw.Ref)
		if os.IsNotExist(e) {
			return true, nil
		}
		return empty, e
	}); e != nil {
		return nil, e
	}
	stopMS := switchMS(began)
	if e = budgetDestroyed(ctx, api, raw.Ref); e != nil {
		return nil, e
	}
	q, e := driverQuotaRead(rawOwner.ProjectID)
	if e != nil || !quotaEmpty(q) {
		return nil, errors.New("old raw quota not zero while ticket Sync held")
	}
	if e = nodePrepareDurableDestroyed(rawKey, raw.Ref); e != nil {
		return nil, e
	}
	reclaimMS := switchMS(began)
	if e = waitNode(ctx, func() (bool, error) { e := sessionTicketStatus(ctx, c, next, 1, 1, 2); return e == nil, nil }); e != nil {
		return nil, e
	}
	if e = sessionTicketHeldInventory(observer, ledger, bound.ID, journal); e != nil {
		return nil, e
	}
	if e = sessionTicketBackend([]sandbox.Ref{bound.Current}); e != nil {
		return nil, e
	}
	select {
	case <-finished:
		return nil, errors.New("held original session HTTP already completed")
	default:
	}
	if requestCtx.Err() != nil {
		return nil, errors.New("original accepted request expired or was cancelled")
	}
	snapshot := observer.snapshot()
	if snapshot.FileEntries != 1 || snapshot.OtherWhileHeld <= 0 || snapshot.Injected != 0 || snapshot.TicketContinued != 0 {
		return nil, errors.New("initial ticket/other FSYNC witness incomplete")
	}
	observer.ticketContinue <- struct{}{}
	var accepted reply
	select {
	case accepted = <-finished:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if accepted.Err != nil {
		return nil, accepted.Err
	}
	readyMS := switchMS(requestIssued)
	if e = waitNode(ctx, func() (bool, error) { s := observer.snapshot(); return s.TicketContinued == 1, s.Err }); e != nil {
		return nil, e
	}
	ticketID, _ := observer.sessionTicketIdentity()
	b := accepted.Result
	if b.ID != ticketID || b.ID == bound.ID || b.Current == bound.Current || b.Current == raw.Ref || b.Revision != 1 || b.Previous != (sandbox.Ref{}) {
		return nil, errors.New("accepted original ticket bound wrong or reused candidate")
	}
	acceptedBoot, e := operatorGuest(ctx, n, api, b.Current, "switched", &b)
	if e != nil {
		return nil, e
	}
	if acceptedBoot == rawBoot || acceptedBoot == existingBoot {
		return nil, errors.New("accepted ticket guest boot reused")
	}
	if e = operatorIdle(ctx, c, 2, 3); e != nil {
		return nil, e
	}
	if e = sessionTicketStatus(ctx, c, next, 2, 0, 3); e != nil {
		return nil, e
	}
	replay, e := api.openSession(ctx, acceptedKey)
	if e != nil || replay.ID != b.ID || replay.Revision != b.Revision || replay.Current != b.Current {
		return nil, errors.New("accepted session replay lost or duplicated ticket")
	}
	if e = sessionTicketStatus(ctx, c, next, 2, 0, 3); e != nil {
		return nil, e
	}
	if e = sessionTicketBackend([]sandbox.Ref{bound.Current, b.Current}); e != nil {
		return nil, e
	}
	if e = operatorDenied(ctx, api, "/v1/sandboxes", rejectedKey, nodeSpec()); e != nil {
		return nil, e
	}
	for _, binding := range []session.Result{bound, b} {
		if e = api.revoke(ctx, binding); e != nil {
			return nil, e
		}
		if e = budgetDestroyed(ctx, api, binding.Current); e != nil {
			return nil, e
		}
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	if e = operatorIdle(ctx, c, 0, 3); e != nil {
		return nil, e
	}
	if e = n.stopOperatorDaemon(ctx); e != nil {
		return nil, e
	}
	if e = observer.close(); e != nil {
		return nil, e
	}
	snapshot = observer.snapshot()
	if snapshot.FileEntries != 1 || snapshot.TicketContinued != 1 || snapshot.Injected != 0 {
		return nil, errors.New("ticket Sync had more than one target reply")
	}
	saved := sessionTicketSaved{Version: 1, L1Boot: n.boot, Before: before, Committed: next, Raw: raw.Ref, Existing: bound, Accepted: b, RawKey: rawKey, ExistingKey: existingKey, AcceptedKey: acceptedKey, RejectedKey: rejectedKey, RawBoot: rawBoot, ExistingBoot: existingBoot, AcceptedBoot: acceptedBoot}
	saved.Config, e = fileHash("/srv/config/backend.json")
	if e != nil {
		return nil, e
	}
	if e = privateWrite(sessionTicketReceipt, saved); e != nil {
		return nil, e
	}
	return map[string]any{"real_nested_kvm": true, "exact_ordinary_elf_incarnation_tgid_control_and_session_fsync_inode_checked": true, "complete_initial_creating_zero_target_payload_before_core": true, "one_pending_ticket_existing_two_no_new_core_backend_or_quota": true, "durable_drain_ack_while_initial_session_sync_held": true, "new_raw_session_switch503_no_new_record_or_history": true, "old_raw_progress_and_existing_session_exec_continue": true, "old_raw_stop_private_destroy_quota0_while_ticket_held": true, "original_accepted_request_kept_alive_not_cancelled": true, "single_continue_not_synthetic_success_or_sync_completion": true, "accepted_ticket_creates_real_session_after_gate_closed": true, "one_shot_ticket_pending0_replay_no_new_core": true, "three_distinct_real_guest_boots_clean_workspaces": true, "all_four_projects_zero_pools_idle_daemon_reaped_before_cold": true, "acknowledged_state_saved_without_fixture_metadata_rewrite": true, "initial_file_sync_entries": snapshot.FileEntries, "target_continue_replies": snapshot.TicketContinued, "target_errno_replies": snapshot.Injected, "other_fsync_continue_replies_while_held": snapshot.OtherWhileHeld, "pending_before_continue": 1, "existing_active_before_continue": 2, "core_records_before_continue": 2, "pending_after_continue": 0, "core_records_after_continue": 3, "acknowledged_drain_revision": 2, "hold_deadline_ms": int(operatorStoreHoldMax / time.Millisecond), "original_http_budget_ms": 40000, "prepare_timeout_ms_unchanged": 30000, "execution_domain_stop_observed_ms": stopMS, "private_destroy_quota_zero_observed_ms": reclaimMS, "original_session_request_to_ready_observed_ms": readyMS, "filesystem_d_or_physical_media_claim": false, "production_slo_claim": false}, nil
}
func validateSessionTicketSaved(s sessionTicketSaved, boot string) error {
	if s.Version != 1 || !switchUUID(s.L1Boot) || s.L1Boot == boot || !hashPattern.MatchString(s.Config) || !switchRefValid(s.Raw) || !hex32Pattern(s.Existing.ID) || !hex32Pattern(s.Accepted.ID) || s.Existing.ID == s.Accepted.ID || s.Existing.Revision != 1 || s.Accepted.Revision != 1 || !switchRefValid(s.Existing.Current) || !switchRefValid(s.Accepted.Current) || s.Raw == s.Existing.Current || s.Raw == s.Accepted.Current || s.Existing.Current == s.Accepted.Current || s.Existing.Previous != (sandbox.Ref{}) || s.Accepted.Previous != (sandbox.Ref{}) {
		return errors.New("ticket cold identity invalid")
	}
	seen := map[string]bool{}
	for _, key := range []string{s.RawKey, s.ExistingKey, s.AcceptedKey, s.RejectedKey} {
		if !hashPattern.MatchString(key) || seen[key] {
			return errors.New("ticket private keys invalid/colliding")
		}
		seen[key] = true
	}
	seen = map[string]bool{}
	for _, b := range []string{s.RawBoot, s.ExistingBoot, s.AcceptedBoot} {
		if !switchUUID(b) || seen[b] {
			return errors.New("ticket guest boots invalid/colliding")
		}
		seen[b] = true
	}
	before, next := s.Before, s.Committed
	if before.Version != 1 || before.Mode != nodecontrol.ModeOpen || before.Revision != 1 || !hex32Pattern(before.Epoch) || before.LastRequestID != "" || before.LastExpectedRevision != 0 || next.Version != 1 || next.Mode != nodecontrol.ModeDrained || next.Revision != 2 || next.Epoch != before.Epoch || !hex32Pattern(next.LastRequestID) || next.LastExpectedRevision != 1 {
		return errors.New("ticket ACK authority not exact open1/drained2")
	}
	return nil
}
func (n *node) nodeSessionTicketRecover(ctx context.Context) (map[string]any, error) {
	if e := n.operatorProfile(); e != nil {
		return nil, e
	}
	data, e := privatefile.Read(sessionTicketReceipt, 32768)
	if e != nil {
		return nil, e
	}
	var saved sessionTicketSaved
	if e = strictjson.Decode(data, &saved); e != nil {
		return nil, e
	}
	if e = validateSessionTicketSaved(saved, n.boot); e != nil {
		return nil, e
	}
	config, e := fileHash("/srv/config/backend.json")
	if e != nil || config != saved.Config {
		return nil, errors.New("ticket original node policy changed")
	}
	disk, e := operatorState()
	if e != nil || disk != saved.Committed {
		return nil, errors.New("ACK drain lost before ordinary cold startup")
	}
	refs := []sandbox.Ref{saved.Raw, saved.Existing.Current, saved.Accepted.Current}
	for _, ref := range refs {
		if e = budgetAbsent(ref); e != nil {
			return nil, e
		}
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	if e = n.start(ctx); e != nil {
		return nil, e
	}
	c, e := nodecontrol.NewClient("/srv/state")
	if e != nil {
		return nil, e
	}
	defer c.Close()
	if e = operatorIdle(ctx, c, 0, 3); e != nil {
		return nil, e
	}
	if e = sessionTicketStatus(ctx, c, saved.Committed, 0, 0, 3); e != nil {
		return nil, e
	}
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	defer api.close()
	for _, ref := range refs {
		if e = budgetDestroyed(ctx, api, ref); e != nil {
			return nil, e
		}
	}
	if e = api.call(ctx, "POST", "/v1/sandboxes", saved.RawKey, nodeSpec(), nil, 410); e != nil {
		return nil, e
	}
	for _, key := range []string{saved.ExistingKey, saved.AcceptedKey} {
		if e = api.call(ctx, "POST", "/v1/sessions", key, nodeSpec(), nil, 410); e != nil {
			return nil, e
		}
	}
	for _, b := range []session.Result{saved.Existing, saved.Accepted} {
		var route struct {
			Has   bool   `json:"has_binding"`
			Phase string `json:"phase"`
		}
		if e = api.call(ctx, "GET", "/v1/sessions/"+b.ID, "", nil, &route, 200); e != nil || route.Has || route.Phase != "CLOSED" {
			return nil, errors.New("cold ticket session route resurrected")
		}
	}
	if e = operatorDenied(ctx, api, "/v1/sandboxes", saved.RejectedKey, nodeSpec()); e != nil {
		return nil, e
	}
	retry := nodecontrol.Command{Version: 1, Epoch: saved.Committed.Epoch, ExpectedRevision: 1, RequestID: saved.Committed.LastRequestID}
	ack, e := c.Change(ctx, nodecontrol.ModeDrained, retry)
	if e != nil || ack.Control.Committed != saved.Committed {
		return nil, errors.New("cold exact drain retry not idempotent")
	}
	resume, e := operatorCommand(saved.Committed)
	if e != nil {
		return nil, e
	}
	open, e := c.Change(ctx, nodecontrol.ModeOpen, resume)
	if e != nil || !open.Control.AdmissionOpen || open.Control.Committed.Revision != 3 {
		return nil, errors.New("explicit ticket cold resume failed")
	}
	fresh, e := api.create(ctx, saved.RejectedKey)
	if e != nil {
		return nil, e
	}
	boot, e := operatorGuest(ctx, n, api, fresh.Ref, "cold", nil)
	if e != nil || boot == saved.RawBoot || boot == saved.ExistingBoot || boot == saved.AcceptedBoot {
		return nil, errors.New("ticket cold fresh guest reused identity")
	}
	if e = api.call(ctx, "DELETE", switchPath(fresh.Ref), "", generationBody(fresh.Ref), nil, 202); e != nil {
		return nil, e
	}
	if e = budgetDestroyed(ctx, api, fresh.Ref); e != nil {
		return nil, e
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	if e = operatorIdle(ctx, c, 0, 4); e != nil {
		return nil, e
	}
	if e = n.stopOperatorDaemon(ctx); e != nil {
		return nil, e
	}
	for _, path := range []string{nodeBudgetInstances, nodeGroup + "/control", nodeGroup} {
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	}
	return map[string]any{"l1_boot_changed_ack_drained_state_checked_before_daemon": true, "ordinary_uninstrumented_restart_stays_drained_pending0": true, "three_old_raw_session_keys410_no_route_or_ticket_resurrection": true, "exact_ack_retry_then_explicit_resume_revision3": true, "fresh_real_guest_uid_boot_clean_workspace_rejected_key_reusable": true, "all_four_projects_zero_pools_idle_daemon_reaped_node_subtree_removed": true, "control_metadata_not_repaired_rewritten_or_restored_by_fixture": true}, nil
}
