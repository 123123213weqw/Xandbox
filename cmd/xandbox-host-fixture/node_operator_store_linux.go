//go:build linux && xandbox_host_fixture

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const operatorStoreReceipt = "/srv/fixture/operator-store-receipt.json"

type operatorStoreReceiptValue struct {
	Version                         int
	Mode                            operatorStoreMode
	L1Boot, Config                  string
	Before, Attempted, Expected     nodecontrol.State
	Command                         nodecontrol.Command
	Raw                             sandbox.Ref
	Session                         session.Result
	RawKey, SessionKey, RejectedKey string
	RawBoot, SessionBoot            string
}

func operatorStoreExpected(mode operatorStoreMode, before, next nodecontrol.State) (nodecontrol.State, error) {
	if !mode.valid() {
		return nodecontrol.State{}, errors.New("unknown fixed store phase")
	}
	if mode == operatorStorePre {
		return before, nil
	}
	return next, nil
}
func operatorStoreSequence(mode operatorStoreMode, s operatorStoreSnapshot) error {
	if s.Err != nil {
		return s.Err
	}
	if s.HeldID == 0 || s.FileEntries != 1 {
		return errors.New("ordinary file fsync entry not witnessed")
	}
	if mode == operatorStorePre {
		if s.AdmissionDirEntries != 0 || s.RootEntries != 0 {
			return errors.New("pre-rename hold progressed into directory sync")
		}
	} else if mode == operatorStorePost {
		if s.AdmissionDirEntries != 1 || s.RootEntries != 1 {
			return errors.New("post-commit directory sequence incomplete")
		}
	} else {
		return errors.New("unknown operator store phase")
	}
	return nil
}
func operatorStoreShortStatus(ctx context.Context, c *nodecontrol.Client) (nodecontrol.Reply, error) {
	short, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	return c.Status(short)
}
func operatorStorePending(ctx context.Context, c *nodecontrol.Client, before nodecontrol.State, command nodecontrol.Command) error {
	v, e := operatorStoreShortStatus(ctx, c)
	if e != nil {
		return e
	}
	s := v.Control
	if s.Phase != "pending" || s.AdmissionOpen || s.Committed != before || s.DesiredMode != nodecontrol.ModeDrained || s.PendingRequestID != command.RequestID {
		return errors.New("pending control status changed or admission opened")
	}
	return nil
}
func operatorStoreFenced(ctx context.Context, c *nodecontrol.Client, before nodecontrol.State) error {
	return waitNode(ctx, func() (bool, error) {
		v, e := operatorStoreShortStatus(ctx, c)
		if e != nil {
			return false, e
		}
		return v.Control.Phase == "fenced" && !v.Control.AdmissionOpen && v.Control.Committed == before, nil
	})
}
func (n *node) nodeOperatorStoreCheckpoint(ctx context.Context, mode operatorStoreMode) (out map[string]any, err error) {
	if !mode.valid() {
		return nil, errors.New("fixed operator store phase required")
	}
	if e := n.operatorProfile(); e != nil {
		return nil, e
	}
	// Ordinary healthy startup initializes the real store, then an exclusive clean
	// restart adds only the inherited TEST filter. No metadata is written by hand.
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
		return nil, errors.New("fresh healthy operator initialization required")
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
	baseline, e := c.Status(ctx)
	if e != nil || baseline.Control.Committed != initial.Control.Committed || !baseline.Control.AdmissionOpen {
		return nil, errors.New("observed restart changed initial authority")
	}
	before := baseline.Control.Committed
	command, e := operatorCommand(before)
	if e != nil {
		return nil, e
	}
	next := nodecontrol.State{Version: 1, Epoch: before.Epoch, Revision: 2, Mode: nodecontrol.ModeDrained, LastRequestID: command.RequestID, LastExpectedRevision: 1}
	expected, e := operatorStoreExpected(mode, before, next)
	if e != nil {
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
	sessionKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	bound, e := api.openSession(ctx, sessionKey)
	if e != nil {
		return nil, e
	}
	sessionBoot, e := operatorGuest(ctx, n, api, bound.Current, "session", &bound)
	if e != nil {
		return nil, fmt.Errorf("store session validation: %w", e)
	}
	if sessionBoot == rawBoot {
		return nil, errors.New("independent store session boots required")
	}
	owner, _, e := budgetOwner(raw.Ref)
	if e != nil {
		return nil, e
	}
	busy, e := n.submit(ctx, raw.Ref, []string{"sh", "-c", "i=0; while :; do i=$((i+1)); printf '%s\\n' \"$i\" > store-progress.tmp; mv store-progress.tmp store-progress; sleep 0.05; done"})
	if e != nil {
		return nil, e
	}
	progress := func() (int, error) {
		output, e := api.executeVM(ctx, raw.Ref, []string{"sh", "-c", "cat store-progress 2>/dev/null || echo 0"})
		if e != nil {
			return 0, e
		}
		return strconv.Atoi(strings.TrimSpace(output.Stdout))
	}
	first := 0
	if e = waitNode(ctx, func() (bool, error) { var e error; first, e = progress(); return first > 0, e }); e != nil {
		return nil, e
	}
	ledger, e := operatorFileNames("/srv/state/ledger")
	if e != nil || len(ledger) != 2 {
		return nil, errors.New("unexpected pre-fault record inventory")
	}
	journal, e := operatorSessionBytes(bound.ID)
	if e != nil {
		return nil, e
	}
	if e = observer.arm(mode, before, next); e != nil {
		return nil, e
	}
	requestCtx, cancelRequest := context.WithCancel(ctx)
	defer cancelRequest()
	finished := make(chan error, 1)
	go func() { _, e := c.Change(requestCtx, nodecontrol.ModeDrained, command); finished <- e }()
	select {
	case <-observer.held:
	case <-observer.done:
		return nil, errors.Join(errors.New("operator observer ended before target"), observer.snapshot().Err)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if e = observer.heldValid(); e != nil {
		return nil, e
	}
	if e = operatorStoreSequence(mode, observer.snapshot()); e != nil {
		return nil, e
	}
	if e = operatorStorePending(ctx, c, before, command); e != nil {
		return nil, e
	}
	disk, e := operatorState()
	if e != nil || disk != expected {
		return nil, errors.New("pre/post-commit disk namespace differs at held entry")
	}
	cancelRequest()
	select {
	case e = <-finished:
		if !errors.Is(e, context.Canceled) {
			return nil, errors.New("caller cancellation did not terminate only its wait")
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if e = observer.heldValid(); e != nil {
		return nil, e
	}
	if e = operatorStorePending(ctx, c, before, command); e != nil {
		return nil, e
	}
	other, e := operatorCommand(before)
	if e != nil {
		return nil, e
	}
	short, cancel := context.WithTimeout(ctx, time.Second)
	_, busyErr := c.Change(short, nodecontrol.ModeOpen, other)
	cancel()
	if busyErr == nil || !strings.Contains(busyErr.Error(), "BUSY") {
		return nil, errors.New("pending mutation did not reject BUSY promptly")
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
	afterLedger, e := operatorFileNames("/srv/state/ledger")
	if e != nil || strings.Join(afterLedger, ",") != strings.Join(ledger, ",") {
		return nil, errors.New("pending drain created ledger record")
	}
	afterJournal, e := operatorSessionBytes(bound.ID)
	if e != nil || !bytes.Equal(afterJournal, journal) {
		return nil, errors.New("pending drain changed session history")
	}
	sessions, e := operatorFileNames("/srv/state/sessions")
	if e != nil || len(sessions) != 1 {
		return nil, errors.New("pending drain created session record")
	}
	if e = waitNode(ctx, func() (bool, error) { v, e := progress(); return v > first, e }); e != nil {
		return nil, e
	}
	job, e := n.job(ctx, raw.Ref, busy)
	if e != nil || job.Status != "RUNNING" {
		return nil, errors.New("pre-existing raw task not running under control hold")
	}
	value, e := api.sessionExec(ctx, bound, []string{"cat", "operator-marker"})
	if e != nil || value.Stdout != "session" {
		return nil, errors.New("existing session command stalled behind control fsync")
	}
	if e = api.call(ctx, "GET", "/readyz", "", nil, nil, 503); e != nil {
		return nil, e
	}
	if e = api.call(ctx, "GET", "/healthz", "", nil, nil, 200); e != nil {
		return nil, e
	}
	began := time.Now()
	if e = api.call(ctx, "DELETE", switchPath(raw.Ref), "", generationBody(raw.Ref), nil, 202); e != nil {
		return nil, e
	}
	if e = waitNode(ctx, func() (bool, error) { return nodePrepareGroupEmpty(raw.Ref) }); e != nil {
		return nil, e
	}
	stopMS := switchMS(began)
	if e = budgetDestroyed(ctx, api, raw.Ref); e != nil {
		return nil, e
	}
	q, e := driverQuotaRead(owner.ProjectID)
	if e != nil || !quotaEmpty(q) {
		return nil, errors.New("raw quota remained while control fsync held")
	}
	reclaimMS := switchMS(began)
	if e = operatorIdle(ctx, c, 1, 2); e != nil {
		return nil, e
	}
	if e = observer.heldValid(); e != nil {
		return nil, e
	}
	if e = operatorStorePending(ctx, c, before, command); e != nil {
		return nil, e
	}
	snap := observer.snapshot()
	if snap.OtherWhileHeld <= 0 {
		return nil, errors.New("no other actual fsync notifications continued during target hold")
	}
	observer.inject <- struct{}{}
	if e = operatorStoreFenced(ctx, c, before); e != nil {
		return nil, e
	}
	if e = waitNode(ctx, func() (bool, error) { s := observer.snapshot(); return s.Injected == 1, s.Err }); e != nil {
		return nil, e
	}
	id := observer.snapshot().HeldID
	if e = quotaNotifyIO(observer.fd, quotaNotifIDValid, unsafe.Pointer(&id)); !errors.Is(e, unix.ENOENT) {
		return nil, errors.New("injected target remained pending")
	}
	other, e = operatorCommand(before)
	if e != nil {
		return nil, e
	}
	if _, e = c.Change(ctx, nodecontrol.ModeOpen, other); e == nil || !strings.Contains(e.Error(), "PERSISTENCE_FENCED") {
		return nil, errors.New("error latch allowed new control mutation")
	}
	disk, e = operatorState()
	if e != nil || disk != expected {
		return nil, errors.New("EIO changed expected real disk truth")
	}
	if e = operatorDenied(ctx, api, "/v1/sandboxes", rejectedKey, nodeSpec()); e != nil {
		return nil, e
	}
	value, e = api.sessionExec(ctx, bound, []string{"cat", "operator-marker"})
	if e != nil || value.Stdout != "session" {
		return nil, errors.New("error fence stopped existing session")
	}
	if e = api.revoke(ctx, bound); e != nil {
		return nil, e
	}
	if e = budgetDestroyed(ctx, api, bound.Current); e != nil {
		return nil, e
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	if e = operatorIdle(ctx, c, 0, 2); e != nil {
		return nil, e
	}
	if e = n.stopOperatorDaemon(ctx); e != nil {
		return nil, e
	}
	if e = observer.close(); e != nil {
		return nil, e
	}
	snap = observer.snapshot()
	if e = operatorStoreSequence(mode, snap); e != nil || snap.Injected != 1 {
		return nil, errors.New("exact one EIO sequence not retained")
	}
	saved := operatorStoreReceiptValue{Version: 1, Mode: mode, L1Boot: n.boot, Before: before, Attempted: next, Expected: expected, Command: command, Raw: raw.Ref, Session: bound, RawKey: rawKey, SessionKey: sessionKey, RejectedKey: rejectedKey, RawBoot: rawBoot, SessionBoot: sessionBoot}
	saved.Config, e = fileHash("/srv/config/backend.json")
	if e != nil {
		return nil, e
	}
	if e = privateWrite(operatorStoreReceipt, saved); e != nil {
		return nil, e
	}
	return map[string]any{"mode": string(mode), "real_nested_kvm": true, "exact_ordinary_elf_incarnation_tgid_control_and_fsync_fd_inode_checked": true, "actual_temp_payload_and_pre_or_post_rename_directory_sequence_checked": true, "held_notification_is_not_filesystem_d_or_media_failure": true, "caller_cancelled_after_acceptance_target_remained_valid": true, "status_pending_and_busy_mutation_prompt_while_store_blocked": true, "new_raw_session_switch503_no_record_or_history": true, "accepted_raw_progress_and_existing_session_exec_continue": true, "raw_stop_private_destroy_quota0_and_pools_baseline_while_target_held": true, "other_fsyncs_continued_not_synthetic_success": true, "single_target_errno_eio_and_memory_fence_until_restart": true, "cached_committed_before_but_actual_disk_truth_checked": true, "existing_session_exec_and_reclaim_continue_after_error_latch": true, "all_four_projects_zero_controller_reaped_before_cold": true, "receipt_fsynced_without_editing_control_metadata": true, "file_sync_entries": snap.FileEntries, "admission_dir_sync_entries": snap.AdmissionDirEntries, "root_dir_sync_entries": snap.RootEntries, "target_errno_eio_replies": snap.Injected, "other_fsync_continue_replies_while_held": snap.OtherWhileHeld, "execution_domain_stop_observed_ms": stopMS, "private_destroy_quota_zero_observed_ms": reclaimMS, "expected_cold_mode": expected.Mode, "filesystem_d_or_physical_eio_claim": false, "production_slo_claim": false}, nil
}
func validateOperatorStoreReceipt(s operatorStoreReceiptValue, mode operatorStoreMode, boot string) error {
	if s.Version != 1 || !mode.valid() || s.Mode != mode || !switchUUID(s.L1Boot) || s.L1Boot == boot || !hashPattern.MatchString(s.Config) || !switchRefValid(s.Raw) || !switchRefValid(s.Session.Current) || s.Raw == s.Session.Current || !hex32Pattern(s.Session.ID) || s.Session.Revision != 1 || !switchUUID(s.RawBoot) || !switchUUID(s.SessionBoot) || s.RawBoot == s.SessionBoot {
		return errors.New("invalid fixed operator store recovery identity")
	}
	for _, key := range []string{s.RawKey, s.SessionKey, s.RejectedKey} {
		if !hashPattern.MatchString(key) {
			return errors.New("invalid operator store private replay key")
		}
	}
	before := s.Before
	if before.Version != 1 || !hex32Pattern(before.Epoch) || before.Revision != 1 || before.Mode != nodecontrol.ModeOpen || before.LastRequestID != "" || before.LastExpectedRevision != 0 || !s.Command.Valid() || s.Command.Epoch != before.Epoch || s.Command.ExpectedRevision != 1 {
		return errors.New("invalid initial operator store authority")
	}
	next := nodecontrol.State{Version: 1, Epoch: before.Epoch, Revision: 2, Mode: nodecontrol.ModeDrained, LastRequestID: s.Command.RequestID, LastExpectedRevision: 1}
	expected, e := operatorStoreExpected(mode, before, next)
	if e != nil || s.Attempted != next || s.Expected != expected {
		return errors.New("operator store cold truth not bound to exact failed command")
	}
	return nil
}
func (n *node) nodeOperatorStoreRecover(ctx context.Context, mode operatorStoreMode) (map[string]any, error) {
	return n.recoverOperatorStore(ctx, mode, operatorStoreReceipt)
}
func (n *node) recoverOperatorStore(ctx context.Context, mode operatorStoreMode, receipt string) (map[string]any, error) {
	if receipt != operatorStoreReceipt && !(receipt == operatorShutdownReceipt && mode == operatorStorePre) {
		return nil, errors.New("fixed recovery receipt required")
	}
	if e := n.operatorProfile(); e != nil {
		return nil, e
	}
	data, e := privatefile.Read(receipt, 32768)
	if e != nil {
		return nil, e
	}
	var saved operatorStoreReceiptValue
	if e = strictjson.Decode(data, &saved); e != nil {
		return nil, e
	}
	if e = validateOperatorStoreReceipt(saved, mode, n.boot); e != nil {
		return nil, e
	}
	config, e := fileHash("/srv/config/backend.json")
	if e != nil || config != saved.Config {
		return nil, errors.New("operator store node policy changed")
	}
	disk, e := operatorState()
	if e != nil || disk != saved.Expected {
		return nil, errors.New("cold state did not preserve observed pre/post EIO namespace")
	}
	for _, ref := range []sandbox.Ref{saved.Raw, saved.Session.Current} {
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
	view, e := c.Status(ctx)
	if e != nil || view.Control.Phase != "ready" || view.Control.Committed != saved.Expected || view.Control.AdmissionOpen != (mode == operatorStorePre) || (receipt == operatorShutdownReceipt && view.Control.PendingSessionReservations != 0) {
		return nil, errors.New("ordinary restart did not use actual disk truth")
	}
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	defer api.close()
	for _, ref := range []sandbox.Ref{saved.Raw, saved.Session.Current} {
		if e = budgetDestroyed(ctx, api, ref); e != nil {
			return nil, e
		}
	}
	if e = api.call(ctx, "POST", "/v1/sandboxes", saved.RawKey, nodeSpec(), nil, 410); e != nil {
		return nil, e
	}
	if e = api.call(ctx, "POST", "/v1/sessions", saved.SessionKey, nodeSpec(), nil, 410); e != nil {
		return nil, e
	}
	if mode == operatorStorePost {
		if e = operatorDenied(ctx, api, "/v1/sandboxes", saved.RejectedKey, nodeSpec()); e != nil {
			return nil, e
		}
		replay, e := c.Change(ctx, nodecontrol.ModeDrained, saved.Command)
		if e != nil || replay.Control.Committed != saved.Expected || replay.Control.AdmissionOpen {
			return nil, errors.New("post-commit exact retry did not acknowledge committed truth")
		}
		resume, e := operatorCommand(saved.Expected)
		if e != nil {
			return nil, e
		}
		if _, e = c.Change(ctx, nodecontrol.ModeOpen, resume); e != nil {
			return nil, e
		}
	}
	fresh, e := api.create(ctx, saved.RejectedKey)
	if e != nil {
		return nil, e
	}
	boot, e := operatorGuest(ctx, n, api, fresh.Ref, "cold", nil)
	if e != nil || boot == saved.RawBoot || boot == saved.SessionBoot {
		return nil, errors.New("fresh post-error guest identity invalid")
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
	if e = operatorIdle(ctx, c, 0, 3); e != nil {
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
	return map[string]any{"mode": string(mode), "l1_boot_changed_original_disk_truth_checked_before_daemon": true, "ordinary_uninstrumented_restart_matches_pre_or_post_commit_state": true, "precommit_failed_unacknowledged_drain_may_reopen_old_open_not_fabricated_persistence": mode == operatorStorePre, "postcommit_drained_exact_retry_and_explicit_resume_checked": mode == operatorStorePost, "old_raw_session_keys410_and_prior_quota_namespace_zero": true, "fresh_real_guest_uid_boot_clean_workspace_rejected_key_reusable": true, "all_four_projects_zero_pools_idle_daemon_reaped_node_subtree_removed": true, "control_metadata_not_repaired_rewritten_or_restored_by_fixture": true, "expected_recovered_mode": saved.Expected.Mode}, nil
}
