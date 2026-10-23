//go:build linux && xandbox_host_fixture

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/client"
	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

func shutdownDurable(ref sandbox.Ref) error {
	if e := requireNode(); e != nil {
		return e
	}
	if !switchRefValid(ref) {
		return errors.New("fixed shutdown ref required")
	}
	b, e := privatefile.Read("/srv/state/ledger/"+ref.ID+".json", sandbox.MaxLedgerRecordBytes)
	if e != nil {
		return e
	}
	var env struct {
		Version int            `json:"version"`
		Record  sandbox.Record `json:"record"`
	}
	if strictjson.Decode(b, &env) != nil || env.Version != 1 || env.Record.Ref != ref || env.Record.Backend != "firecracker" || env.Record.TenantID != "nested-fixture" || env.Record.State != sandbox.Destroyed || env.Record.StoppedAt.IsZero() || env.Record.DestroyedAt.IsZero() {
		return errors.New("actual stopped and durable destroyed shutdown record required")
	}
	return budgetAbsent(ref)
}

// Compare immutable bytes/names across the failed contender, not access times.
// Do not call production Load while the original Store goroutine is pending.
func shutdownInventoryName(dir, name, held string) bool {
	switch dir {
	case "/srv/state/admission":
		return name == "state.json" || (held != "" && name == filepath.Base(held))
	case "/srv/state/ledger", "/srv/state/sessions":
		return len(name) == 37 && name[32:] == ".json" && hex32Pattern(name[:32])
	case "/srv/state/firecracker":
		return name == "config.json"
	}
	return false
}
func shutdownInventory(held string) (string, error) {
	if e := requireNode(); e != nil {
		return "", e
	}
	if filepath.Clean(held) != held || filepath.Dir(held) != "/srv/state/admission" || !operatorTempPattern.MatchString(filepath.Base(held)) {
		return "", errors.New("exact held control temp path required")
	}
	h := sha256.New()
	for _, dir := range []string{"/srv/state/admission", "/srv/state/ledger", "/srv/state/sessions", "/srv/state/firecracker", "/srv/r/j/firecracker"} {
		entries, e := os.ReadDir(dir)
		if os.IsNotExist(e) && dir == "/srv/r/j/firecracker" {
			fmt.Fprintf(h, "%s:absent\n", dir)
			continue
		}
		want := map[string]int{"/srv/state/admission": 2, "/srv/state/ledger": 2, "/srv/state/sessions": 1, "/srv/state/firecracker": 1, "/srv/r/j/firecracker": 0}[dir]
		if e != nil || len(entries) != want {
			return "", fmt.Errorf("exact shutdown metadata count required in %s", dir)
		}
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			if !shutdownInventoryName(dir, entry.Name(), held) {
				return "", errors.New("unexpected shutdown metadata name")
			}
			names = append(names, entry.Name())
		}
		for _, name := range names {
			path := filepath.Join(dir, name)
			info, e := os.Lstat(path)
			if e != nil {
				return "", e
			}
			if !info.Mode().IsRegular() {
				return "", errors.New("shutdown stable inventory must contain only regular metadata")
			}
			b, e := privatefile.Read(path, sandbox.MaxLedgerRecordBytes)
			if e != nil {
				return "", e
			}
			fmt.Fprintf(h, "%s:%d:%x\n", path, info.Mode(), sha256.Sum256(b))
		}
	}
	// Cgroup pseudo-files are neither stable metadata nor private regular files.
	// Only the absence of generation subdirectories belongs in this inventory.
	entries, e := os.ReadDir(nodeBudgetInstances)
	if e != nil || len(entries) > 128 {
		return "", errors.New("bounded instances cgroup inventory required")
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return "", errors.New("generation cgroup remained after shutdown cleanup")
		}
	}
	fmt.Fprintln(h, "instances:no-generation-directories")
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (n *node) shutdownContender(ctx context.Context, s *operatorShutdownObserver, before nodecontrol.State) error {
	if e := s.bothValid(); e != nil {
		return e
	}
	info, e := os.Lstat("/srv/state/controller.lock")
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != 0 || st.Nlink != 1 {
		return errors.New("private single-link controller lock required")
	}
	baseline, e := shutdownInventory(s.store.tempPath)
	if e != nil {
		return e
	}
	cg, e := os.Open(nodeGroup + "/control")
	if e != nil {
		return e
	}
	defer cg.Close()
	short, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	// PID1 launches this unfiltered second process. No listener FD is passed.
	cmd := exec.CommandContext(short, "/srv/assets/sandboxd", "-backend", "firecracker", "-state-dir", "/srv/state", "-auth-file", "/srv/config/auth.json", "-firecracker-config", "/srv/config/backend.json", "-max-instances", "4", "-max-records", "1024", "-max-sessions", "32", "-metrics")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	e = cmd.Run()
	var ex *exec.ExitError
	if !errors.As(e, &ex) || ex.ExitCode() != 1 || short.Err() != nil || out.Len() > 16384 || !strings.Contains(out.String(), "sandboxd: state directory already locked") {
		return errors.New("same ordinary contender did not promptly fail actual state lock")
	}
	current, e := os.Lstat("/srv/state/controller.lock")
	if e != nil || !os.SameFile(info, current) || current.Mode() != info.Mode() {
		return errors.New("contender changed state lock inode or mode")
	}
	after, e := shutdownInventory(s.store.tempPath)
	if e != nil || after != baseline {
		return errors.New("failed contender changed stable metadata/backend inventory")
	}
	disk, e := operatorState()
	if e != nil || disk != before {
		return errors.New("failed contender changed committed authority")
	}
	for _, p := range []string{"/srv/state/api.sock", operatorSocket, "/srv/state/metrics.sock"} {
		if _, e = os.Lstat(p); !os.IsNotExist(e) {
			return errors.New("API listener exists after run returned")
		}
	}
	return s.bothValid()
}
func (n *node) nodeOperatorShutdownCheckpoint(ctx context.Context) (out map[string]any, err error) {
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
		return nil, errors.New("fresh healthy shutdown store required")
	}
	if e = n.stopOperatorDaemon(ctx); e != nil {
		return nil, e
	}
	o, s, e := n.startOperatorObserved(ctx, true)
	if e != nil {
		return nil, e
	}
	defer func() {
		// Kill ONLY our known subject before closing the notification listener.
		if n.process != nil {
			n.process.Process.Kill()
			select {
			case <-n.exited:
				n.process = nil
			case <-time.After(2 * time.Second):
			}
		}
		err = errors.Join(err, o.close())
	}()
	c, e = nodecontrol.NewClient("/srv/state")
	if e != nil {
		return nil, e
	}
	defer c.Close()
	v, e := c.Status(ctx)
	if e != nil || v.Control.Committed != initial.Control.Committed || !v.Control.AdmissionOpen {
		return nil, errors.New("observed shutdown baseline changed")
	}
	before := v.Control.Committed
	command, e := operatorCommand(before)
	if e != nil {
		return nil, e
	}
	next := nodecontrol.State{Version: 1, Epoch: before.Epoch, Revision: 2, Mode: nodecontrol.ModeDrained, LastRequestID: command.RequestID, LastExpectedRevision: 1}
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
	if e != nil || sessionBoot == rawBoot {
		return nil, errors.New("two distinct shutdown real guest boots required")
	}
	// Both guests really execute, including a running raw job at shutdown.
	job, e := n.submit(ctx, raw.Ref, []string{"sh", "-c", "while :; do printf x > shutdown-progress; sleep 0.05; done"})
	if e != nil {
		return nil, e
	}
	if _, e = api.executeVM(ctx, raw.Ref, []string{"sh", "-c", "while [ ! -s shutdown-progress ]; do sleep 0.05; done; cat shutdown-progress"}); e != nil {
		return nil, e
	}
	j, e := n.job(ctx, raw.Ref, job)
	if e != nil || j.Status != "RUNNING" {
		return nil, errors.New("actual raw job must be running")
	}
	if e = o.arm(operatorStorePre, before, next); e != nil {
		return nil, e
	}
	requestCtx, cancelRequest := context.WithCancel(ctx)
	defer cancelRequest()
	finished := make(chan error, 1)
	go func() { _, e := c.Change(requestCtx, nodecontrol.ModeDrained, command); finished <- e }()
	select {
	case <-o.held:
	case <-o.done:
		return nil, errors.Join(errors.New("shutdown observer ended before file hold"), o.snapshot().Err)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if e = o.heldValid(); e != nil {
		return nil, e
	}
	if e = operatorStorePending(ctx, c, before, command); e != nil {
		return nil, e
	}
	select {
	case <-finished:
		return nil, errors.New("drain completed before shutdown")
	default:
	}
	rejectedKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	if e = operatorDenied(ctx, api, "/v1/sandboxes", rejectedKey, nodeSpec()); e != nil {
		return nil, e
	}
	if e = s.signal(); e != nil {
		return nil, e
	}
	began := time.Now()
	if e = n.process.Process.Signal(syscall.SIGTERM); e != nil {
		return nil, e
	}
	refs := []sandbox.Ref{raw.Ref, bound.Current}
	if e = waitNode(ctx, func() (bool, error) {
		if e := o.snapshot().Err; e != nil {
			return false, e
		}
		for _, ref := range refs {
			empty, e := nodePrepareGroupEmpty(ref)
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				return false, e
			}
			if !empty {
				return false, nil
			}
		}
		return true, o.heldValid()
	}); e != nil {
		return nil, e
	}
	stopMS := switchMS(began)
	if e = waitNode(ctx, func() (bool, error) {
		if e := o.snapshot().Err; e != nil {
			return false, e
		}
		for _, ref := range refs {
			if e := shutdownDurable(ref); e != nil {
				return false, nil
			}
		}
		if e := driverQuotaAllClear(); e != nil {
			return false, nil
		}
		return true, o.heldValid()
	}); e != nil {
		return nil, e
	}
	reclaimMS := switchMS(began)
	select {
	case <-s.exitHeld:
	case <-o.done:
		return nil, errors.Join(errors.New("shutdown observer ended before real exit"), o.snapshot().Err)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	exitMS := switchMS(began)
	if e = s.bothValid(); e != nil {
		return nil, e
	}
	if e = n.shutdownContender(ctx, s, before); e != nil {
		return nil, e
	}
	contenderMS := switchMS(began)
	// Only EXIT_GROUP is authorized. The pending Store never resumes.
	s.continueExit <- struct{}{}
	select {
	case e = <-n.exited:
		var ex *exec.ExitError
		if !errors.As(e, &ex) || ex.ExitCode() != 1 {
			return nil, errors.New("ordinary shutdown did not really exit code1")
		}
		n.process = nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if e = waitNode(ctx, func() (bool, error) { return s.snapshot().ExitContinued == 1, o.snapshot().Err }); e != nil {
		return nil, e
	}
	if e = s.invalidAfterReap(); e != nil {
		return nil, e
	}
	select {
	case e = <-finished:
		if e == nil {
			return nil, errors.New("uncommitted drain falsely ACKed")
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	snap := o.snapshot()
	if e = operatorStoreSequence(operatorStorePre, snap); e != nil {
		return nil, e
	}
	if snap.Injected != 0 || snap.TicketContinued != 0 || snap.OtherWhileHeld < 1 {
		return nil, errors.New("shutdown held FSYNC replied or independent IO not witnessed")
	}
	if e = o.close(); e != nil {
		return nil, e
	}
	n.api.Close()
	n.api = client.NewWithToken("/srv/state/api.sock", n.token)
	disk, e := operatorState()
	if e != nil || disk != before {
		return nil, errors.New("never-continued pre-file drain unexpectedly committed")
	}
	for _, ref := range refs {
		if e = shutdownDurable(ref); e != nil {
			return nil, e
		}
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	saved := operatorStoreReceiptValue{Version: 1, Mode: operatorStorePre, L1Boot: n.boot, Before: before, Attempted: next, Expected: before, Command: command, Raw: raw.Ref, Session: bound, RawKey: rawKey, SessionKey: sessionKey, RejectedKey: rejectedKey, RawBoot: rawBoot, SessionBoot: sessionBoot}
	saved.Config, e = fileHash("/srv/config/backend.json")
	if e != nil {
		return nil, e
	}
	if e = privateWrite(operatorShutdownReceipt, saved); e != nil {
		return nil, e
	}
	return map[string]any{"real_nested_kvm": true, "exact_ordinary_elf_incarnation_tgid_control_checked": true, "actual_pre_rename_temp_payload_pending_no_ack": true, "actual_sigterm_while_fsync_id_valid": true, "both_guests_execution_empty_and_durable_private_gc_before_store_resolution": true, "actual_control_close_deadline_error_and_exit_group1_after_run_defers": true, "two_notifications_valid_while_same_ordinary_contender_lock_refused": true, "contender_reaped_no_metadata_namespace_or_listener_change": true, "only_exit_group_continue_no_file_reply_or_synthetic_success": true, "actual_exit1_reaped_then_both_ids_enoent_with_listener_open": true, "failed_unacknowledged_pre_file_drain_actual_old_open1": true, "all_four_projects_zero_before_private_receipt_and_cold": true, "file_sync_entries": snap.FileEntries, "file_sync_continue_or_errno_replies": 0, "exit_group_continue_replies": s.snapshot().ExitContinued, "ordinary_process_exit_code": 1, "other_fsync_continue_replies_while_held": snap.OtherWhileHeld, "other_exit_group_continue_replies": s.snapshot().OtherExits, "hold_deadline_ms": 20000, "control_close_timeout_ms_unchanged": 5000, "sigterm_to_execution_domain_empty_observed_ms": stopMS, "sigterm_to_private_destroy_quota_zero_observed_ms": reclaimMS, "sigterm_to_exit_group_entry_observed_ms": exitMS, "sigterm_to_contender_reaped_observed_ms": contenderMS, "filesystem_d_or_physical_media_claim": false, "production_slo_claim": false}, nil
}
func (n *node) nodeOperatorShutdownRecover(ctx context.Context) (map[string]any, error) {
	v, e := n.recoverOperatorStore(ctx, operatorStorePre, operatorShutdownReceipt)
	if e != nil {
		return nil, e
	}
	for _, k := range []string{"l1_boot_changed_original_disk_truth_checked_before_daemon", "ordinary_uninstrumented_restart_matches_pre_or_post_commit_state", "precommit_failed_unacknowledged_drain_may_reopen_old_open_not_fabricated_persistence", "old_raw_session_keys410_and_prior_quota_namespace_zero", "fresh_real_guest_uid_boot_clean_workspace_rejected_key_reusable", "all_four_projects_zero_pools_idle_daemon_reaped_node_subtree_removed", "control_metadata_not_repaired_rewritten_or_restored_by_fixture"} {
		if v[k] != true {
			return nil, errors.New("shutdown cold recovery witness absent")
		}
	}
	return map[string]any{"l1_boot_changed_old_open1_original_disk_before_daemon": true, "ordinary_unfiltered_restart_ready_open_pending0": true, "old_raw_session_keys410_no_route_resurrection": true, "fresh_real_guest_boot_uid_clean_workspace_rejected_key_reusable": true, "all_four_projects_zero_pools_idle_daemon_reaped_node_subtree_removed": true, "no_control_metadata_repair_or_failed_intent_fabrication": true}, nil
}
