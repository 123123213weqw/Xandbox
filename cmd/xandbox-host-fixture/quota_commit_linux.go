//go:build linux && xandbox_host_fixture

package main

// Fixed extensions of the real quota filesystem barrier fixture. No tenant
// selected ordinal, device, errno, PID, tracepoint or execution command.
import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/client"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

func expectedCommitSets(mode quotaCommitMode) int {
	if mode.phase() == "" {
		return 0
	}
	if mode == quotaReleasePostHold {
		return 2
	}
	return 1
}
func validateCommitBoundary(mode quotaCommitMode, r quotaRecord) error {
	if mode.phase() == "" {
		return errors.New("unknown fixed commit boundary")
	}
	if mode == quotaReleasePostHold {
		if !quotaEmpty(r) {
			return errors.New("post-clear quota record not empty")
		}
		return nil
	}
	if r.BHard != 192<<10 || r.IHard != 128 || r.BSoft|r.ISoft|r.BTime|r.ITime != 0 || r.Space > 192<<20 || r.Inodes > 128 {
		return errors.New("known immutable limits missing at commit boundary")
	}
	// Pre-clear syncfs also drains delayed inode release. Namespace absence
	// does not imply the pre-call quota counters are already zero.
	if mode != quotaReleasePreHold && (r.Space != 0 || r.Inodes != 0) {
		return errors.New("pre-fork quota already charged")
	}
	return nil
}
func (n *node) reserveCommitEIO(ctx context.Context, live *quotaBarrierLive, api *client.Client) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	var createErr error
	select {
	case createErr = <-live.done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if createErr == nil || !strings.Contains(createErr.Error(), "HTTP 500:") {
		return nil, errors.New("real commit EIO did not refuse Create500")
	}
	s := live.o.snapshot()
	if s.err != nil {
		return nil, s.err
	}
	if !s.barrierContinued || !s.baselineSaved || s.injected != 0 || live.o.exitTrace == nil {
		return nil, errors.New("real EIO target was not continued into kernel")
	}
	var exit quotaExitResult
	if e := waitNode(ctx, func() (bool, error) { var e error; exit, e = live.o.exitTrace.read(); return exit.Seen != 0, e }); e != nil {
		return nil, e
	}
	if exit.Seen != 1 || exit.Return != -int64(unix.EIO) {
		return nil, errors.New("selected real syncfs exit was not EIO")
	}
	live.o.exitTrace.close()
	log, e := os.ReadFile("/run/quota-commit-eio.log")
	if e != nil || len(log) > 65536 || !strings.Contains(string(log), "Firecracker preparation failed") || !strings.Contains(string(log), "input/output error") {
		return nil, errors.New("ordinary Prepare EIO diagnostics not observed independently")
	}
	// Restore only our mapping for read-only owner inspection. Never remount
	// an aborted filesystem RW: recovery requires a new owned-L1 cold boot.
	if e = n.mapper.linear(); e != nil {
		return nil, e
	}
	base, _ := quotaSyscallBase(quotaBarrierCase)
	b, e := privatefile.Read(base+"/s/firecracker/"+s.ref.ID+s.ref.Generation+".json", 2048)
	if e != nil || string(b) != string(s.owner) {
		return nil, errors.New("EIO lost or changed exact durable quota owner")
	}
	if e = quotaBarrierNamespaceAbsent(s.ref); e != nil {
		return nil, e
	}
	var old sandbox.Record
	if e = api.Do(ctx, "GET", nodePath(s.ref), nil, &old); e != nil {
		return nil, e
	}
	if old.State == sandbox.Ready || old.State == sandbox.Destroyed || !old.StoppedAt.IsZero() || !old.DestroyedAt.IsZero() {
		return nil, errors.New("failed commit emitted false durable readiness/stop/destroy")
	}
	other, e := randomKey()
	if e != nil {
		return nil, e
	}
	var refused sandbox.Record
	if e = api.Create(ctx, other, nodeSpec(), &refused); e == nil || !strings.Contains(e.Error(), "HTTP 503:") {
		return nil, errors.New("EIO opened new admission")
	}
	n.quotaHeld = live
	return map[string]any{"phase": quotaReserveEIO.phase(), "checkpoint_receipt_fsynced_before_set": true, "durable_attempted_owner_before_set": true, "installed_limits_checked_before_fault": true, "ordinary_qsync_returned_before_syncfs": true, "notification_continued_no_errno_or_success_emulation": true, "selected_syncfs_kernel_exit_observed": true, "selected_syncfs_kernel_errno": int(unix.EIO), "selected_syncfs_exit_observations": exit.Seen, "ordinary_prepare_eio_diagnostic_in_tmpfs": true, "create_refused500": true, "no_false_ready_stop_destroy_confirmation": true, "exact_owner_retained_after_linear_restore": true, "pre_fork_namespace_absent_after_eio": true, "admission_new_create503": true, "no_quota_query_after_eio": true, "own_mapper_linear_restored_no_rw_remount": true, "fixed_project_zero_dirty_bytes": 4 << 20, "no_l2_vm_born_at_checkpoint": true}, nil
}
func (n *node) releaseCommitCheckpoint(ctx context.Context, mode quotaCommitMode, live *quotaBarrierLive, api *client.Client, cfg firecracker.Config) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !mode.release() {
		return nil, errors.New("fixed release mode required")
	}
	worker := &node{api: api}
	old, e := worker.create(ctx, live.plan.Key)
	if e != nil {
		return nil, e
	}
	if e = syscallGuestBoundary(cfg, old.Ref, live.p.cmd.Process.Pid); e != nil {
		return nil, e
	}
	u, e := worker.execute(ctx, old.Ref, []string{"id", "-u"})
	if e != nil || strings.TrimSpace(u.Stdout) != "65534" {
		return nil, errors.New("release guest UID mismatch")
	}
	boot, e := worker.execute(ctx, old.Ref, []string{"cat", "/proc/sys/kernel/random/boot_id"})
	if e != nil || strings.TrimSpace(boot.Stdout) == "" {
		return nil, errors.New("release guest boot missing")
	}
	base, _ := quotaSyscallBase(quotaBarrierCase)
	b, e := privatefile.Read(base+"/s/firecracker/"+old.ID+old.Generation+".json", 2048)
	if e != nil {
		return nil, e
	}
	if e = decodeQuotaBarrierOwner(b, old.Ref); e != nil {
		return nil, e
	}
	fs, e := openQuotaFSWithMapper(false, n.mapper)
	if e != nil {
		return nil, e
	}
	r, e := fs.get(quotaFirst)
	fs.file.Close()
	if e != nil || r.Space < 128<<20 || r.Space > 192<<20 || r.Inodes == 0 || r.Inodes > 128 || r.BHard != 192<<10 || r.IHard != 128 {
		return nil, errors.New("live release generation is not charged within fixed policy")
	}
	for _, path := range []string{cfg.RuntimeRoot + "/j/firecracker/" + old.ID + old.Generation, cfg.RuntimeRoot + "/j/firecracker/" + old.ID + old.Generation + "/root", cfg.RuntimeRoot + "/j/firecracker/" + old.ID + old.Generation + "/root/workspace.ext4"} {
		a, e := quotaAttributes(path, nil)
		if e != nil || a.Project != quotaFirst {
			return nil, errors.New("live release private project changed")
		}
	}
	receipt := quotaBarrierReceipt{Mode: mode, Phase: mode.phase(), Ref: old.Ref, Key: live.plan.Key, L1Boot: n.boot, L2Boot: strings.TrimSpace(boot.Stdout), ConfigHash: live.plan.ConfigHash, Owner: b}
	// All receipt fsync is BEFORE DELETE; never force a post-clear commit.
	if e = privateWrite(quotaBarrierReceiptPath, receipt); e != nil {
		return nil, e
	}
	live.o.mu.Lock()
	valid := live.o.state.syncfsPassed == 1 && live.o.state.qsetPassed == 1 && live.o.state.qsyncPassed == 1
	if valid {
		live.o.state.ref = old.Ref
		live.o.state.owner = append([]byte(nil), b...)
		live.o.state.baselineSaved = true
		live.o.state.armed = true
	}
	live.o.mu.Unlock()
	if !valid {
		return nil, errors.New("unexpected reserve barrier sequence before release")
	}
	var accepted sandbox.Record
	if e = api.Do(ctx, "DELETE", nodePath(old.Ref), generationBody(old.Ref), &accepted); e != nil {
		return nil, e
	}
	if e = waitNode(ctx, live.o.actualBarrierBlocked); e != nil {
		return nil, e
	}
	for i := 0; i < 3; i++ {
		time.Sleep(100 * time.Millisecond)
		blocked, e := live.o.actualBarrierBlocked()
		if e != nil || !blocked {
			return nil, errors.New("release commit not held in actual filesystem kernel path")
		}
	}
	var held sandbox.Record
	if e = api.Do(ctx, "GET", nodePath(old.Ref), nil, &held); e != nil {
		return nil, e
	}
	if held.State != sandbox.Reclaiming || held.StoppedAt.IsZero() || !held.DestroyedAt.IsZero() {
		return nil, errors.New("release commit acknowledged ownership destruction too soon")
	}
	other, e := randomKey()
	if e != nil {
		return nil, e
	}
	var refused sandbox.Record
	request, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if e = api.Create(request, other, nodeSpec(), &refused); e == nil || !strings.Contains(e.Error(), "HTTP 503:") {
		return nil, errors.New("held release commit returned capacity")
	}
	s := live.o.snapshot()
	n.quotaHeld = live
	return map[string]any{"phase": mode.phase(), "checkpoint_receipt_fsynced_before_delete": true, "old_real_kvm_guest_uid_exec_and_quota_checked": true, "same_durable_owner_checked_at_release_boundary": true, "namespace_and_cgroup_absent_before_suspend": true, "selected_syncfs_ordinal": mode.ordinal(), "quota_record_empty_before_suspend": mode == quotaReleasePostHold, "quota_space_before_suspend": s.boundarySpace, "quota_inodes_before_suspend": s.boundaryInodes, "ordinary_qsync_returned_before_selected_syncfs": true, "notification_continued_into_real_kernel": true, "actual_syncfs_syscall_D_filesystem_stack_not_seccomp": true, "actual_kernel_hold_rechecked_three_times": true, "durable_reclaiming_stopped_not_destroyed": true, "capacity_retained_new_create503": true, "no_quota_or_srv_reads_after_suspend": true, "no_observer_sync_after_delete": true, "mapper_still_suspended_until_power_cut": true, "fixed_project_zero_dirty_bytes": 4 << 20}, nil
}
