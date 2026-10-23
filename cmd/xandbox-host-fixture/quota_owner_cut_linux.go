//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: an unreturned owner-directory fsync after ordinary namespace and
// quota cleanup. Receipt is private control data, NEVER an L1 disk write.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

type ownerCutReceipt struct {
	copyCutReceipt
	VictimBoot, Ledger string
}
type ownerCutLive struct{ observer *ownerObserver }

func validateOwnerCutReceipt(r ownerCutReceipt) error {
	if e := validateCutReceiptOwners(r.copyCutReceipt, true); e != nil {
		return e
	}
	if !switchUUID(r.VictimBoot) || r.VictimBoot == r.KeeperBoot || !hashPattern.MatchString(r.Ledger) {
		return errors.New("invalid initialized owner-cut private baseline")
	}
	return nil
}
func marshalOwnerCutReceipt(r ownerCutReceipt) ([]byte, error) {
	if e := validateOwnerCutReceipt(r); e != nil {
		return nil, e
	}
	b, e := json.Marshal(r)
	if e != nil {
		return nil, e
	}
	if len(b) > copyCutReceiptMax {
		return nil, errors.New("owner-cut receipt exceeds unchanged control scanner")
	}
	return b, nil
}
func ownerReclaimingLedger(ref sandbox.Ref) ([]byte, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	b, e := privatefile.Read("/srv/state/ledger/"+ref.ID+".json", 64<<10)
	if e != nil {
		return nil, e
	}
	var env struct {
		Version int            `json:"version"`
		Record  sandbox.Record `json:"record"`
	}
	if e = strictjson.Decode(b, &env); e != nil {
		return nil, e
	}
	r := env.Record
	if env.Version != 1 || r.Ref != ref || r.State != sandbox.Reclaiming || !r.DeleteRequested || r.StoppedAt.IsZero() || !r.DestroyedAt.IsZero() {
		return nil, errors.New("owner-cut stopped but unconfirmed reclaiming ledger required")
	}
	return b, nil
}
func (n *node) quotaOwnerCutCheckpoint(ctx context.Context) (result map[string]any, private []byte, err error) {
	if e := requireNode(); e != nil {
		return nil, nil, e
	}
	if !n.quotaSnapshot || n.quotaSwitch || n.mapper != nil || n.process != nil || n.ownerCut != nil || n.copyCut != nil {
		return nil, nil, errors.New("fresh fixed owner-cut node required")
	}
	if _, e := fixedCopyConfig(); e != nil {
		return nil, nil, e
	}
	setup, e := n.quotaSnapshotSetup(ctx)
	if e != nil {
		return nil, nil, e
	}
	obs, e := n.startOwnerObserved(ctx)
	if e != nil {
		return nil, nil, e
	}
	success := false
	defer func() {
		if !success {
			if n.process != nil {
				n.process.Process.Kill()
				select {
				case <-n.exited:
					n.process = nil
				case <-time.After(5 * time.Second):
				}
			}
			obs.close()
		}
	}()
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	defer api.close()
	r := ownerCutReceipt{copyCutReceipt: copyCutReceipt{Version: 1, Boot: n.boot}}
	cfg, e := fixedCopyConfig()
	if e != nil {
		return nil, nil, e
	}
	for i := 0; i < 2; i++ {
		key, e := randomKey()
		if e != nil {
			return nil, nil, e
		}
		record, e := api.create(ctx, key)
		if e != nil {
			return nil, nil, e
		}
		if e = actualNestedVM(record.Ref); e != nil {
			return nil, nil, e
		}
		if e = syscallGuestBoundary(cfg, record.Ref, n.process.Process.Pid); e != nil {
			return nil, nil, e
		}
		marker := "owner-keeper"
		if i == 1 {
			marker = "owner-victim"
		}
		out, e := api.executeVM(ctx, record.Ref, []string{"sh", "-c", "set -e; printf " + marker + " > cut-marker; sync; id -u; cat /proc/sys/kernel/random/boot_id"})
		if e != nil {
			return nil, nil, e
		}
		boot, e := switchGuestIdentity(out)
		if e != nil {
			return nil, nil, e
		}
		o, owner, e := copyOwner(record.Ref, true)
		if e != nil {
			return nil, nil, e
		}
		if i == 0 {
			r.Keeper, r.KeeperKey, r.KeeperBoot, r.KeeperOwner, r.Template = record.Ref, key, boot, owner, o.TemplateID
		} else {
			r.Victim, r.VictimKey, r.VictimBoot, r.VictimOwner = record.Ref, key, boot, owner
			if o.TemplateID != r.Template {
				return nil, nil, errors.New("owner-cut active template drift")
			}
		}
	}
	if e = copyPins(ctx, r.Template, 2, true); e != nil {
		return nil, nil, e
	}
	var ko, vo clearWindowOwner
	if e = strictjson.Decode(r.KeeperOwner, &ko); e != nil {
		return nil, nil, e
	}
	if e = strictjson.Decode(r.VictimOwner, &vo); e != nil {
		return nil, nil, e
	}
	// Sync the two-ready baseline BEFORE DELETE. The saved keeper tree is sampled
	// again READ ONLY after victim links are durably removed, never synchronized
	// while owner-directory fsync is pending.
	if _, e = captureCopyKeeper(r.Keeper, ko.ProjectID); e != nil {
		return nil, nil, e
	}
	for name, target := range map[string]*string{"/srv/config/backend.json": &r.Config, "/srv/export/manifest.json": &r.Manifest, "/srv/state/firecracker/catalog/index.json": &r.Index} {
		*target, e = fileHash(name)
		if e != nil {
			return nil, nil, e
		}
	}
	if e = obs.arm(r.Victim, vo.ProjectID); e != nil {
		return nil, nil, e
	}
	// DELETE202 only acknowledges intent; background cleanup is independent of
	// this HTTP request context. It is NOT a pending synchronous DELETE claim.
	if e = api.call(ctx, "DELETE", switchPath(r.Victim), "", generationBody(r.Victim), nil, 202); e != nil {
		return nil, nil, e
	}
	select {
	case <-obs.held:
	case <-obs.done:
		_, _, e := obs.snapshot()
		if e == nil {
			e = errors.New("owner observer ended before held directory fsync")
		}
		return nil, nil, e
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	// READ ONLY until outer cut: no admin status/GC (scanOwners fsyncs), q.sync,
	// syncfs, L1 receipt/config writes, or new keeper commands with ledger fsync.
	if e = obs.checkHeld(); e != nil {
		return nil, nil, e
	}
	ledger, e := ownerReclaimingLedger(r.Victim)
	if e != nil {
		return nil, nil, e
	}
	sum := sha256.Sum256(ledger)
	r.Ledger = hex.EncodeToString(sum[:])
	r.KeeperQuota, e = captureCutKeeper(r.Keeper, ko.ProjectID, false)
	if e != nil {
		return nil, nil, e
	}
	present, e := ownerCutOwners(r.copyCutReceipt)
	if e != nil {
		return nil, nil, e
	}
	if present {
		return nil, nil, errors.New("victim owner unlink not visible at fsync entry")
	}
	if e = absentClearVictim(r.Victim); e != nil {
		return nil, nil, e
	}
	qr, e := driverQuotaRead(vo.ProjectID)
	if e != nil || !quotaEmpty(qr) {
		return nil, nil, errors.New("owner-cut victim quota not fully cleared")
	}
	if e = actualNestedVM(r.Keeper); e != nil {
		return nil, nil, e
	}
	if e = ownerCutCatalogLocked(); e != nil {
		return nil, nil, e
	}
	var current sandbox.Record
	if e = api.call(ctx, "GET", switchPath(r.Victim), "", nil, &current, 200); e != nil {
		return nil, nil, e
	}
	if current.Ref != r.Victim || current.State != sandbox.Reclaiming || current.StoppedAt.IsZero() || !current.DestroyedAt.IsZero() {
		return nil, nil, errors.New("pending owner commit falsely confirmed destroyed")
	}
	if e = api.call(ctx, "POST", switchPath(r.Victim)+"/exec", "", sandbox.ExecRequest{Generation: r.Victim.Generation, Argv: []string{"true"}}, nil, 409); e != nil {
		return nil, nil, e
	}
	third, e := randomKey()
	if e != nil {
		return nil, nil, e
	}
	if e = api.call(ctx, "POST", "/v1/sandboxes", third, nodeSpec(), nil, 503); e != nil {
		return nil, nil, e
	}
	if e = obs.checkHeld(); e != nil {
		return nil, nil, e
	}
	private, e = marshalOwnerCutReceipt(r)
	if e != nil {
		return nil, nil, e
	}
	continued, _, e := obs.snapshot()
	if e != nil {
		return nil, nil, e
	}
	n.ownerCut = &ownerCutLive{observer: obs}
	success = true
	return map[string]any{"genuine_l1_snapshot_setup": setup, "two_real_initialized_guest_uids_boots_data_and_filters_checked": true, "exact_daemon_directory_fd_inode_and_post_unlink_fsync_checked": true, "victim_jail_cgroup_absent_and_quota_policy_usage_times_zero_before_owner_commit": true, "victim_owner_unlink_visible_but_directory_fsync_has_not_returned": true, "catalog_interprocess_lock_still_held_during_directory_commit": true, "ledger_and_api_reclaiming_stopped_not_destroyed_exec409_capacity503": true, "keeper_actual_kvm_domain_retained_and_post_cleanup_links_accounted": true, "keeper_post_target_guest_command_not_issued": true, "no_observer_sync_admin_or_l1_receipt_after_selected_unlink": true, "private_receipt_only_control_to_outer_l0": true, "zero_target_error_or_continue_reply_notification_wait_not_filesystem_D": true, "other_fsync_continue_reply_submissions": continued, "delete202_was_intent_only_not_a_pending_http_request": true}, private, nil
}
func (n *node) quotaOwnerCutRecover(ctx context.Context, private []byte) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.quotaSnapshot || n.quotaSwitch || n.mapper != nil || n.process != nil || n.ownerCut != nil || n.copyCut != nil || len(private) == 0 || len(private) > copyCutReceiptMax {
		return nil, errors.New("fresh fixed owner-cut recovery required")
	}
	var r ownerCutReceipt
	if e := strictjson.Decode(private, &r); e != nil {
		return nil, e
	}
	if e := validateOwnerCutReceipt(r); e != nil {
		return nil, e
	}
	if r.Boot == n.boot {
		return nil, errors.New("owner-cut host boot unchanged")
	}
	if _, e := fixedCopyConfig(); e != nil {
		return nil, e
	}
	for name, want := range map[string]string{"/srv/config/backend.json": r.Config, "/srv/export/manifest.json": r.Manifest, "/srv/state/ledger/" + r.Victim.ID + ".json": r.Ledger} {
		actual, e := fileHash(name)
		if e != nil || actual != want {
			return nil, errors.New("exact owner-cut policy/export/reclaiming ledger changed")
		}
	}
	b, e := privatefile.Read("/srv/export/manifest.json", 8192)
	if e != nil {
		return nil, e
	}
	var manifest firecracker.SnapshotManifest
	if e = strictjson.Decode(b, &manifest); e != nil {
		return nil, e
	}
	abi, e := firecracker.SnapshotHostABI()
	if e != nil || manifest.Assignment != "UNASSIGNED" || manifest.HostABI != abi {
		return nil, errors.New("owner-cut export assigned or host ABI retargeted")
	}
	if _, e = ownerReclaimingLedger(r.Victim); e != nil {
		return nil, e
	}
	present, e := ownerCutOwners(r.copyCutReceipt)
	if e != nil {
		return nil, e
	}
	for _, ref := range []sandbox.Ref{r.Keeper, r.Victim} {
		if _, e = os.Lstat(nodeGroup + "/" + ref.ID + ref.Generation); !os.IsNotExist(e) {
			return nil, errors.New("old owner-cut execution domain survived cold boot")
		}
	}
	if e = absentClearVictim(r.Victim); e != nil {
		return nil, e
	}
	var vo clearWindowOwner
	if e = strictjson.Decode(r.VictimOwner, &vo); e != nil {
		return nil, e
	}
	qr, e := driverQuotaRead(vo.ProjectID)
	if e != nil || !quotaEmpty(qr) {
		return nil, errors.New("completed quota clear lost before pending owner fsync")
	}
	qr, e = driverQuotaRead(r.KeeperQuota.Project)
	if e != nil {
		return nil, e
	}
	blocks, inodes, entries, e := driverQuotaTree(r.KeeperQuota.Jail, true)
	if e != nil {
		return nil, e
	}
	if e = validateDriverQuotaAccounting(r.KeeperQuota, qr, blocks, inodes, entries); e != nil {
		return nil, e
	}
	if e = verifySharedQuotaFiles(r.KeeperQuota.Jail); e != nil {
		return nil, e
	}
	// No fixture repair or quota setters: the ordinary unobserved daemon must
	// reconcile its ledger even when the unreturned unlink persisted.
	if e = n.finishCutRecovery(ctx, r.copyCutReceipt, r.VictimBoot); e != nil {
		return nil, e
	}
	pins := 1
	if present {
		pins = 2
	}
	return map[string]any{"l1_boot_changed": true, "exact_policy_export_abi_index_and_reclaiming_ledger_checked_before_daemon": true, "cold_victim_owner_present": present, "cold_durable_owner_pins": pins, "victim_namespace_absent_and_completed_quota_clear_remained_zero": true, "keeper_post_cleanup_full_metadata_shared_inodes_and_quota_accounted": true, "cold_known_owners_only_no_fixture_owner_restore_or_unknown_quota_adoption": true, "old_execution_domains_absent_before_daemon": true, "ordinary_unobserved_recovery_both_destroyed_resources_absent_keys410_exec409": true, "two_fresh_real_guest_uids_boots_and_workspaces_checked": true, "retired_backing_two_then_one_pin_gc_and_surviving_exec_checked": true, "last_pin_exact_gc_all_four_projects_zero_controller_reaped_parent_removed": true}, nil
}
