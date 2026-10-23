//go:build linux && xandbox_host_fixture

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

type switchSavedBinding struct {
	Binding   session.Result
	Key, Boot string
	Job       sandbox.Job
	Owner     []byte
	Quota     driverQuotaReceipt
}
type switchCrashReceipt struct {
	Version                      int
	L1Boot, ConfigHash, Template string
	Bindings                     [2]switchSavedBinding
}

func (n *node) quotaSwitchCheckpoint(ctx context.Context) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.quotaSwitch || n.process == nil {
		return nil, errors.New("active switch profile required")
	}
	info, e := os.Lstat("/srv/fixture/quota-switch-load-complete")
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("complete measured load required before crash checkpoint")
	}
	if _, e = os.Lstat(switchReceiptPath); !os.IsNotExist(e) {
		return nil, errors.New("refuse repeat switch crash checkpoint")
	}
	if e = switchAllClear(); e != nil {
		return nil, e
	}
	api := n.switchClients()
	defer api[0].close()
	defer api[1].close()
	result, e := n.switchCrashCheckpoint(ctx, api)
	if e == nil {
		result["phase"] = "quota-enabled-two-tenant-switching"
	}
	return result, e
}
func (n *node) switchCrashCheckpoint(ctx context.Context, api [2]*switchAPI) (map[string]any, error) {
	saved := switchCrashReceipt{Version: 1, L1Boot: n.boot, Template: n.switchTemplate}
	hash, e := fileHash("/srv/config/backend.json")
	if e != nil {
		return nil, e
	}
	saved.ConfigHash = hash
	for i := 0; i < 2; i++ {
		key, e := randomKey()
		if e != nil {
			return nil, e
		}
		b, e := api[i].openSession(ctx, key)
		if e != nil {
			return nil, e
		}
		out, e := api[i].sessionExec(ctx, b, switchFreshCommand())
		if e != nil {
			return nil, e
		}
		boot, e := switchGuestIdentity(out)
		if e != nil {
			return nil, e
		}
		if _, e = api[i].sessionExec(ctx, b, []string{"sh", "-c", "set -e; printf assigned > mixed-marker; sync"}); e != nil {
			return nil, e
		}
		job, e := api[i].waitBusy(ctx, b)
		if e != nil {
			return nil, e
		}
		q, e := n.switchReady(b.Current, true)
		if e != nil {
			return nil, e
		}
		_, owner, e := switchReadOwner(b.Current)
		if e != nil {
			return nil, e
		}
		saved.Bindings[i] = switchSavedBinding{Binding: b, Key: key, Boot: boot, Job: job, Owner: owner, Quota: q}
	}
	status, e := n.fixedCatalogStatus(ctx)
	if e != nil {
		return nil, e
	}
	if e = clearCatalogPins(status, n.switchTemplate, 2); e != nil {
		return nil, e
	}
	if saved.Bindings[0].Quota.Project == saved.Bindings[1].Quota.Project {
		return nil, errors.New("checkpoint sessions share private project")
	}
	for i := 0; i < 2; i++ {
		live, e := api[i].job(ctx, saved.Bindings[i].Binding.Current, saved.Bindings[i].Job)
		if e != nil || live.Status != "RUNNING" {
			return nil, errors.New("checkpoint old writers no longer running")
		}
	}
	if _, e = os.Lstat(switchReceiptPath); !os.IsNotExist(e) {
		return nil, errors.New("existing switch crash receipt")
	}
	if e = privateWrite(switchReceiptPath, saved); e != nil {
		return nil, e
	}
	return map[string]any{"real_nested_kvm": true, "checkpoint_receipt_fsynced": true, "two_live_tenant_sessions_and_running_old_jobs": true, "distinct_private_projects_with_named_inode_accounting": true, "two_active_template_pins_checked": true, "ordinary_quota_ready_owners_saved_privately": true, "checkpoint_after_measured_load_not_an_inflight_commit_fault": true}, nil
}
func verifySavedSwitchQuota(saved driverQuotaReceipt) error {
	if !saved.Snapshot || saved.Phase != "running" || saved.Project < driverProjectFirst || saved.Project >= driverProjectFirst+switchSlots {
		return errors.New("invalid saved switch quota range")
	}
	q, e := openQuotaFS(false)
	if e != nil {
		return e
	}
	r, e := switchQuotaRead(q, saved.Project)
	q.file.Close()
	if e != nil {
		return e
	}
	blocks, inodes, entries, e := driverQuotaTree(saved.Jail, true)
	if e != nil {
		return e
	}
	if e = validateDriverQuotaAccounting(saved, r, blocks, inodes, entries); e != nil {
		return e
	}
	return verifySharedQuotaFiles(saved.Jail)
}
func (n *node) quotaSwitchRecover(ctx context.Context) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.quotaSwitch || n.process != nil || n.mapper != nil {
		return nil, errors.New("fresh fixed switch recovery boot required")
	}
	b, e := privatefile.Read(switchReceiptPath, 128<<10)
	if e != nil {
		return nil, e
	}
	var saved switchCrashReceipt
	if e = strictjson.Decode(b, &saved); e != nil {
		return nil, e
	}
	if saved.Version != 1 || saved.L1Boot == "" || saved.L1Boot == n.boot || !hashPattern.MatchString(saved.Template) {
		return nil, errors.New("invalid saved switch host incarnation")
	}
	if _, e = fixedSwitchConfig(); e != nil {
		return nil, e
	}
	hash, e := fileHash("/srv/config/backend.json")
	if e != nil || hash != saved.ConfigHash {
		return nil, errors.New("switch immutable config changed across cold boot")
	}
	// Never relabel/export an assigned clone or restore its old execution.
	mb, e := privatefile.Read("/srv/export/manifest.json", 8192)
	if e != nil {
		return nil, e
	}
	var manifest firecracker.SnapshotManifest
	if e = strictjson.Decode(mb, &manifest); e != nil {
		return nil, e
	}
	abi, e := firecracker.SnapshotHostABI()
	if e != nil || manifest.Assignment != "UNASSIGNED" || manifest.HostABI != abi {
		return nil, errors.New("L1 pristine export ABI/assignment changed")
	}
	n.switchTemplate = saved.Template
	for i := 0; i < 2; i++ {
		old := saved.Bindings[i]
		if !switchRefValid(old.Binding.Current) || !hex32Pattern(old.Binding.ID) || len(old.Key) != 64 || strings.Trim(old.Key, "0123456789abcdef") != "" || old.Boot == "" || old.Job.Ref != old.Binding.Current || !hex32Pattern(old.Job.ID) {
			return nil, errors.New("invalid private switch binding receipt")
		}
		owner, b, e := switchReadOwner(old.Binding.Current)
		if e != nil || !bytes.Equal(b, old.Owner) || owner.TemplateID != saved.Template || old.Quota.Project != owner.ProjectID || old.Quota.Jail != "/srv/r/j/firecracker/"+old.Binding.Current.ID+old.Binding.Current.Generation {
			return nil, errors.New("cold switch durable owner or private namespace changed")
		}
		if _, e = os.Lstat(nodeGroup + "/" + old.Binding.Current.ID + old.Binding.Current.Generation); !os.IsNotExist(e) {
			return nil, errors.New("old execution domain survived L1 cold boot")
		}
		if e = verifySavedSwitchQuota(old.Quota); e != nil {
			return nil, e
		}
	}
	status, e := n.fixedCatalogStatus(ctx)
	if e != nil {
		return nil, e
	}
	if e = clearCatalogPins(status, saved.Template, 2); e != nil {
		return nil, e
	}
	if e = n.start(ctx); e != nil {
		return nil, e
	}
	api := n.switchClients()
	defer api[0].close()
	defer api[1].close()
	for i := 0; i < 2; i++ {
		old := saved.Bindings[i]
		if e = api[i].destroyed(ctx, old.Binding.Current); e != nil {
			return nil, e
		}
		var view struct {
			Phase      string `json:"phase"`
			HasBinding bool   `json:"has_binding"`
		}
		if e = api[i].call(ctx, "GET", "/v1/sessions/"+old.Binding.ID, "", nil, &view, 200); e != nil {
			return nil, e
		}
		if view.Phase != "CLOSED" || view.HasBinding {
			return nil, errors.New("old session binding restored after cold boot")
		}
		if e = api[i].call(ctx, "POST", "/v1/sessions/"+old.Binding.ID+"/exec", "", map[string]any{"revision": old.Binding.Revision, "argv": []string{"true"}}, nil, 410); e != nil {
			return nil, e
		}
		if e = api[i].call(ctx, "POST", "/v1/sessions", old.Key, switchGuestSpec(), nil, 410); e != nil {
			return nil, e
		}
		if e = api[i].call(ctx, "GET", switchPath(old.Binding.Current)+"/executions/"+old.Job.ID, "", nil, nil, 404); e != nil {
			return nil, e
		}
	}
	if e = switchAllClear(); e != nil {
		return nil, e
	}
	status, e = n.fixedCatalogStatus(ctx)
	if e != nil {
		return nil, e
	}
	if e = clearCatalogPins(status, saved.Template, 0); e != nil {
		return nil, e
	}
	fresh := [2]session.Result{}
	for i := 0; i < 2; i++ {
		key, e := randomKey()
		if e != nil {
			return nil, e
		}
		fresh[i], e = api[i].openSession(ctx, key)
		if e != nil {
			return nil, e
		}
		if fresh[i].Current == saved.Bindings[i].Binding.Current {
			return nil, errors.New("old switch reference reused")
		}
		out, e := api[i].sessionExec(ctx, fresh[i], switchFreshCommand())
		if e != nil {
			return nil, e
		}
		boot, e := switchGuestIdentity(out)
		if e != nil || boot == saved.Bindings[i].Boot {
			return nil, errors.New("old assigned guest restored after switch host crash")
		}
		if _, e = n.switchReady(fresh[i].Current, true); e != nil {
			return nil, e
		}
	}
	for i := 0; i < 2; i++ {
		if e = api[i].revoke(ctx, fresh[i]); e != nil {
			return nil, e
		}
	}
	if e = switchAllClear(); e != nil {
		return nil, e
	}
	status, e = n.fixedCatalogStatus(ctx)
	if e != nil {
		return nil, e
	}
	if e = clearCatalogPins(status, saved.Template, 0); e != nil {
		return nil, e
	}
	if e = n.process.Process.Signal(os.Interrupt); e != nil {
		return nil, e
	}
	select {
	case e = <-n.exited:
		if e != nil {
			return nil, e
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	n.process = nil
	groups, e := os.ReadDir(nodeGroup)
	if e != nil {
		return nil, e
	}
	for _, d := range groups {
		if d.IsDir() {
			return nil, errors.New("switch recovery left a generation cgroup")
		}
	}
	if e = os.Remove(nodeGroup); e != nil {
		return nil, e
	}
	return map[string]any{"phase": "quota-enabled-two-tenant-switching", "l1_boot_changed": true, "two_exact_owners_policy_shared_backing_and_independent_quota_checked_before_daemon": true, "two_old_execution_domains_absent": true, "two_pins_retained_before_ordinary_recovery": true, "old_sessions_closed_exec_and_create_keys410_no_old_job_resume": true, "both_old_generations_destroyed_resources_absent": true, "two_fresh_real_kvm_guest_uids_workspaces_and_boots_checked": true, "all_eight_project_records_zero_and_active_template_pins_zero": true, "controller_reaped_and_owned_cgroup_root_removed": true, "no_assigned_guest_restored_or_exported": true}, nil
}
