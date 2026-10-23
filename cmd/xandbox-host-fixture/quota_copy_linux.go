//go:build linux && xandbox_host_fixture

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

func copyAdmin(ctx context.Context, args ...string) ([]byte, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	a := append([]string{"-state-dir", "/srv/state", "-config", "/srv/config/backend.json"}, args...)
	c := exec.CommandContext(ctx, "/srv/assets/admin", a...)
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	c.Stderr = os.Stderr
	var b bytes.Buffer
	c.Stdout = &b
	if e := c.Run(); e != nil {
		return nil, e
	}
	if b.Len() > 8192 {
		return nil, errors.New("bounded copy admin reply exceeded")
	}
	return b.Bytes(), nil
}
func copyPins(ctx context.Context, id string, count int, active bool) error {
	b, e := copyAdmin(ctx, "status")
	if e != nil {
		return e
	}
	var status firecracker.CatalogStatus
	if e = strictjson.Decode(b, &status); e != nil {
		return e
	}
	if active && status.Active != id {
		return errors.New("copy active template mismatch")
	}
	for _, item := range status.Items {
		if item.ID == id {
			if item.Pins != count || active && item.Phase != "AVAILABLE" || !active && item.Phase != "RETIRING" {
				return errors.New("copy exact pin/phase mismatch")
			}
			return nil
		}
	}
	return errors.New("copy owned template missing")
}
func copyGC(ctx context.Context, id string, want int) error {
	b, e := copyAdmin(ctx, "gc")
	if e != nil {
		return e
	}
	var out struct {
		Removed []string `json:"removed"`
	}
	if e = strictjson.Decode(b, &out); e != nil {
		return e
	}
	if len(out.Removed) != want || want == 1 && out.Removed[0] != id {
		return errors.New("copy keeper GC mismatch")
	}
	return nil
}
func copyOwner(ref sandbox.Ref, initialized bool) (clearWindowOwner, []byte, error) {
	var out clearWindowOwner
	b, e := clearOwnerBytes(ref)
	if e != nil {
		return out, nil, e
	}
	if e = strictjson.Decode(b, &out); e != nil {
		return out, nil, e
	}
	if out.Ref != ref || out.Version != 4 || !out.QuotaAttempted || out.InitializationAttempted != initialized || out.UID < 400000 || out.UID >= 400004 || out.ProjectID != driverProjectFirst+uint32(out.UID-400000) || !hashPattern.MatchString(out.TemplateID) {
		return out, nil, errors.New("copy durable owner mismatch")
	}
	return out, b, nil
}
func copyRepublish(ctx context.Context, old string) (string, error) {
	b, e := os.ReadFile("/srv/export/manifest.json")
	if e != nil {
		return "", e
	}
	var m firecracker.SnapshotManifest
	if e = strictjson.Decode(b, &m); e != nil {
		return "", e
	}
	abi, e := firecracker.SnapshotHostABI()
	if e != nil || m.Assignment != "UNASSIGNED" || m.HostABI != abi {
		return "", errors.New("copy may republish only genuine never-assigned export")
	}
	m.CreatedAt = time.Now().UTC()
	if e = privateWrite("/srv/fixture/copy-republish-manifest.json", m); e != nil {
		return "", e
	}
	b, e = copyAdmin(ctx, "-manifest", "/srv/fixture/copy-republish-manifest.json", "-memory", "/srv/export/memory", "-snapshot-state", "/srv/export/state", "publish")
	if e != nil {
		return "", e
	}
	var out struct {
		ID string `json:"template_id"`
	}
	if e = strictjson.Decode(b, &out); e != nil {
		return "", e
	}
	if !hashPattern.MatchString(out.ID) || out.ID == old {
		return "", errors.New("copy retired template reused")
	}
	_, e = copyAdmin(ctx, "activate", out.ID)
	return out.ID, e
}
func (n *node) quotaCopySetup(ctx context.Context) (result map[string]any, err error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.quotaSnapshot || n.quotaSwitch || n.mapper != nil || n.process != nil {
		return nil, errors.New("fresh fixed partial-copy profile required")
	}
	cfg, e := fixedCopyConfig()
	if e != nil {
		return nil, e
	}
	setup, e := n.quotaSnapshotSetup(ctx)
	if e != nil {
		return nil, e
	}
	obs, e := n.startCopyObserved(ctx)
	if e != nil {
		return nil, e
	}
	// Failure cleanup is restricted to this exact child and our isolated outer
	// fixture scope. Success below separately proves ordinary per-generation GC.
	defer func() {
		if n.process != nil {
			n.process.Process.Kill()
			select {
			case <-n.exited:
				n.process = nil
			case <-time.After(5 * time.Second):
			}
		}
		if closeErr := obs.close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	defer api.close()
	keeperKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	keeper, e := api.create(ctx, keeperKey)
	if e != nil {
		return nil, e
	}
	if e = actualNestedVM(keeper.Ref); e != nil {
		return nil, e
	}
	if e = syscallGuestBoundary(cfg, keeper.Ref, n.process.Process.Pid); e != nil {
		return nil, e
	}
	out, e := api.executeVM(ctx, keeper.Ref, []string{"sh", "-c", "set -e; printf copy-keeper > copy-marker; sync; id -u; cat /proc/sys/kernel/random/boot_id"})
	if e != nil {
		return nil, e
	}
	keeperBoot, e := switchGuestIdentity(out)
	if e != nil {
		return nil, e
	}
	ko, _, e := copyOwner(keeper.Ref, true)
	if e != nil {
		return nil, e
	}
	if e = copyPins(ctx, ko.TemplateID, 1, true); e != nil {
		return nil, e
	}
	key, e := randomKey()
	if e != nil {
		return nil, e
	}
	obs.arm()
	requestDone := make(chan error, 1)
	go func() { requestDone <- api.call(ctx, "POST", "/v1/sandboxes", key, nodeSpec(), nil, 500) }()
	var boundary copyBoundary
	select {
	case boundary = <-obs.held:
	case e = <-requestDone:
		if _, _, observedError := obs.snapshot(); observedError != nil {
			return nil, observedError
		}
		if e == nil {
			e = errors.New("create500 before actual partial-copy boundary")
		}
		return nil, e
	case <-obs.done:
		_, _, e = obs.snapshot()
		if e == nil {
			e = errors.New("copy observer exited before prefix")
		}
		return nil, e
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	victim, owner, e := copyOwner(boundary.Ref, false)
	if e != nil || !bytes.Equal(owner, boundary.Owner) || victim.TemplateID != ko.TemplateID || victim.ProjectID == ko.ProjectID {
		return nil, errors.New("partial copy crossed owner/template boundary")
	}
	var record sandbox.Record
	if e = api.call(ctx, "GET", switchPath(boundary.Ref), "", nil, &record, 200); e != nil {
		return nil, e
	}
	if record.Ref != boundary.Ref || record.State != sandbox.Creating || record.DeleteRequested {
		return nil, errors.New("partial copy not durably preparing")
	}
	ledger, e := privatefile.Read("/srv/state/ledger/"+boundary.Ref.ID+".json", 64<<10)
	if e != nil {
		return nil, e
	}
	var envelope struct {
		Version int            `json:"version"`
		Record  sandbox.Record `json:"record"`
	}
	if e = strictjson.Decode(ledger, &envelope); e != nil {
		return nil, e
	}
	if envelope.Version != 1 || envelope.Record.Ref != boundary.Ref || envelope.Record.TenantID != "nested-fixture" || envelope.Record.State != sandbox.Creating || envelope.Record.DeleteRequested || !envelope.Record.StoppedAt.IsZero() || !envelope.Record.DestroyedAt.IsZero() {
		return nil, errors.New("partial-copy atomic durable ledger is not CREATING")
	}
	fmt.Fprintf(os.Stderr, "private partial-copy stable boundary size=%d allocated=%d inodes=%d\n", boundary.Size, boundary.Space, boundary.Inodes)

	if e = api.call(ctx, "POST", switchPath(boundary.Ref)+"/exec", "", sandbox.ExecRequest{Generation: boundary.Ref.Generation, Argv: []string{"true"}}, nil, 409); e != nil {
		return nil, e
	}
	third, e := randomKey()
	if e != nil {
		return nil, e
	}
	if e = api.call(ctx, "POST", "/v1/sandboxes", third, nodeSpec(), nil, 503); e != nil {
		return nil, e
	}
	if e = copyPins(ctx, ko.TemplateID, 2, true); e != nil {
		return nil, e
	}
	if _, e = copyAdmin(ctx, "retire", ko.TemplateID); e != nil {
		return nil, e
	}
	if e = copyPins(ctx, ko.TemplateID, 2, false); e != nil {
		return nil, e
	}
	if e = copyGC(ctx, ko.TemplateID, 0); e != nil {
		return nil, e
	}
	if _, e = api.executeVM(ctx, keeper.Ref, []string{"sh", "-c", "set -e; test $(cat copy-marker) = copy-keeper"}); e != nil {
		return nil, e
	}
	select {
	case <-requestDone:
		return nil, errors.New("partial copy completed before fixed error reply")
	default:
	}
	close(obs.release)
	select {
	case e = <-requestDone:
		if e != nil {
			return nil, e
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if e = waitNode(ctx, func() (bool, error) { injected, _, err := obs.snapshot(); return injected == 1, err }); e != nil {
		return nil, e
	}
	injected, _, notifyErr := obs.snapshot()
	if notifyErr != nil || injected != 1 {
		return nil, errors.New("exactly one fixed write error required")
	}
	log, e := os.Open("/srv/fixture/copy-controller.log")
	if e != nil {
		return nil, e
	}
	b, e := io.ReadAll(io.LimitReader(log, 32769))
	log.Close()
	if e != nil || len(b) > 32768 || !bytes.Contains(b, []byte("input/output error")) {
		return nil, errors.New("ordinary private Prepare EIO diagnostic absent")
	}
	if e = api.destroyed(ctx, boundary.Ref); e != nil {
		return nil, e
	}
	qr, e := driverQuotaRead(victim.ProjectID)
	if e != nil || !quotaEmpty(qr) {
		return nil, errors.New("partial victim quota not cleared before slot reuse")
	}
	if e = api.call(ctx, "POST", "/v1/sandboxes", key, nodeSpec(), nil, 410); e != nil {
		return nil, e
	}
	if e = copyPins(ctx, ko.TemplateID, 1, false); e != nil {
		return nil, e
	}
	if e = copyGC(ctx, ko.TemplateID, 0); e != nil {
		return nil, e
	}
	out, e = api.executeVM(ctx, keeper.Ref, []string{"sh", "-c", "set -e; test $(cat copy-marker) = copy-keeper; id -u; cat /proc/sys/kernel/random/boot_id"})
	if e != nil {
		return nil, e
	}
	boot, e := switchGuestIdentity(out)
	if e != nil || boot != keeperBoot {
		return nil, errors.New("copy keeper was replaced or lost data")
	}
	if e = verifySharedQuotaFiles("/srv/r/j/firecracker/" + keeper.ID + keeper.Generation); e != nil {
		return nil, e
	}
	next, e := copyRepublish(ctx, ko.TemplateID)
	if e != nil {
		return nil, e
	}
	freshKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	fresh, e := api.create(ctx, freshKey)
	if e != nil {
		return nil, e
	}
	fo, _, e := copyOwner(fresh.Ref, true)
	if e != nil || fo.UID != victim.UID || fo.ProjectID != victim.ProjectID || fo.TemplateID != next || fresh.Ref == boundary.Ref {
		return nil, errors.New("copy cleared slot not reused with fresh ownership")
	}
	if e = actualNestedVM(fresh.Ref); e != nil {
		return nil, e
	}
	if e = syscallGuestBoundary(cfg, fresh.Ref, n.process.Process.Pid); e != nil {
		return nil, e
	}
	out, e = api.executeVM(ctx, fresh.Ref, []string{"sh", "-c", "set -e; test ! -e copy-marker; id -u; cat /proc/sys/kernel/random/boot_id"})
	if e != nil {
		return nil, e
	}
	freshBoot, identityErr := switchGuestIdentity(out)
	if identityErr != nil || freshBoot == keeperBoot {
		return nil, errors.New("fresh copy slot restored a used guest identity")
	}
	if e = copyPins(ctx, next, 1, true); e != nil {
		return nil, e
	}
	if e = copyPins(ctx, ko.TemplateID, 1, false); e != nil {
		return nil, e
	}
	if e = api.remove(ctx, fresh.Ref); e != nil {
		return nil, e
	}
	if e = copyGC(ctx, ko.TemplateID, 0); e != nil {
		return nil, e
	}
	if e = api.remove(ctx, keeper.Ref); e != nil {
		return nil, e
	}
	if e = copyPins(ctx, ko.TemplateID, 0, false); e != nil {
		return nil, e
	}
	if e = copyGC(ctx, ko.TemplateID, 1); e != nil {
		return nil, e
	}
	if e = driverQuotaAllClear(); e != nil {
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
		n.process = nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if e = os.Remove(nodeGroup); e != nil {
		return nil, e
	}
	injected, continued, e := obs.snapshot()
	if e != nil || injected != 1 || continued < 256 {
		return nil, errors.New("copy continuation/error proof incomplete")
	}
	return map[string]any{"genuine_l1_snapshot_setup": setup, "partial_copy": map[string]any{
		"test_only_write_errno_not_physical_eio": true, "partial_workspace_bytes": boundary.Size, "partial_project_space_bytes": boundary.Space, "partial_project_inodes": boundary.Inodes, "fixed_write_error_replies": injected, "real_kernel_write_continue_replies": continued,
		"exact_child_thread_fd_owner_and_project_checked": true, "actual_positive_partial_prefix_before_shared_links_and_vmm_birth": true, "healthy_observer_sync_for_stable_prefix_not_latency_measurement": true, "independent_named_inode_quota_accounting": true, "durable_creating_and_exec409_and_capacity503_while_held": true, "retired_template_pins_two_and_gc_zero_at_partial_boundary": true, "live_keeper_data_and_execution_survived": true, "ordinary_prepare500_and_private_eio_diagnostic_checked": true, "victim_destroyed_resources_absent_quota_zero_key410": true, "same_uid_project_reused_only_after_clear_with_new_ref_template_and_clean_guest": true, "new_declaration_only_from_never_assigned_export": true, "retired_backing_survived_until_last_keeper_release": true, "last_pin_gc_removed_exact_old_template": true, "all_four_project_records_zero_controller_reaped_parent_removed": true,
	}}, nil
}
