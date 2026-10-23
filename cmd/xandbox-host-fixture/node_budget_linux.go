//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: a separately bounded 8GiB/12GiB/CPU8 node, not an enlargement of
// previous profiles. Only our L1 PID1 configures these disposable cgroups.
import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const nodeBudgetInstances = nodeGroup + "/instances"

func budgetPolicy() firecracker.NodePolicy {
	return firecracker.NodePolicy{Version: 1, CgroupRoot: nodeGroup, MaxInstances: 4, MaxRecords: 1024, MaxSessions: 32, PrepareWorkers: 1, MemoryMax: 7 << 30, ControllerMemoryMax: 1 << 30, HostMemoryReserve: 512 << 20, PidsMax: 384, ControllerPidsMax: 128, CPUQuota: 800000, IOBytesPerSecond: 256 << 20, IOOperationsPerSecond: 8192, DiskBytes: 10 << 30, DiskInodes: 100000, ExternalDiskBytes: 2 << 30, ExternalInodes: 2048, MinFreeBytes: 256 << 20, MinFreeInodes: 2048}
}
func fixedBudgetConfig() (firecracker.Config, error) {
	var c firecracker.Config
	b, e := privatefile.Read("/srv/config/backend.json", 16384)
	if e != nil {
		return c, e
	}
	if e = strictjson.Decode(b, &c); e != nil {
		return c, e
	}
	if c.Version != 3 || c.RuntimeRoot != "/srv/r" || c.CgroupRoot != nodeBudgetInstances || c.UIDStart != 400000 || c.UIDCount != 4 || !c.ReservedUIDRange || c.Snapshot != nil || c.Quota == nil || c.Quota.ProjectStart != driverProjectFirst || c.Quota.MaxBytes != 192<<20 || c.Quota.MaxInodes != 128 || c.IO == nil || c.IO.Version != 1 || c.IO.BytesPerSecond != 16<<20 || c.IO.OperationsPerSecond != 1024 || c.Node == nil || *c.Node != budgetPolicy() {
		return c, errors.New("fixed full node policy required")
	}
	return c, nil
}
func (n *node) initializeNodeBudget() error {
	if e := requireNode(); e != nil {
		return e
	}
	if !n.nodeBudget || !n.quotaDriver || n.quotaSnapshot || n.mapper != nil {
		return errors.New("fixed budget L1 required")
	}
	c, e := fixedBudgetConfig()
	if e != nil {
		return e
	}
	return n.initializeBudgetCgroups(c)
}
func (n *node) initializeBudgetCgroups(c firecracker.Config) error {
	if e := requireNode(); e != nil {
		return e
	}
	var e error
	var st unix.Stat_t
	if e = unix.Lstat("/dev/vda", &st); e != nil || st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return errors.New("own fixed budget disk required")
	}
	dev := fmt.Sprintf("%d:%d", unix.Major(st.Rdev), unix.Minor(st.Rdev))
	if c.IO.FilesystemDevice != dev || c.IO.Device != dev {
		if _, e = os.Lstat("/srv/state/firecracker/config.json"); !os.IsNotExist(e) {
			return errors.New("budget IO locator cannot change after binding")
		}
		// Actual L1 queue is bound BEFORE the first daemon/registry, not retargeted
		// from an L0 device or changed on cold recovery.
		c.IO.FilesystemDevice, c.IO.Device = dev, dev
		if e = privateWrite("/srv/config/backend.json", c); e != nil {
			return e
		}
	}
	for _, root := range []string{"/sys/fs/cgroup", nodeGroup} {
		if e = os.WriteFile(root+"/cgroup.subtree_control", []byte("+memory +pids +cpu +io"), 0); e != nil {
			return e
		}
	}
	for _, path := range []string{nodeGroup + "/control", nodeBudgetInstances} {
		if e = os.Mkdir(path, 0700); e != nil && !os.IsExist(e) {
			return e
		}
	}
	if e = os.WriteFile(nodeBudgetInstances+"/cgroup.subtree_control", []byte("+memory +pids +cpu +io"), 0); e != nil {
		return e
	}
	p := budgetPolicy()
	for path, value := range map[string]string{nodeGroup + "/memory.max": strconv.FormatUint(p.MemoryMax, 10), nodeGroup + "/memory.swap.max": "0", nodeGroup + "/pids.max": strconv.FormatUint(p.PidsMax, 10), nodeGroup + "/cpu.max": "800000 100000", nodeGroup + "/io.max": fmt.Sprintf("%s rbps=%d wbps=%d riops=%d wiops=%d", dev, p.IOBytesPerSecond, p.IOBytesPerSecond, p.IOOperationsPerSecond, p.IOOperationsPerSecond), nodeGroup + "/control/memory.max": strconv.FormatUint(p.ControllerMemoryMax, 10), nodeGroup + "/control/memory.swap.max": "0", nodeGroup + "/control/memory.oom.group": "1", nodeGroup + "/control/pids.max": strconv.FormatUint(p.ControllerPidsMax, 10)} {
		if e = os.WriteFile(path, []byte(value), 0); e != nil {
			return e
		}
	}
	return nil
}
func runNodeBudgetDaemon(bad bool) error {
	if e := requireQuotaChild(); e != nil {
		return e
	}
	if _, e := fixedBudgetConfig(); e != nil {
		return e
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, unix.CAP_SYS_RESOURCE, 0); e != 0 {
		return e
	}
	count := "4"
	if bad {
		count = "5"
	}
	return unix.Exec("/srv/assets/sandboxd", []string{"sandboxd", "-backend", "firecracker", "-state-dir", "/srv/state", "-auth-file", "/srv/config/auth.json", "-firecracker-config", "/srv/config/backend.json", "-max-instances", count, "-max-records", "1024", "-max-sessions", "32", "-metrics"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
}
func budgetVM(ref sandbox.Ref) error {
	if e := requireNode(); e != nil {
		return e
	}
	if !switchRefValid(ref) {
		return errors.New("budget ref invalid")
	}
	b, e := os.ReadFile(nodeBudgetInstances + "/" + ref.ID + ref.Generation + "/cgroup.procs")
	if e != nil {
		return e
	}
	for _, pid := range strings.Fields(string(b)) {
		fds, e := os.ReadDir("/proc/" + pid + "/fd")
		if e != nil {
			return e
		}
		for _, fd := range fds {
			target, _ := os.Readlink("/proc/" + pid + "/fd/" + fd.Name())
			if strings.Contains(target, "kvm-vm") {
				return nil
			}
		}
	}
	return errors.New("budget instance lacks actual KVM descriptor")
}
func budgetOwner(ref sandbox.Ref) (clearWindowOwner, []byte, error) {
	if e := requireNode(); e != nil {
		return clearWindowOwner{}, nil, e
	}
	if !switchRefValid(ref) {
		return clearWindowOwner{}, nil, errors.New("invalid fixed budget owner ref")
	}
	var o clearWindowOwner
	b, e := clearOwnerBytes(ref)
	if e != nil {
		return o, nil, e
	}
	if e = strictjson.Decode(b, &o); e != nil {
		return o, nil, e
	}
	if o.Version != 3 || o.Ref != ref || !o.QuotaAttempted || o.InitializationAttempted || o.TemplateID != "" || o.UID < 400000 || o.UID >= 400004 || o.ProjectID != driverProjectFirst+uint32(o.UID-400000) {
		return o, nil, errors.New("budget owner invalid")
	}
	return o, b, nil
}
func budgetAbsent(ref sandbox.Ref) error {
	if e := requireNode(); e != nil {
		return e
	}
	if !switchRefValid(ref) {
		return errors.New("invalid budget cleanup ref")
	}
	for _, path := range []string{nodeBudgetInstances + "/" + ref.ID + ref.Generation, "/srv/r/j/firecracker/" + ref.ID + ref.Generation, "/srv/state/firecracker/" + ref.ID + ref.Generation + ".json"} {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			return errors.New("budget generation resources retained")
		}
	}
	return nil
}
func budgetDestroyed(ctx context.Context, api *switchAPI, ref sandbox.Ref) error {
	if e := waitNode(ctx, func() (bool, error) {
		var r sandbox.Record
		e := api.call(ctx, "GET", switchPath(ref), "", nil, &r, 200)
		return e == nil && r.Ref == ref && r.State == sandbox.Destroyed, e
	}); e != nil {
		return e
	}
	return budgetAbsent(ref)
}
func (n *node) budgetNegative(ctx context.Context, badLimits bool) error {
	if e := requireNode(); e != nil {
		return e
	}
	mode := "node-budget-daemon"
	if badLimits {
		mode = "node-budget-bad-limits"
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/xandbox-host-fixture", "-mode", mode)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if badLimits {
		cg, e := os.Open(nodeGroup + "/control")
		if e != nil {
			return e
		}
		defer cg.Close()
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	e := cmd.Run()
	if e == nil || output.Len() > 16384 {
		return errors.New("invalid budget startup was accepted or diagnostic unbounded")
	}
	want := "controller/publisher must be inside node control subtree"
	if badLimits {
		want = "frontend admission differs from immutable node policy"
	}
	if !strings.Contains(output.String(), want) {
		fmt.Fprintln(os.Stderr, "private budget negative diagnostic", output.String())
		return errors.New("specific node rejection not observed")
	}
	for _, path := range []string{"/srv/state/api.sock", "/srv/state/firecracker/config.json"} {
		if _, e = os.Lstat(path); !os.IsNotExist(e) {
			return errors.New("rejected budget start created API or binding")
		}
	}
	return nil
}

type budgetCheckpoint struct {
	Node   nodeReceipt
	Owner  []byte
	Config string
	Quota  driverQuotaReceipt
}

func (n *node) nodeBudgetCheckpoint(ctx context.Context) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.nodeBudget || n.process != nil {
		return nil, errors.New("fresh fixed node budget required")
	}
	if e := n.budgetNegative(ctx, true); e != nil {
		return nil, e
	}
	if e := n.budgetNegative(ctx, false); e != nil {
		return nil, e
	}
	if e := n.start(ctx); e != nil {
		return nil, e
	}
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	defer api.close()
	cfg, e := fixedBudgetConfig()
	if e != nil {
		return nil, e
	}
	records := make([]sandbox.Record, 0, 4)
	for i := 0; i < 4; i++ {
		key, e := randomKey()
		if e != nil {
			return nil, e
		}
		r, e := api.create(ctx, key)
		if e != nil {
			return nil, e
		}
		if e = budgetVM(r.Ref); e != nil {
			return nil, e
		}
		if e = syscallGuestBoundaryWithObserver(cfg, r.Ref, n.process.Process.Pid, false); e != nil {
			return nil, e
		}
		out, e := api.executeVM(ctx, r.Ref, []string{"sh", "-c", "set -e; test ! -e budget-marker; printf budget > budget-marker; dd if=/dev/zero of=/tmp/budget-memory bs=1048576 count=8 2>/dev/null; sync; id -u; cat /proc/sys/kernel/random/boot_id"})
		if e != nil {
			return nil, e
		}
		if _, e = switchGuestIdentity(out); e != nil {
			return nil, e
		}
		records = append(records, r)
	}
	key, e := randomKey()
	if e != nil {
		return nil, e
	}
	if e = api.call(ctx, "POST", "/v1/sandboxes", key, nodeSpec(), nil, 503); e != nil {
		return nil, e
	}
	first, _, e := budgetOwner(records[0].Ref)
	if e != nil {
		return nil, e
	}
	if e = api.call(ctx, "DELETE", switchPath(records[0].Ref), "", generationBody(records[0].Ref), nil, 202); e != nil {
		return nil, e
	}
	if e = budgetDestroyed(ctx, api, records[0].Ref); e != nil {
		return nil, e
	}
	q, e := driverQuotaRead(first.ProjectID)
	if e != nil || !quotaEmpty(q) {
		return nil, errors.New("budget first slot not reclaimed")
	}
	// Tighten by4KiB, but never below actual use: this tests immutable readback
	// drift, not OOM killing or a larger silently accepted envelope.
	current, e := os.ReadFile(nodeGroup + "/memory.current")
	if e != nil {
		return nil, e
	}
	used, e := strconv.ParseUint(strings.TrimSpace(string(current)), 10, 64)
	if e != nil || used+256<<20 >= cfg.Node.MemoryMax-4096 {
		return nil, errors.New("no safe drift-test memory headroom")
	}
	if e = os.WriteFile(nodeGroup+"/memory.max", []byte(strconv.FormatUint(cfg.Node.MemoryMax-4096, 10)), 0); e != nil {
		return nil, e
	}
	pressureKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	if e = api.call(ctx, "POST", "/v1/sandboxes", pressureKey, nodeSpec(), nil, 500); e != nil {
		return nil, e
	}
	// Cleanup/Stop are never behind the new preparation gate or budget recheck.
	second, _, e := budgetOwner(records[1].Ref)
	if e != nil {
		return nil, e
	}
	if e = api.call(ctx, "DELETE", switchPath(records[1].Ref), "", generationBody(records[1].Ref), nil, 202); e != nil {
		return nil, e
	}
	if e = budgetDestroyed(ctx, api, records[1].Ref); e != nil {
		return nil, e
	}
	q, e = driverQuotaRead(second.ProjectID)
	if e != nil || !quotaEmpty(q) {
		return nil, errors.New("cleanup blocked behind budget drift")
	}
	if _, e = api.executeVM(ctx, records[2].Ref, []string{"true"}); e != nil {
		return nil, e
	}
	if e = os.WriteFile(nodeGroup+"/memory.max", []byte(strconv.FormatUint(cfg.Node.MemoryMax, 10)), 0); e != nil {
		return nil, e
	}
	if e = waitNode(ctx, func() (bool, error) {
		e := api.call(ctx, "POST", "/v1/sandboxes", pressureKey, nodeSpec(), nil, 410)
		return e == nil, nil
	}); e != nil {
		return nil, e
	}
	for _, r := range records[2:] {
		if e = api.call(ctx, "DELETE", switchPath(r.Ref), "", generationBody(r.Ref), nil, 202); e != nil {
			return nil, e
		}
		if e = budgetDestroyed(ctx, api, r.Ref); e != nil {
			return nil, e
		}
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	key, e = randomKey()
	if e != nil {
		return nil, e
	}
	live, e := api.create(ctx, key)
	if e != nil {
		return nil, e
	}
	if e = budgetVM(live.Ref); e != nil {
		return nil, e
	}
	out, e := api.executeVM(ctx, live.Ref, []string{"sh", "-c", "set -e; test ! -e budget-marker; printf fresh-budget > budget-marker; sync; id -u; cat /proc/sys/kernel/random/boot_id"})
	if e != nil {
		return nil, e
	}
	boot, e := switchGuestIdentity(out)
	if e != nil {
		return nil, e
	}
	owner, raw, e := budgetOwner(live.Ref)
	if e != nil {
		return nil, e
	}
	fs, e := openQuotaFS(false)
	if e != nil {
		return nil, e
	}
	defer fs.file.Close()
	if e = fs.sync(); e != nil {
		return nil, e
	}
	if e = unix.Syncfs(int(fs.file.Fd())); e != nil {
		return nil, e
	}
	qr, e := driverQuotaRead(owner.ProjectID)
	if e != nil {
		return nil, e
	}
	jail := "/srv/r/j/firecracker/" + live.ID + live.Generation
	blocks, inodes, entries, e := driverQuotaTree(jail, false)
	if e != nil {
		return nil, e
	}
	receipt := budgetCheckpoint{Node: nodeReceipt{Phase: "node-envelope-healthy-checkpoint", Ref: live.Ref, Key: key, L1Boot: n.boot, L2Boot: boot}, Owner: raw, Quota: driverQuotaReceipt{Phase: "running", Jail: jail, Project: owner.ProjectID, Record: qr, NamespaceBlocks: blocks, NamespaceInodes: inodes, Entries: entries}}
	if e = validateDriverQuotaAccounting(receipt.Quota, qr, blocks, inodes, entries); e != nil {
		return nil, e
	}
	receipt.Config, e = fileHash("/srv/config/backend.json")
	if e != nil {
		return nil, e
	}
	if e = privateWrite("/srv/fixture/node-budget-receipt.json", receipt); e != nil {
		return nil, e
	}
	return map[string]any{"real_nested_kvm": true, "checkpoint_receipt_fsynced": true, "node_schema3_exact_frontend_counts_and_parent_control_placement_enforced": true, "wrong_limits_and_wrong_control_subtree_rejected_before_binding_and_api": true, "four_simultaneous_actual_kvm_guests_uid_data_and_filters_checked": true, "fifth_create503_then_full_quota_reclaim_checked": true, "parent_limit_drift_refused_new_preparation_without_fallback": true, "stop_cleanup_and_existing_exec_continue_during_stricter_parent_drift": true, "failed_prepare_key410_and_same_policy_restored_before_fresh_guest": true, "healthy_synced_checkpoint_not_inflight_metadata_fault": true, "guest_memory_touched_bytes_each": 8 << 20, "node_memory_max_bytes": cfg.Node.MemoryMax, "controller_memory_max_bytes": cfg.Node.ControllerMemoryMax, "node_cpu_quota_us": cfg.Node.CPUQuota, "node_pids_max": cfg.Node.PidsMax, "prepare_workers": cfg.Node.PrepareWorkers, "node_io_bytes_per_second": cfg.Node.IOBytesPerSecond, "node_io_operations_per_second": cfg.Node.IOOperationsPerSecond}, nil
}
func (n *node) nodeBudgetRecover(ctx context.Context) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.nodeBudget || n.process != nil {
		return nil, errors.New("fresh budget recovery required")
	}
	b, e := privatefile.Read("/srv/fixture/node-budget-receipt.json", 32768)
	if e != nil {
		return nil, e
	}
	var saved budgetCheckpoint
	if e = strictjson.Decode(b, &saved); e != nil {
		return nil, e
	}
	if saved.Node.Phase != "node-envelope-healthy-checkpoint" || !switchRefValid(saved.Node.Ref) || saved.Node.L1Boot == n.boot || !switchUUID(saved.Node.L1Boot) || !switchUUID(saved.Node.L2Boot) || !hashPattern.MatchString(saved.Node.Key) || !hashPattern.MatchString(saved.Config) {
		return nil, errors.New("budget cold identity invalid")
	}
	h, e := fileHash("/srv/config/backend.json")
	if e != nil || h != saved.Config {
		return nil, errors.New("bound node policy changed on cold boot")
	}
	savedOwner, owner, e := budgetOwner(saved.Node.Ref)
	if e != nil || !bytes.Equal(owner, saved.Owner) {
		return nil, errors.New("budget owner changed on cold boot")
	}
	if saved.Quota.Project != savedOwner.ProjectID || saved.Quota.Snapshot || saved.Quota.Phase != "running" || saved.Quota.Jail != "/srv/r/j/firecracker/"+saved.Node.Ref.ID+saved.Node.Ref.Generation {
		return nil, errors.New("budget quota checkpoint binding invalid")
	}
	if _, e = os.Lstat(nodeBudgetInstances + "/" + saved.Node.Ref.ID + saved.Node.Ref.Generation); !os.IsNotExist(e) {
		return nil, errors.New("old budget execution survived")
	}
	qr, e := driverQuotaRead(saved.Quota.Project)
	if e != nil {
		return nil, e
	}
	blocks, inodes, entries, e := driverQuotaTree(saved.Quota.Jail, false)
	if e != nil {
		return nil, e
	}
	if e = validateDriverQuotaAccounting(saved.Quota, qr, blocks, inodes, entries); e != nil {
		return nil, e
	}
	if e = n.start(ctx); e != nil {
		return nil, e
	}
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	defer api.close()
	if e = budgetDestroyed(ctx, api, saved.Node.Ref); e != nil {
		return nil, e
	}
	if e = api.call(ctx, "POST", "/v1/sandboxes", saved.Node.Key, nodeSpec(), nil, 410); e != nil {
		return nil, e
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	key, e := randomKey()
	if e != nil {
		return nil, e
	}
	fresh, e := api.create(ctx, key)
	if e != nil {
		return nil, e
	}
	if e = budgetVM(fresh.Ref); e != nil {
		return nil, e
	}
	out, e := api.executeVM(ctx, fresh.Ref, []string{"sh", "-c", "set -e; test ! -e budget-marker; id -u; cat /proc/sys/kernel/random/boot_id"})
	if e != nil {
		return nil, e
	}
	boot, e := switchGuestIdentity(out)
	if e != nil || boot == saved.Node.L2Boot {
		return nil, errors.New("old assigned budget guest restored")
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
	for _, path := range []string{nodeBudgetInstances, nodeGroup + "/control", nodeGroup} {
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	}
	return map[string]any{"l1_boot_changed": true, "exact_node_policy_and_owner_quota_metadata_checked_before_daemon": true, "old_execution_absent_and_ordinary_recovery_destroyed_resources_absent": true, "old_key410_all_four_projects_zero_before_reuse": true, "fresh_actual_guest_uid_boot_workspace_checked": true, "all_four_projects_zero_controller_reaped_entire_node_subtree_removed": true, "no_assigned_guest_restore_and_no_node_policy_retargeted": true}, nil
}
