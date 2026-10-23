//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: capture an in-flight partial-copy checkpoint over the private
// control channel, NOT onto the L1 filesystem whose unsynced prefix is tested.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const copyCutReceiptMax = 7000

type copyCutReceipt struct {
	Version                                 int `json:"version"`
	Boot, Config, Manifest, Template, Index string
	Keeper, Victim                          sandbox.Ref
	KeeperKey, VictimKey, KeeperBoot        string
	KeeperOwner, VictimOwner                []byte
	KeeperQuota                             driverQuotaReceipt
}
type copyCutLive struct {
	observer *copyObserver
	cancel   context.CancelFunc
	api      *switchAPI
	done     chan error
}

func validateCopyCutReceipt(r copyCutReceipt) error {
	if r.Version != 1 || !switchUUID(r.Boot) || !hashPattern.MatchString(r.Config) || !hashPattern.MatchString(r.Manifest) || !hashPattern.MatchString(r.Template) || !hashPattern.MatchString(r.Index) || !switchRefValid(r.Keeper) || !switchRefValid(r.Victim) || r.Keeper == r.Victim || !switchUUID(r.KeeperBoot) {
		return errors.New("invalid fixed private cut identity")
	}
	for _, s := range []string{r.KeeperKey, r.VictimKey} {
		if len(s) != 64 || strings.Trim(s, "0123456789abcdef") != "" {
			return errors.New("invalid private cut key")
		}
	}
	if r.KeeperKey == r.VictimKey {
		return errors.New("cut keys not distinct")
	}
	var ko, vo clearWindowOwner
	if strictjson.Decode(r.KeeperOwner, &ko) != nil || strictjson.Decode(r.VictimOwner, &vo) != nil {
		return errors.New("invalid private cut owners")
	}
	for i, o := range []clearWindowOwner{ko, vo} {
		ref := r.Keeper
		if i == 1 {
			ref = r.Victim
		}
		if o.Ref != ref || o.Version != 4 || !o.QuotaAttempted || o.InitializationAttempted != (i == 0) || o.TemplateID != r.Template || o.UID < 400000 || o.UID >= 400004 || o.ProjectID != driverProjectFirst+uint32(o.UID-400000) {
			return errors.New("cut owner policy invalid")
		}
	}
	if ko.UID == vo.UID || ko.ProjectID == vo.ProjectID {
		return errors.New("cut private projects shared")
	}
	q := r.KeeperQuota
	if !q.Snapshot || q.Phase != "running" || q.Project != ko.ProjectID || q.Jail != "/srv/r/j/firecracker/"+r.Keeper.ID+r.Keeper.Generation || len(q.Entries) == 0 || len(q.Entries) > 32 {
		return errors.New("invalid exact keeper quota receipt")
	}
	return nil
}
func marshalCopyCutReceipt(r copyCutReceipt) ([]byte, error) {
	if e := validateCopyCutReceipt(r); e != nil {
		return nil, e
	}
	b, e := json.Marshal(r)
	if e != nil {
		return nil, e
	}
	if len(b) > copyCutReceiptMax {
		return nil, errors.New("private cut receipt exceeds unchanged8KiB request budget")
	}
	return b, nil
}
func captureCopyKeeper(ref sandbox.Ref, project uint32) (driverQuotaReceipt, error) {
	var r driverQuotaReceipt
	if e := requireNode(); e != nil {
		return r, e
	}
	q, e := openQuotaFS(false)
	if e != nil {
		return r, e
	}
	defer q.file.Close()
	// This occurs BEFORE starting the partial-copy request, never after its
	// target write is held. The initialized keeper has a stable full baseline.
	if e = q.sync(); e != nil {
		return r, e
	}
	if e = unix.Syncfs(int(q.file.Fd())); e != nil {
		return r, e
	}
	qr, e := driverQuotaRead(project)
	if e != nil {
		return r, e
	}
	r = driverQuotaReceipt{Snapshot: true, Phase: "running", Jail: "/srv/r/j/firecracker/" + ref.ID + ref.Generation, Project: project, Record: qr}
	r.NamespaceBlocks, r.NamespaceInodes, r.Entries, e = driverQuotaTree(r.Jail, true)
	if e != nil {
		return r, e
	}
	if e = validateDriverQuotaAccounting(r, qr, r.NamespaceBlocks, r.NamespaceInodes, r.Entries); e != nil {
		return r, e
	}
	return r, nil
}
func validateCopyCutIndex(b []byte, r copyCutReceipt) error {
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != r.Index {
		return errors.New("cut catalog index differs from pre-victim baseline")
	}
	var index struct {
		Version  int    `json:"version"`
		Config   string `json:"config_sha256"`
		Registry string `json:"registry_sha256"`
		Active   string `json:"active"`
		Entries  map[string]struct {
			Phase string `json:"phase"`
			Bytes int64  `json:"bytes"`
		} `json:"entries"`
	}
	if e := strictjson.Decode(b, &index); e != nil {
		return e
	}
	if index.Version != 1 || !hashPattern.MatchString(index.Config) || !hashPattern.MatchString(index.Registry) || len(index.Entries) == 0 || len(index.Entries) > 4 || index.Active != r.Template || index.Entries[r.Template].Phase != "AVAILABLE" || index.Entries[r.Template].Bytes < 1 || index.Entries[r.Template].Bytes > 2<<30 {
		return errors.New("cut pristine active template changed")
	}
	for id, entry := range index.Entries {
		if !hashPattern.MatchString(id) || entry.Bytes < 1 || entry.Bytes > 2<<30 || (id != r.Template && entry.Phase != "RETIRED") {
			return errors.New("unknown retained cut catalog entry")
		}
	}
	return nil
}
func copyCutPinsReadOnly(r copyCutReceipt) error {
	if e := requireNode(); e != nil {
		return e
	}
	b, e := privatefile.Read("/srv/state/firecracker/catalog/index.json", 256<<10)
	if e != nil {
		return e
	}
	if e = validateCopyCutIndex(b, r); e != nil {
		return e
	}
	entries, e := os.ReadDir("/srv/state/firecracker")
	if e != nil {
		return e
	}
	count := 0
	for _, d := range entries {
		if len(d.Name()) != 69 || !strings.HasSuffix(d.Name(), ".json") {
			continue
		}
		b, e := privatefile.Read("/srv/state/firecracker/"+d.Name(), 2048)
		if e != nil {
			return e
		}
		var o clearWindowOwner
		if e = strictjson.Decode(b, &o); e != nil {
			return e
		}
		if !hashPattern.MatchString(strings.TrimSuffix(d.Name(), ".json")) || d.Name() != o.Ref.ID+o.Ref.Generation+".json" || (o.Ref != r.Keeper && o.Ref != r.Victim) {
			return errors.New("unexpected extra live owner at cut")
		}
		if o.TemplateID != r.Template {
			return errors.New("cut owner pin changed")
		}
		count++
	}
	if count != 2 {
		return errors.New("two durable cut pins not observed")
	}
	return nil
}
func (n *node) quotaCopyCutCheckpoint(ctx context.Context) (result map[string]any, private []byte, err error) {
	if e := requireNode(); e != nil {
		return nil, nil, e
	}
	if !n.quotaSnapshot || n.quotaSwitch || n.mapper != nil || n.process != nil || n.copyCut != nil {
		return nil, nil, errors.New("fresh fixed partial cut profile required")
	}
	cfg, e := fixedCopyConfig()
	if e != nil {
		return nil, nil, e
	}
	setup, e := n.quotaSnapshotSetup(ctx)
	if e != nil {
		return nil, nil, e
	}
	obs, e := n.startCopyObservedOn(ctx, true)
	if e != nil {
		return nil, nil, e
	}
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	liveCtx, liveCancel := context.WithTimeout(context.Background(), 90*time.Second)
	success := false
	defer func() {
		if !success {
			liveCancel()
			api.close()
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
	r := copyCutReceipt{Version: 1, Boot: n.boot}
	r.Config, e = fileHash("/srv/config/backend.json")
	if e != nil {
		return nil, nil, e
	}
	r.Manifest, e = fileHash("/srv/export/manifest.json")
	if e != nil {
		return nil, nil, e
	}
	r.KeeperKey, e = randomKey()
	if e != nil {
		return nil, nil, e
	}
	keeper, e := api.create(ctx, r.KeeperKey)
	if e != nil {
		return nil, nil, e
	}
	r.Keeper = keeper.Ref
	if e = actualNestedVM(r.Keeper); e != nil {
		return nil, nil, e
	}
	if e = syscallGuestBoundary(cfg, r.Keeper, n.process.Process.Pid); e != nil {
		return nil, nil, e
	}
	out, e := api.executeVM(ctx, r.Keeper, []string{"sh", "-c", "set -e; printf cut-keeper > cut-marker; sync; id -u; cat /proc/sys/kernel/random/boot_id"})
	if e != nil {
		return nil, nil, e
	}
	r.KeeperBoot, e = switchGuestIdentity(out)
	if e != nil {
		return nil, nil, e
	}
	ko, b, e := copyOwner(r.Keeper, true)
	if e != nil {
		return nil, nil, e
	}
	r.KeeperOwner = b
	r.Template = ko.TemplateID
	if e = copyPins(ctx, r.Template, 1, true); e != nil {
		return nil, nil, e
	}
	r.KeeperQuota, e = captureCopyKeeper(r.Keeper, ko.ProjectID)
	if e != nil {
		return nil, nil, e
	}
	r.Index, e = fileHash("/srv/state/firecracker/catalog/index.json")
	if e != nil {
		return nil, nil, e
	}
	r.VictimKey, e = randomKey()
	if e != nil {
		return nil, nil, e
	}
	done := make(chan error, 1)
	obs.arm()
	go func() {
		var record sandbox.Record
		done <- api.call(liveCtx, "POST", "/v1/sandboxes", r.VictimKey, nodeSpec(), &record, 201)
	}()
	var boundary copyBoundary
	select {
	case boundary = <-obs.held:
	case <-done:
		_, _, e := obs.snapshot()
		if e == nil {
			e = errors.New("cut request returned before held prefix")
		}
		return nil, nil, e
	case <-obs.done:
		_, _, e := obs.snapshot()
		if e == nil {
			e = errors.New("cut observer stopped")
		}
		return nil, nil, e
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	r.Victim = boundary.Ref
	r.VictimOwner = boundary.Owner
	// READ ONLY from here until cut: no catalog admin (which fsyncs the owner
	// directory), quota sync, receipt write or file/directory fsync in this L1.
	if e = validateCopyCutReceipt(r); e != nil {
		return nil, nil, e
	}
	ledger, e := privatefile.Read("/srv/state/ledger/"+r.Victim.ID+".json", 64<<10)
	if e != nil {
		return nil, nil, e
	}
	var env struct {
		Version int            `json:"version"`
		Record  sandbox.Record `json:"record"`
	}
	if e = strictjson.Decode(ledger, &env); e != nil {
		return nil, nil, e
	}
	if env.Version != 1 || env.Record.Ref != r.Victim || env.Record.State != sandbox.Creating || env.Record.DeleteRequested || !env.Record.StoppedAt.IsZero() || !env.Record.DestroyedAt.IsZero() {
		return nil, nil, errors.New("held cut victim durable CREATING not retained")
	}
	if e = copyCutPinsReadOnly(r); e != nil {
		return nil, nil, e
	}
	owner, e := clearOwnerBytes(r.Keeper)
	if e != nil || !bytes.Equal(owner, r.KeeperOwner) {
		return nil, nil, errors.New("cut keeper owner changed")
	}
	select {
	case <-done:
		return nil, nil, errors.New("held cut create completed or canceled")
	default:
	}
	injected, _, e := obs.snapshot()
	if e != nil || injected != 0 {
		return nil, nil, errors.New("cut selected write received a reply")
	}
	private, e = marshalCopyCutReceipt(r)
	if e != nil {
		return nil, nil, e
	}
	n.copyCut = &copyCutLive{observer: obs, cancel: liveCancel, api: api, done: done}
	success = true
	return map[string]any{"genuine_l1_snapshot_setup": setup, "real_keeper_kvm_uid_data_and_filters_checked": true, "attempted_uninitialized_victim_no_vmm_or_shared_links": true, "actual_live_workspace_prefix_bytes": boundary.Size, "live_kernel_quota_space_bytes": boundary.Space, "live_named_allocated_bytes": boundary.NamedSpace, "live_quota_inodes": boundary.Inodes, "live_named_inodes": boundary.NamedInodes, "two_durable_owner_pins_read_without_catalog_sync": true, "durable_creating_and_request_still_pending": true, "zero_selected_write_error_or_continue_reply": true, "no_observer_l1_sync_or_receipt_write_after_prefix": true, "keeper_baseline_synced_only_before_victim_creation": true, "private_receipt_only_over_control_not_l1_disk": true, "held_notification_not_actual_filesystem_D": true}, private, nil
}
func validateColdPartialCopy(q quotaRecord, blocks, inodes uint64, entries map[string]driverQuotaEntry) (int64, error) {
	if q.BHard != 192<<10 || q.IHard != 128 || q.BSoft|q.ISoft|q.BTime|q.ITime != 0 || q.Space != blocks || q.Inodes != inodes || q.Space > 192<<20 || len(entries) > 3 || inodes > 3 {
		return 0, errors.New("cold partial quota not independently accounted")
	}
	var size int64
	var namedBlocks uint64
	seen := make(map[uint64]bool)
	if inodes != uint64(len(entries)) {
		return 0, errors.New("cold partial inode count mismatch")
	}
	for name, a := range entries {
		if a.Inode == 0 || seen[a.Inode] || a.Blocks > 192<<20 || a.Blocks%512 != 0 {
			return 0, errors.New("cold partial inode identity or blocks invalid")
		}
		seen[a.Inode] = true
		namedBlocks += a.Blocks
		if a.Shared || a.UID != 0 || a.GID != 0 || a.Device != 0 {
			return 0, errors.New("unexpected cold partial inode owner/type")
		}
		switch name {
		case ".", "root":
			if a.Mode != unix.S_IFDIR|0700 || a.Links < 2 || a.Links > 3 {
				return 0, errors.New("cold partial directory invalid")
			}
		case "root/workspace.ext4":
			if a.Mode != unix.S_IFREG|0600 || a.Links != 1 || a.Size < 0 || a.Size > copyPrefix {
				return 0, errors.New("cold partial file beyond unexecuted write")
			}
			size = a.Size
		default:
			return 0, errors.New("cold partial stage contains unexpected name")
		}
	}
	if namedBlocks != blocks {
		return 0, errors.New("cold partial named allocation mismatch")
	}
	if len(entries) > 0 {
		if _, ok := entries["."]; !ok {
			return 0, errors.New("cold partial root missing")
		}
	}
	if top, ok := entries["."]; ok {
		wantLinks := uint64(2)
		if _, hasRoot := entries["root"]; hasRoot {
			wantLinks = 3
		}
		if top.Links != wantLinks {
			return 0, errors.New("cold partial root links invalid")
		}
	}
	if root, ok := entries["root"]; ok && root.Links != 2 {
		return 0, errors.New("cold partial private directory links invalid")
	}
	if _, ok := entries["root/workspace.ext4"]; ok {
		if _, has := entries["root"]; !has {
			return 0, errors.New("partial workspace without parent")
		}
	}
	return size, nil
}
func (n *node) quotaCopyCutRecover(ctx context.Context, private []byte) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.quotaSnapshot || n.quotaSwitch || n.mapper != nil || n.process != nil || n.copyCut != nil || len(private) == 0 || len(private) > copyCutReceiptMax {
		return nil, errors.New("fresh fixed partial-copy recovery required")
	}
	var r copyCutReceipt
	if e := strictjson.Decode(private, &r); e != nil {
		return nil, e
	}
	if e := validateCopyCutReceipt(r); e != nil {
		return nil, e
	}
	if r.Boot == n.boot {
		return nil, errors.New("partial cut host incarnation unchanged")
	}
	if _, e := fixedCopyConfig(); e != nil {
		return nil, e
	}
	for path, want := range map[string]string{"/srv/config/backend.json": r.Config, "/srv/export/manifest.json": r.Manifest} {
		actual, e := fileHash(path)
		if e != nil || actual != want {
			return nil, errors.New("partial cut immutable policy/export changed")
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
		return nil, errors.New("partial cut assigned export or ABI retarget")
	}
	var vo clearWindowOwner
	for i, ref := range []sandbox.Ref{r.Keeper, r.Victim} {
		o, owner, e := copyOwner(ref, i == 0)
		if e != nil {
			return nil, e
		}
		want := r.KeeperOwner
		if i == 1 {
			want = r.VictimOwner
			vo = o
		}
		if !bytes.Equal(owner, want) {
			return nil, errors.New("exact cut attempted owner changed")
		}
		if _, e = os.Lstat(nodeGroup + "/" + ref.ID + ref.Generation); !os.IsNotExist(e) {
			return nil, errors.New("old cut execution survived cold boot")
		}
	}
	if e = copyCutPinsReadOnly(r); e != nil {
		return nil, e
	}
	qr, e := driverQuotaRead(r.KeeperQuota.Project)
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
	jail := "/srv/r/j/firecracker/" + r.Victim.ID + r.Victim.Generation
	blocks, inodes, entries = 0, 0, map[string]driverQuotaEntry{}
	if _, e = os.Lstat(jail); e == nil {
		blocks, inodes, entries, e = driverQuotaTree(jail, true)
		if e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	qr, e = driverQuotaRead(vo.ProjectID)
	if e != nil {
		return nil, e
	}
	coldSize, e := validateColdPartialCopy(qr, blocks, inodes, entries)
	if e != nil {
		return nil, e
	}
	for name := range entries {
		a, e := quotaAttributes(filepath.Join(jail, name), nil)
		if e != nil || a.Project != vo.ProjectID {
			return nil, errors.New("cold partial attribution changed")
		}
		if name != "root/workspace.ext4" && a.XFlags&quotaInherit == 0 {
			return nil, errors.New("cold partial inherit lost")
		}
	}
	coldSpace, coldInodes := qr.Space, qr.Inodes
	// Only now may the ordinary uninstrumented daemon recover and reclaim.
	if e = n.start(ctx); e != nil {
		return nil, e
	}
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	defer api.close()
	for i, ref := range []sandbox.Ref{r.Keeper, r.Victim} {
		if e = api.destroyed(ctx, ref); e != nil {
			return nil, e
		}
		key := r.KeeperKey
		if i == 1 {
			key = r.VictimKey
		}
		if e = api.call(ctx, "POST", "/v1/sandboxes", key, nodeSpec(), nil, 410); e != nil {
			return nil, e
		}
		if e = api.call(ctx, "POST", switchPath(ref)+"/exec", "", sandbox.ExecRequest{Generation: ref.Generation, Argv: []string{"true"}}, nil, 409); e != nil {
			return nil, e
		}
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	if e = copyPins(ctx, r.Template, 0, true); e != nil {
		return nil, e
	}
	var fresh [2]sandbox.Record
	boots := map[string]bool{r.KeeperBoot: true}
	cfg, e := fixedCopyConfig()
	if e != nil {
		return nil, e
	}
	for i := range fresh {
		key, e := randomKey()
		if e != nil {
			return nil, e
		}
		fresh[i], e = api.create(ctx, key)
		if e != nil {
			return nil, e
		}
		if fresh[i].Ref == r.Keeper || fresh[i].Ref == r.Victim {
			return nil, errors.New("old cut generation reused")
		}
		if e = actualNestedVM(fresh[i].Ref); e != nil {
			return nil, e
		}
		if e = syscallGuestBoundaryWithObserver(cfg, fresh[i].Ref, n.process.Process.Pid, false); e != nil {
			return nil, e
		}
		out, e := api.executeVM(ctx, fresh[i].Ref, []string{"sh", "-c", "set -e; test ! -e cut-marker; id -u; cat /proc/sys/kernel/random/boot_id"})
		if e != nil {
			return nil, e
		}
		boot, e := switchGuestIdentity(out)
		if e != nil || boots[boot] {
			return nil, errors.New("assigned cut guest restored")
		}
		boots[boot] = true
	}
	if e = copyPins(ctx, r.Template, 2, true); e != nil {
		return nil, e
	}
	if _, e = copyAdmin(ctx, "retire", r.Template); e != nil {
		return nil, e
	}
	if e = copyGC(ctx, r.Template, 0); e != nil {
		return nil, e
	}
	if e = api.remove(ctx, fresh[0].Ref); e != nil {
		return nil, e
	}
	if e = copyPins(ctx, r.Template, 1, false); e != nil {
		return nil, e
	}
	if e = copyGC(ctx, r.Template, 0); e != nil {
		return nil, e
	}
	if _, e = api.executeVM(ctx, fresh[1].Ref, []string{"true"}); e != nil {
		return nil, e
	}
	if e = api.remove(ctx, fresh[1].Ref); e != nil {
		return nil, e
	}
	if e = copyGC(ctx, r.Template, 1); e != nil {
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
	return map[string]any{"l1_boot_changed": true, "private_control_receipt_revalidated_not_l1_disk_receipt": true, "exact_attempted_owners_policy_and_pristine_abi_checked_before_daemon": true, "old_execution_domains_absent_before_daemon": true, "keeper_full_namespace_and_shared_inodes_accounted": true, "partial_namespace_subset_policy_and_actual_kernel_quota_accounted": true, "cold_partial_entries": len(entries), "cold_partial_workspace_size_bytes": coldSize, "cold_partial_project_space_bytes": coldSpace, "cold_partial_project_inodes": coldInodes, "two_durable_template_pins_retained_before_recovery": true, "ordinary_unobserved_recovery_both_destroyed_resources_absent_keys410_exec409": true, "two_fresh_real_guest_uids_boots_and_workspaces_checked": true, "retired_backing_two_then_one_pin_gc_and_surviving_exec_checked": true, "last_pin_exact_gc_all_four_projects_zero_controller_reaped_parent_removed": true}, nil
}
