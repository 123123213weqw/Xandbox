//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: retain a healthy catalog lock after the ordinary driver's quota
// clear, then power-cut only our L1. No production hooks or quota setters.
import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const quotaClearPhase = "quota-cleared-owner-pinned"
const quotaClearLock = "/srv/state/firecracker/catalog/.lock"
const quotaClearReceipt = "/srv/fixture/quota-clear-window.json"

type clearWindowOwner struct {
	Version                 int         `json:"version"`
	Ref                     sandbox.Ref `json:"ref"`
	QuotaAttempted          bool        `json:"quota_attempted,omitempty"`
	ProjectID               uint32      `json:"project_id,omitempty"`
	UID                     int         `json:"uid"`
	TemplateID              string      `json:"template_id,omitempty"`
	InitializationAttempted bool        `json:"initialization_attempted,omitempty"`
}
type clearWindowReceipt struct {
	Victim, Keeper           nodeReceipt
	VictimOwner, KeeperOwner []byte
	KeeperQuota              driverQuotaReceipt
}

func decodeClearWindowOwner(b []byte, ref sandbox.Ref) (clearWindowOwner, error) {
	var o clearWindowOwner
	if e := strictjson.Decode(b, &o); e != nil {
		return o, e
	}
	if len(ref.ID) != 32 || len(ref.Generation) != 32 || strings.Trim(ref.ID+ref.Generation, "0123456789abcdef") != "" ||
		o.Version != 4 || o.Ref != ref || !o.QuotaAttempted || !o.InitializationAttempted || o.UID < 400000 || o.UID >= 400004 || o.ProjectID != driverProjectFirst+uint32(o.UID-400000) ||
		len(o.TemplateID) != 64 || strings.Trim(o.TemplateID, "0123456789abcdef") != "" || strings.Trim(o.TemplateID, "0") == "" {
		return o, errors.New("invalid fixed initialized quota snapshot owner")
	}
	return o, nil
}
func clearOwnerBytes(ref sandbox.Ref) ([]byte, error) {
	return privatefile.Read("/srv/state/firecracker/"+ref.ID+ref.Generation+".json", 2048)
}
func absentClearVictim(ref sandbox.Ref) error {
	for _, path := range []string{nodeGroup + "/" + ref.ID + ref.Generation, "/srv/r/j/firecracker/" + ref.ID + ref.Generation} {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			return errors.New("cleared victim namespace or execution domain remains")
		}
	}
	return nil
}
func (n *node) fixedCatalogStatus(ctx context.Context) (firecracker.CatalogStatus, error) {
	var out firecracker.CatalogStatus
	if e := requireNode(); e != nil {
		return out, e
	}
	c := exec.CommandContext(ctx, "/srv/assets/admin", "-state-dir", "/srv/state", "-config", "/srv/config/backend.json", "status")
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	c.Stderr = os.Stderr
	var b bytes.Buffer
	c.Stdout = &b
	if e := c.Run(); e != nil {
		return out, e
	}
	if b.Len() > 8192 {
		return out, errors.New("oversized fixed catalog status")
	}
	if e := strictjson.Decode(b.Bytes(), &out); e != nil {
		return out, e
	}
	return out, nil
}
func clearCatalogPins(status firecracker.CatalogStatus, template string, want int) error {
	if status.Active != template {
		return errors.New("active pristine template changed")
	}
	for _, item := range status.Items {
		if item.ID == template {
			if item.Pins != want {
				return errors.New("pending quota owner catalog pin lost")
			}
			return nil
		}
	}
	return errors.New("pending quota template missing")
}
func (n *node) openClearLock() (f *os.File, err error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	fd, e := unix.Open(quotaClearLock, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f = os.NewFile(uintptr(fd), "owned-catalog-window-lock")
	defer func(opened *os.File) {
		if err != nil {
			opened.Close()
		}
	}(f)
	info, e := f.Stat()
	if e != nil {
		return nil, e
	}
	link, e := os.Lstat(quotaClearLock)
	if e != nil {
		return nil, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != 0 || st.Nlink != 1 || !os.SameFile(info, link) {
		return nil, errors.New("fixed catalog lock identity changed")
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return nil, e
	}
	return f, nil
}

// Observe only our direct child's FD table, guarded by immutable proc identity.
// The kernel inode, not a textual symlink target, must match our stable lock.
func (n *node) clearCatalogFDCount(identity string, lock os.FileInfo) (int, error) {
	if e := requireNode(); e != nil {
		return 0, e
	}
	if n.process == nil || n.process.Process == nil {
		return 0, errors.New("owned daemon missing")
	}
	pid := n.process.Process.Pid
	start, e := processStart(pid)
	if e != nil || start != identity {
		return 0, errors.New("owned daemon identity changed")
	}
	base := fmt.Sprintf("/proc/%d/fd/", pid)
	entries, e := os.ReadDir(base)
	if e != nil {
		return 0, e
	}
	if len(entries) > 512 {
		return 0, errors.New("unexpected owned daemon FD count")
	}
	count := 0
	for _, entry := range entries {
		info, e := os.Stat(base + entry.Name())
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return 0, e
		}
		if os.SameFile(lock, info) {
			count++
		}
	}
	end, e := processStart(pid)
	if e != nil || end != identity {
		return 0, errors.New("owned daemon identity changed during FD observation")
	}
	return count, nil
}
func adjustedKeeperQuota(before driverQuotaReceipt, actual quotaRecord, blocks, inodes uint64, entries map[string]driverQuotaEntry) (driverQuotaReceipt, error) {
	if !before.Snapshot || before.Phase != "running" {
		return before, errors.New("snapshot keeper baseline required")
	}
	expected := map[string]driverQuotaEntry{}
	for path, entry := range before.Entries {
		expected[path] = entry
	}
	for _, path := range []string{"root/template.mem", "root/template.state"} {
		entry, ok := expected[path]
		if !ok || !entry.Shared || entry.Links < 3 {
			return before, errors.New("two-clone immutable link baseline missing")
		}
		entry.Links--
		expected[path] = entry
	}
	before.Entries = expected
	if e := validateDriverQuotaAccounting(before, actual, blocks, inodes, entries); e != nil {
		return before, e
	}
	before.Record, before.Entries, before.NamespaceBlocks, before.NamespaceInodes = actual, entries, blocks, inodes
	return before, nil
}
func (n *node) quotaClearCheckpoint(ctx context.Context) (result map[string]any, err error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.quotaDriver || !n.quotaSnapshot || n.quotaStateIO || n.mapper != nil || n.process == nil || n.quotaWindowLock != nil {
		return nil, errors.New("initialized fixed snapshot quota window required")
	}
	for _, path := range []string{quotaClearReceipt, "/srv/fixture/receipt.json"} {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			return nil, errors.New("refuse existing window receipt")
		}
	}
	receipts := []nodeReceipt{}
	owners := [][]byte{}
	ownerViews := []clearWindowOwner{}
	var keeperQuota driverQuotaReceipt
	for index, marker := range []string{"window-victim", "window-keeper"} {
		key, e := randomKey()
		if e != nil {
			return nil, e
		}
		r, e := n.create(ctx, key)
		if e != nil {
			return nil, e
		}
		if e = actualNestedVM(r.Ref); e != nil {
			return nil, e
		}
		uid, e := n.execute(ctx, r.Ref, []string{"id", "-u"})
		if e != nil || strings.TrimSpace(uid.Stdout) != "65534" {
			return nil, errors.New("wrong window guest UID")
		}
		if _, e = n.execute(ctx, r.Ref, []string{"sh", "-c", "printf " + marker + " > window-marker"}); e != nil {
			return nil, e
		}
		boot, e := n.execute(ctx, r.Ref, []string{"cat", "/proc/sys/kernel/random/boot_id"})
		if e != nil {
			return nil, e
		}
		b, e := clearOwnerBytes(r.Ref)
		if e != nil {
			return nil, e
		}
		o, e := decodeClearWindowOwner(b, r.Ref)
		if e != nil {
			return nil, e
		}
		qr, _, e := n.observeDriverQuota(r.Ref, "running", nil)
		if e != nil {
			return nil, e
		}
		if index == 1 {
			keeperQuota = qr
		}
		receipts = append(receipts, nodeReceipt{Phase: quotaClearPhase, Ref: r.Ref, Key: key, L1Boot: n.boot, L2Boot: strings.TrimSpace(boot.Stdout)})
		owners = append(owners, b)
		ownerViews = append(ownerViews, o)
	}
	victim, keeper := receipts[0], receipts[1]
	if victim.Ref == keeper.Ref || ownerViews[0].ProjectID == ownerViews[1].ProjectID || ownerViews[0].TemplateID != ownerViews[1].TemplateID {
		return nil, errors.New("independent shared-template window clones required")
	}
	status, e := n.fixedCatalogStatus(ctx)
	if e != nil {
		return nil, e
	}
	if e = clearCatalogPins(status, ownerViews[0].TemplateID, 2); e != nil {
		return nil, e
	}
	identity, e := processStart(n.process.Process.Pid)
	if e != nil {
		return nil, e
	}
	lockInfo, e := os.Lstat(quotaClearLock)
	if e != nil {
		return nil, e
	}
	if count, e := n.clearCatalogFDCount(identity, lockInfo); e != nil || count != 0 {
		return nil, errors.New("catalog must be quiescent before the window")
	}
	lock, e := n.openClearLock()
	if e != nil {
		return nil, e
	}
	heldInfo, e := lock.Stat()
	if e != nil || !os.SameFile(lockInfo, heldInfo) {
		lock.Close()
		return nil, errors.New("catalog lock inode changed at acquisition")
	}
	n.quotaWindowLock = lock
	keepLock := false
	defer func() {
		if !keepLock {
			lock.Close()
			n.quotaWindowLock = nil
		}
	}()
	var accepted sandbox.Record
	if e = n.api.Do(ctx, "DELETE", nodePath(victim.Ref), generationBody(victim.Ref), &accepted); e != nil {
		return nil, e
	}
	if accepted.State == sandbox.Destroyed || !accepted.DestroyedAt.IsZero() {
		return nil, errors.New("pending cleanup falsely acknowledged destroyed")
	}
	// The distinct daemon FD is opened by withLock ONLY after quota.release's
	// Q_SYNC/readback returns. Zero quota alone would not establish that point.
	if e = waitNode(ctx, func() (bool, error) {
		count, e := n.clearCatalogFDCount(identity, lockInfo)
		if e != nil {
			return false, e
		}
		if count == 0 {
			return false, nil
		}
		record, e := driverQuotaRead(ownerViews[0].ProjectID)
		if e != nil {
			return false, e
		}
		if !quotaEmpty(record) {
			return false, nil
		}
		if e = absentClearVictim(victim.Ref); e != nil {
			return false, e
		}
		b, e := clearOwnerBytes(victim.Ref)
		if e != nil || !bytes.Equal(b, owners[0]) {
			return false, errors.New("cleared victim owner prematurely released or changed")
		}
		var current sandbox.Record
		if e = n.api.Do(ctx, "GET", nodePath(victim.Ref), nil, &current); e != nil {
			return false, e
		}
		if current.State != sandbox.Reclaiming || current.StoppedAt.IsZero() || !current.DestroyedAt.IsZero() {
			return false, errors.New("wrong post-clear durable lifecycle stage")
		}
		return true, nil
	}); e != nil {
		return nil, e
	}
	freshKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	var rejected sandbox.Record
	if e = n.api.Create(ctx, freshKey, nodeSpec(), &rejected); e == nil || !strings.HasPrefix(e.Error(), "HTTP 503:") {
		return nil, errors.New("zero-quota pending owner released instance capacity")
	}
	if e = actualNestedVM(keeper.Ref); e != nil {
		return nil, e
	}
	marker, e := n.execute(ctx, keeper.Ref, []string{"cat", "window-marker"})
	if e != nil || marker.Stdout != "window-keeper" {
		return nil, errors.New("keeper data or execution changed during quota clear")
	}
	// Do NOT call observeDriverQuota/Q_SYNC after the boundary: only reads.
	// Exactly the victim's two known shared hardlinks have been removed.
	blocks, inodes, entries, e := driverQuotaTree(keeperQuota.Jail, true)
	if e != nil {
		return nil, e
	}
	record, e := driverQuotaRead(ownerViews[1].ProjectID)
	if e != nil {
		return nil, e
	}
	keeperQuota, e = adjustedKeeperQuota(keeperQuota, record, blocks, inodes, entries)
	if e != nil {
		return nil, e
	}
	if e = verifySharedQuotaFiles(keeperQuota.Jail); e != nil {
		return nil, e
	}
	if b, e := clearOwnerBytes(keeper.Ref); e != nil || !bytes.Equal(b, owners[1]) {
		return nil, errors.New("keeper ownership changed")
	}
	w := clearWindowReceipt{Victim: victim, Keeper: keeper, VictimOwner: owners[0], KeeperOwner: owners[1], KeeperQuota: keeperQuota}
	if e = privateWrite(quotaClearReceipt, w); e != nil {
		return nil, e
	}
	if e = privateWrite("/srv/fixture/receipt.json", victim); e != nil {
		return nil, e
	}
	if count, e := n.clearCatalogFDCount(identity, lockInfo); e != nil || count == 0 {
		return nil, errors.New("post-clear catalog barrier was not observed at checkpoint")
	}
	if r, e := driverQuotaRead(ownerViews[0].ProjectID); e != nil || !quotaEmpty(r) {
		return nil, errors.New("victim quota changed before crash checkpoint")
	}
	if b, e := clearOwnerBytes(victim.Ref); e != nil || !bytes.Equal(b, owners[0]) {
		return nil, errors.New("victim owner lost before crash checkpoint")
	}
	// Retain the exact lock descriptor in PID1 until the outer L1 power cut.
	// Returning this successful RPC must never unlock it or let GC erase owner.
	keepLock = true
	return map[string]any{"phase": quotaClearPhase, "real_nested_kvm": true, "guest_uid_checked": true, "checkpoint_receipt_fsynced": true, "two_simultaneous_ordinary_snapshot_clones": true, "private_projects_distinct": true, "catalog_pins_two_checked_before_barrier": true, "ordinary_post_quota_sync_catalog_fd_observed": true, "victim_quota_zero_namespace_absent_owner_retained": true, "victim_durable_reclaiming_not_destroyed": true, "zero_quota_did_not_release_capacity_503": true, "keeper_real_vm_data_execution_survived": true, "only_two_known_shared_links_removed": true, "no_observer_quota_sync_after_clear_boundary": true, "pid1_lock_retained_until_l1_power_cut": true}, nil
}
func loadClearWindowReceipt() (clearWindowReceipt, error) {
	var w clearWindowReceipt
	b, e := privatefile.Read(quotaClearReceipt, 64<<10)
	if e != nil {
		return w, e
	}
	if e = strictjson.Decode(b, &w); e != nil {
		return w, e
	}
	if w.Victim.Phase != quotaClearPhase || w.Keeper.Phase != quotaClearPhase || w.Victim.L1Boot == "" || w.Victim.L1Boot != w.Keeper.L1Boot || w.Victim.Ref == w.Keeper.Ref || w.Victim.Key == "" || w.Keeper.Key == "" {
		return w, errors.New("invalid fixed window identities")
	}
	v, e := decodeClearWindowOwner(w.VictimOwner, w.Victim.Ref)
	if e != nil {
		return w, e
	}
	k, e := decodeClearWindowOwner(w.KeeperOwner, w.Keeper.Ref)
	if e != nil {
		return w, e
	}
	if v.ProjectID == k.ProjectID || v.TemplateID != k.TemplateID || !w.KeeperQuota.Snapshot || w.KeeperQuota.Phase != "running" || w.KeeperQuota.Project != k.ProjectID || w.KeeperQuota.Jail != "/srv/r/j/firecracker/"+w.Keeper.Ref.ID+w.Keeper.Ref.Generation {
		return w, errors.New("window project/template/namespace mismatch")
	}
	return w, nil
}
func (n *node) recoverQuotaClear(ctx context.Context) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.quotaSnapshot || !n.quotaDriver || n.quotaStateIO || n.mapper != nil || n.process != nil || n.quotaWindowLock != nil {
		return nil, errors.New("fresh snapshot quota cold recovery required")
	}
	w, e := loadClearWindowReceipt()
	if e != nil {
		return nil, e
	}
	raw, e := privatefile.Read("/srv/fixture/receipt.json", 16384)
	if e != nil {
		return nil, e
	}
	var primary nodeReceipt
	if e = strictjson.Decode(raw, &primary); e != nil || primary != w.Victim {
		return nil, errors.New("primary window receipt identity mismatch")
	}
	if w.Victim.L1Boot == n.boot {
		return nil, errors.New("window L1 was not power-cut")
	}
	for _, pair := range []struct {
		r nodeReceipt
		b []byte
	}{{w.Victim, w.VictimOwner}, {w.Keeper, w.KeeperOwner}} {
		b, e := clearOwnerBytes(pair.r.Ref)
		if e != nil || !bytes.Equal(b, pair.b) {
			return nil, errors.New("durable window owner changed across power cut")
		}
	}
	victim, _ := decodeClearWindowOwner(w.VictimOwner, w.Victim.Ref)
	keeper, _ := decodeClearWindowOwner(w.KeeperOwner, w.Keeper.Ref)
	if r, e := driverQuotaRead(victim.ProjectID); e != nil || !quotaEmpty(r) {
		return nil, errors.New("cleared quota did not persist across power cut")
	}
	if e = absentClearVictim(w.Victim.Ref); e != nil {
		return nil, e
	}
	if _, e = verifyDriverQuotaReceiptOn(w.KeeperQuota, nil); e != nil {
		return nil, e
	}
	status, e := n.fixedCatalogStatus(ctx)
	if e != nil {
		return nil, e
	}
	if e = clearCatalogPins(status, victim.TemplateID, 2); e != nil {
		return nil, e
	}
	result, e := n.recover(ctx)
	if e != nil {
		return nil, e
	}
	if e = waitNode(ctx, func() (bool, error) {
		var r sandbox.Record
		e := n.api.Do(ctx, "GET", nodePath(w.Keeper.Ref), nil, &r)
		return e == nil && r.State == sandbox.Destroyed, e
	}); e != nil {
		return nil, e
	}
	if e = n.clean(w.Keeper.Ref); e != nil {
		return nil, e
	}
	var replay sandbox.Record
	if e = n.api.Create(ctx, w.Keeper.Key, nodeSpec(), &replay); e == nil || !strings.HasPrefix(e.Error(), "HTTP 410:") {
		return nil, errors.New("old keeper key resurrected")
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	status, e = n.fixedCatalogStatus(ctx)
	if e != nil {
		return nil, e
	}
	if e = clearCatalogPins(status, keeper.TemplateID, 0); e != nil {
		return nil, e
	}
	result["cleared_victim_quota_zero_before_daemon_recovery"] = true
	result["both_durable_owners_and_two_pins_retained_across_cold_boot"] = true
	result["keeper_quota_namespace_and_shared_content_checked_before_recovery"] = true
	result["keeper_old_destroyed_resources_absent_key410"] = true
	result["both_old_pins_released_active_template_unchanged"] = true
	result["all_private_project_ids_cleared"] = true
	return result, nil
}
