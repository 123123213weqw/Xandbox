//go:build linux && xandbox_host_fixture

package main

// TEST ONLY. All paths, commands, budgets and filler names are fixed. Only our
// isolated L1 PID1 may run this profile. No shared L0 configuration is changed.
import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const nodeSnapshotReceiptPath = "/srv/fixture/node-snapshot-receipt.json"
const nodeByteFillerPath = "/srv/fixture/node-byte-fill"
const nodeInodeFillerPath = "/srv/fixture/node-inode-fill"
const nodeInodeFillLimit = 150000

func validateNodeSnapshotConfig(c firecracker.Config) error {
	if c.Version != 3 || c.RuntimeRoot != "/srv/r" || c.CgroupRoot != nodeBudgetInstances || c.UIDStart != 400000 || c.UIDCount != 4 || !c.ReservedUIDRange || c.Node == nil || *c.Node != budgetPolicy() || c.Quota == nil || c.Quota.Version != 1 || c.Quota.ProjectStart != driverProjectFirst || c.Quota.MaxBytes != 192<<20 || c.Quota.MaxInodes != 128 || c.IO == nil || c.IO.Version != 1 || c.IO.BytesPerSecond != 16<<20 || c.IO.OperationsPerSecond != 1024 || c.Snapshot == nil || c.Snapshot.Version != 1 || c.Snapshot.MemoryMiB != 512 || c.Snapshot.VCPUs != 2 || c.Snapshot.MaxEntries != 4 || c.Snapshot.MaxBytes != 2<<30 || (!hashPattern.MatchString(c.Snapshot.AgentSHA256) || strings.Trim(c.Snapshot.AgentSHA256, "0") == "") {
		return errors.New("fixed complete schema3 snapshot node policy required")
	}
	return nil
}
func fixedNodeSnapshotConfig() (firecracker.Config, error) {
	var c firecracker.Config
	b, e := privatefile.Read("/srv/config/backend.json", 16384)
	if e != nil {
		return c, e
	}
	if e = strictjson.Decode(b, &c); e != nil {
		return c, e
	}
	return c, validateNodeSnapshotConfig(c)
}
func (n *node) initializeNodeSnapshotBudget() error {
	if e := requireNode(); e != nil {
		return e
	}
	if !n.nodeSnapshot || !n.nodeBudget || !n.quotaSnapshot || !n.quotaDriver || n.mapper != nil {
		return errors.New("exclusive node snapshot budget required")
	}
	c, e := fixedNodeSnapshotConfig()
	if e != nil {
		return e
	}
	return n.initializeBudgetCgroups(c)
}
func runNodeSnapshotDaemon() error {
	if e := requireQuotaChild(); e != nil {
		return e
	}
	if _, e := fixedNodeSnapshotConfig(); e != nil {
		return e
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, unix.CAP_SYS_RESOURCE, 0); e != 0 {
		return e
	}
	return unix.Exec("/srv/assets/sandboxd", []string{"sandboxd", "-backend", "firecracker", "-state-dir", "/srv/state", "-auth-file", "/srv/config/auth.json", "-firecracker-config", "/srv/config/backend.json", "-max-instances", "4", "-max-records", "1024", "-max-sessions", "32", "-metrics"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
}

// Mirror the fixed frozen planner's reservation, not a credit for current use.
// The actual daemon AND admin must independently reject at this guard on disk.
func nodeSnapshotFreeGuards(c firecracker.Config) (uint64, uint64, error) {
	if e := validateNodeSnapshotConfig(c); e != nil {
		return 0, 0, e
	}
	p := c.Node
	n, records, sessions := uint64(p.MaxInstances), uint64(p.MaxRecords), uint64(p.MaxSessions)
	cat := uint64(c.Snapshot.MaxEntries*2 + 9)
	metadata := (records+n+256)*(80<<10) + (sessions*2+64)*(144<<10) + cat*(32<<10) + (16 << 20)
	inodes := (records+n+256)*2 + (sessions*2+64)*2 + cat*8 + 256
	return n*c.Quota.MaxBytes + uint64(c.Snapshot.MaxBytes) + metadata + p.MinFreeBytes, n*c.Quota.MaxInodes + inodes + p.MinFreeInodes, nil
}
func nodeSnapshotFS() (unix.Statfs_t, error) {
	var s unix.Statfs_t
	if e := requireNode(); e != nil {
		return s, e
	}
	e := unix.Statfs("/srv/r", &s)
	if e == nil && (s.Type != unix.EXT4_SUPER_MAGIC || s.Bsize != 4096 || s.Files < 131072 || s.Files > 135168) {
		e = errors.New("fixed12GiB/inode-formatted ext4 profile required")
	}
	return s, e
}
func nodeSnapshotAdmin(ctx context.Context, args ...string) ([]byte, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if _, e := fixedNodeSnapshotConfig(); e != nil {
		return nil, e
	}
	cg, e := os.Open(nodeGroup + "/control")
	if e != nil {
		return nil, e
	}
	defer cg.Close()
	command := exec.CommandContext(ctx, "/srv/assets/admin", append([]string{"-state-dir", "/srv/state", "-config", "/srv/config/backend.json"}, args...)...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	out, e := command.CombinedOutput()
	if len(out) > 16384 {
		return nil, errors.New("bounded node snapshot admin output exceeded")
	}
	return out, e
}
func nodeSnapshotStatus(ctx context.Context) (firecracker.CatalogStatus, error) {
	var s firecracker.CatalogStatus
	b, e := nodeSnapshotAdmin(ctx, "status")
	if e != nil {
		return s, e
	}
	e = strictjson.Decode(b, &s)
	return s, e
}
func nodeSnapshotPins(ctx context.Context, id string, want int) error {
	s, e := nodeSnapshotStatus(ctx)
	if e != nil {
		return e
	}
	return clearCatalogPins(s, id, want)
}
func nodeSnapshotRetiringPins(ctx context.Context, id string, want int) error {
	status, e := nodeSnapshotStatus(ctx)
	if e != nil {
		return e
	}
	if status.Active == id {
		return errors.New("retiring template remained active")
	}
	for _, item := range status.Items {
		if item.ID == id {
			if item.Pins != want || item.Phase != "RETIRING" {
				return errors.New("retiring node snapshot pin mismatch")
			}
			return nil
		}
	}
	return errors.New("retiring node snapshot missing")
}
func nodeSnapshotPublishArgs() []string {
	return []string{"-manifest", "/srv/fixture/node-next-manifest.json", "-memory", "/srv/export/memory", "-snapshot-state", "/srv/export/state", "publish"}
}
func nodeSnapshotOwner(ref sandbox.Ref) (clearWindowOwner, []byte, error) {
	if e := requireNode(); e != nil {
		return clearWindowOwner{}, nil, e
	}
	b, e := clearOwnerBytes(ref)
	if e != nil {
		return clearWindowOwner{}, nil, e
	}
	o, e := decodeClearWindowOwner(b, ref)
	return o, b, e
}
func (n *node) nodeSnapshotGuest(ctx context.Context, api *switchAPI) (sandbox.Record, string, string, error) {
	if e := requireNode(); e != nil {
		return sandbox.Record{}, "", "", e
	}
	if !n.nodeSnapshot || n.process == nil {
		return sandbox.Record{}, "", "", errors.New("live fixed snapshot node required")
	}
	key, e := randomKey()
	if e != nil {
		return sandbox.Record{}, "", "", e
	}
	r, e := api.create(ctx, key)
	if e != nil {
		return r, key, "", e
	}
	boot, e := n.nodeSnapshotVerifyGuest(ctx, api, r)
	return r, key, boot, e
}
func (n *node) nodeSnapshotVerifyGuest(ctx context.Context, api *switchAPI, r sandbox.Record) (string, error) {
	if e := requireNode(); e != nil {
		return "", e
	}
	if !n.nodeSnapshot || n.process == nil {
		return "", errors.New("fixed live snapshot guest required")
	}
	var e error
	if e = budgetVM(r.Ref); e != nil {
		return "", e
	}
	c, e := fixedNodeSnapshotConfig()
	if e != nil {
		return "", e
	}
	if e = syscallGuestBoundaryWithObserver(c, r.Ref, n.process.Process.Pid, false); e != nil {
		return "", e
	}
	out, e := api.executeVM(ctx, r.Ref, []string{"sh", "-c", "set -e; test ! -e snapshot-marker; printf node-snapshot > snapshot-marker; dd if=/dev/zero of=/tmp/node-memory bs=1048576 count=8 2>/dev/null; sync; id -u; cat /proc/sys/kernel/random/boot_id"})
	if e != nil {
		return "", e
	}
	boot, e := switchGuestIdentity(out)
	return boot, e
}
func nodeSnapshotDelete(ctx context.Context, api *switchAPI, ref sandbox.Ref) error {
	o, _, e := nodeSnapshotOwner(ref)
	if e != nil {
		return e
	}
	if e = api.call(ctx, "DELETE", switchPath(ref), "", generationBody(ref), nil, 202); e != nil {
		return e
	}
	if e = budgetDestroyed(ctx, api, ref); e != nil {
		return e
	}
	q, e := driverQuotaRead(o.ProjectID)
	if e != nil {
		return e
	}
	if !quotaEmpty(q) {
		return errors.New("node snapshot project retained after destruction")
	}
	return nil
}
func nodeSnapshotPressureRefusals(ctx context.Context, api *switchAPI) (string, error) {
	if e := requireNode(); e != nil {
		return "", e
	}
	baseline, e := switchGauges(ctx)
	if e != nil {
		return "", e
	}
	before, e := fileHash("/srv/state/firecracker/catalog/index.json")
	if e != nil {
		return "", e
	}
	key, e := randomKey()
	if e != nil {
		return "", e
	}
	if e = api.call(ctx, "POST", "/v1/sandboxes", key, nodeSpec(), nil, 500); e != nil {
		return key, e
	}
	b, e := nodeSnapshotAdmin(ctx, nodeSnapshotPublishArgs()...)
	if e == nil || !bytes.Contains(b, []byte("node free disk/inodes below full conservative admission reserve")) {
		return key, errors.New("specific node publisher headroom refusal not observed")
	}
	after, e := fileHash("/srv/state/firecracker/catalog/index.json")
	if e != nil || after != before {
		return key, errors.New("failed headroom publication changed catalog index")
	}
	if e = api.call(ctx, "POST", "/v1/sandboxes", key, nodeSpec(), nil, 410); e != nil {
		return key, e
	}
	// The failed key is fenced before asynchronous GC necessarily finishes.
	// Do not cut or continue with an unproved failed-Prepare terminal record.
	if e = waitNode(ctx, func() (bool, error) {
		g, err := switchGauges(ctx)
		if err != nil {
			return false, err
		}
		return g["allocated"] == baseline["allocated"] && g["stop_running"] == 0 && g["cleanup_running"] == 0 && g["stop_queued"] == 0 && g["cleanup_queued"] == 0, nil
	}); e != nil {
		return key, e
	}
	return key, nil
}

type nodeInodeObservation struct{ Before, After uint64 }

func nodeSnapshotInodePressure(ctx context.Context, api *switchAPI, c firecracker.Config, victim sandbox.Ref, observed *nodeInodeObservation) (int, error) {
	if e := requireNode(); e != nil {
		return 0, e
	}
	bytesGuard, inodeGuard, e := nodeSnapshotFreeGuards(c)
	if e != nil {
		return 0, e
	}
	if e = os.Mkdir(nodeInodeFillerPath, 0700); e != nil {
		return 0, e
	}
	anchor, e := os.Lstat(nodeInodeFillerPath)
	if e != nil {
		return 0, e
	}
	count, dirs := 0, 0
	defer func() {
		now, err := os.Lstat(nodeInodeFillerPath)
		if err != nil || !os.SameFile(now, anchor) {
			return
		}
		// Only our generated names, never RemoveAll or foreign inode adoption.
		for i := 0; i < count; i++ {
			p := filepath.Join(nodeInodeFillerPath, strconv.Itoa(i/512), strconv.Itoa(i))
			var st unix.Stat_t
			if unix.Lstat(p, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Uid == 0 && st.Nlink == 1 && st.Size == 0 {
				_ = os.Remove(p)
			}
		}
		for i := 0; i < dirs; i++ {
			_ = os.Remove(filepath.Join(nodeInodeFillerPath, strconv.Itoa(i)))
		}
		_ = os.Remove(nodeInodeFillerPath)
	}()
	for {
		if e = ctx.Err(); e != nil {
			return count, e
		}
		s, err := nodeSnapshotFS()
		if err != nil {
			return count, err
		}
		if s.Ffree+512 < inodeGuard {
			observed.Before = s.Ffree
			if s.Ffree < 1024 || s.Bavail*uint64(s.Bsize) < bytesGuard {
				return count, errors.New("inode pressure must retain byte/cleanup runway")
			}
			break
		}
		if count >= nodeInodeFillLimit {
			return count, errors.New("fixed inode filler limit exceeded")
		}
		for j := 0; j < 128 && count < nodeInodeFillLimit; j++ {
			d := filepath.Join(nodeInodeFillerPath, strconv.Itoa(count/512))
			if count%512 == 0 {
				if e = os.Mkdir(d, 0700); e != nil {
					return count, e
				}
				dirs++
			}
			fd, err := unix.Open(filepath.Join(d, strconv.Itoa(count)), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
			if err != nil {
				return count, err
			}
			if e = unix.Close(fd); e != nil {
				return count, e
			}
			count++
		}
	}
	if _, e = nodeSnapshotPressureRefusals(ctx, api); e != nil {
		return count, e
	}
	if e = nodeSnapshotDelete(ctx, api, victim); e != nil {
		return count, e
	}
	after, err := nodeSnapshotFS()
	if err != nil {
		return count, err
	}
	observed.After = after.Ffree
	if observed.After >= inodeGuard || observed.After < 1024 {
		return count, errors.New("inode pressure did not remain during completed cleanup")
	}
	return count, nil
}

type nodeByteFiller struct {
	Inode uint64
	Size  int64
}

func nodeSnapshotBytePressure(c firecracker.Config) (nodeByteFiller, error) {
	var r nodeByteFiller
	if e := requireNode(); e != nil {
		return r, e
	}
	guard, ig, e := nodeSnapshotFreeGuards(c)
	if e != nil {
		return r, e
	}
	s, e := nodeSnapshotFS()
	if e != nil {
		return r, e
	}
	avail := s.Bavail * uint64(s.Bsize)
	if avail <= guard+(32<<20) || guard < 1<<30 {
		return r, errors.New("byte pressure needs initial headroom")
	}
	size := (avail - (guard - (512 << 20))) &^ uint64(4095)
	if size > 10<<30 {
		return r, errors.New("fixed byte filler bound exceeded")
	}
	fd, e := unix.Open(nodeByteFillerPath, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return r, e
	}
	f := os.NewFile(uintptr(fd), "fixed-node-byte-filler")
	defer f.Close()
	if e = unix.Fallocate(fd, 0, 0, int64(size)); e != nil {
		return r, e
	}
	if e = f.Sync(); e != nil {
		return r, e
	}
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return r, e
	}
	if st.Size != int64(size) || uint64(st.Blocks)*512 < size || st.Uid != 0 || st.Nlink != 1 {
		return r, errors.New("byte filler allocation not real")
	}
	s, e = nodeSnapshotFS()
	if e != nil {
		return r, e
	}
	if s.Bavail*uint64(s.Bsize) >= guard || s.Ffree < ig {
		return r, errors.New("byte-only pressure not achieved")
	}
	return nodeByteFiller{st.Ino, st.Size}, nil
}
func nodeSnapshotRemoveByteFiller(r nodeByteFiller) error {
	if e := requireNode(); e != nil {
		return e
	}
	var st unix.Stat_t
	if e := unix.Lstat(nodeByteFillerPath, &st); e != nil {
		return e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Uid != 0 || st.Nlink != 1 || st.Ino != r.Inode || st.Size != r.Size || r.Size <= 0 || r.Size > 10<<30 {
		return errors.New("byte filler identity changed")
	}
	return os.Remove(nodeByteFillerPath)
}

type nodeSnapshotSavedGuest struct {
	Ref       sandbox.Ref
	Key, Boot string
	Owner     []byte
	Quota     driverQuotaReceipt
}
type nodeSnapshotSaved struct {
	Version                                                          int
	L1Boot, ConfigSHA, IndexSHA, ManifestSHA, Template, NextTemplate string
	Guests                                                           []nodeSnapshotSavedGuest
	Filler                                                           nodeByteFiller
	PressureKey                                                      string
}

func (n *node) nodeSnapshotCheckpoint(ctx context.Context) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.nodeSnapshot || n.process == nil || !hashPattern.MatchString(n.switchTemplate) {
		return nil, errors.New("initialized node snapshot profile required")
	}
	c, e := fixedNodeSnapshotConfig()
	if e != nil {
		return nil, e
	}
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	defer api.close()
	b, e := privatefile.Read("/srv/export/manifest.json", 8192)
	if e != nil {
		return nil, e
	}
	var manifest firecracker.SnapshotManifest
	if e = strictjson.Decode(b, &manifest); e != nil {
		return nil, e
	}
	if manifest.Assignment != "UNASSIGNED" || manifest.ID() != n.switchTemplate {
		return nil, errors.New("unchanged genuine L1 export required")
	}
	manifest.CreatedAt = manifest.CreatedAt.Add(time.Nanosecond)
	next := manifest.ID()
	if e = privateWrite("/srv/fixture/node-next-manifest.json", manifest); e != nil {
		return nil, e
	}
	a, keeper, calibration, e := n.nodePrepareCalibration(ctx, api)
	if e != nil {
		return nil, e
	}
	if e = nodeSnapshotPins(ctx, n.switchTemplate, 2); e != nil {
		return nil, e
	}
	inodeObservation := nodeInodeObservation{}
	filled, e := nodeSnapshotInodePressure(ctx, api, c, a.Ref, &inodeObservation)
	if e != nil {
		return nil, e
	}
	if _, e = os.Lstat(nodeInodeFillerPath); !os.IsNotExist(e) {
		return nil, errors.New("inode filler cleanup incomplete")
	}
	space, ig, e := nodeSnapshotFreeGuards(c)
	if e != nil {
		return nil, e
	}
	fs, e := nodeSnapshotFS()
	if e != nil {
		return nil, e
	}
	if fs.Ffree < ig || fs.Bavail*uint64(fs.Bsize) < space {
		return nil, errors.New("headroom not restored after inode pressure")
	}
	if e = budgetVM(keeper.Ref); e != nil {
		return nil, e
	}
	if _, e = api.executeVM(ctx, keeper.Ref, []string{"cat", "snapshot-marker"}); e != nil {
		return nil, e
	}
	if e = nodeSnapshotDelete(ctx, api, keeper.Ref); e != nil {
		return nil, e
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	saved := nodeSnapshotSaved{Version: 1, L1Boot: n.boot, Template: n.switchTemplate, NextTemplate: next}
	// Sample BOTH namespace receipts only after both clones Ready/pins2.
	for i := 0; i < 2; i++ {
		r, key, boot, err := n.nodeSnapshotGuest(ctx, api)
		if err != nil {
			return nil, err
		}
		saved.Guests = append(saved.Guests, nodeSnapshotSavedGuest{Ref: r.Ref, Key: key, Boot: boot})
	}
	if saved.Guests[0].Boot == saved.Guests[1].Boot {
		return nil, errors.New("snapshot clone boots collided")
	}
	if e = nodeSnapshotPins(ctx, n.switchTemplate, 2); e != nil {
		return nil, e
	}
	for i := range saved.Guests {
		g := &saved.Guests[i]
		o, raw, err := nodeSnapshotOwner(g.Ref)
		if err != nil {
			return nil, err
		}
		if o.TemplateID != n.switchTemplate {
			return nil, errors.New("wrong live node template")
		}
		g.Owner = raw
		q, err := driverQuotaRead(o.ProjectID)
		if err != nil {
			return nil, err
		}
		jail := "/srv/r/j/firecracker/" + g.Ref.ID + g.Ref.Generation
		blocks, inodes, entries, err := driverQuotaTree(jail, true)
		if err != nil {
			return nil, err
		}
		g.Quota = driverQuotaReceipt{Snapshot: true, Phase: "running", Jail: jail, Project: o.ProjectID, Record: q, NamespaceBlocks: blocks, NamespaceInodes: inodes, Entries: entries}
		if err = validateDriverQuotaAccounting(g.Quota, q, blocks, inodes, entries); err != nil {
			return nil, err
		}
		if err = verifySharedQuotaFiles(jail); err != nil {
			return nil, err
		}
	}
	if saved.Guests[0].Ref == saved.Guests[1].Ref || saved.Guests[0].Quota.Project == saved.Guests[1].Quota.Project {
		return nil, errors.New("live initialized clones share ref or private project")
	}
	for _, name := range []string{"template.mem", "template.state"} {
		a := saved.Guests[0].Quota.Entries["root/"+name]
		b := saved.Guests[1].Quota.Entries["root/"+name]
		if !a.Shared || a != b || a.Links < 3 {
			return nil, errors.New("live snapshot shared inode baseline differs")
		}
	}
	saved.Filler, e = nodeSnapshotBytePressure(c)
	if e != nil {
		return nil, e
	}
	saved.PressureKey, e = nodeSnapshotPressureRefusals(ctx, api)
	if e != nil {
		return nil, e
	}
	for _, g := range saved.Guests {
		if e = budgetVM(g.Ref); e != nil {
			return nil, e
		}
		if _, e = api.executeVM(ctx, g.Ref, []string{"true"}); e != nil {
			return nil, e
		}
	}
	fs, e = nodeSnapshotFS()
	if e != nil {
		return nil, e
	}
	if fs.Bavail*uint64(fs.Bsize) >= space {
		return nil, errors.New("byte pressure must persist until cold cut")
	}
	saved.ConfigSHA, e = fileHash("/srv/config/backend.json")
	if e != nil {
		return nil, e
	}
	saved.IndexSHA, e = fileHash("/srv/state/firecracker/catalog/index.json")
	if e != nil {
		return nil, e
	}
	saved.ManifestSHA, e = fileHash("/srv/export/manifest.json")
	if e != nil {
		return nil, e
	}
	qfs, e := openQuotaFS(false)
	if e != nil {
		return nil, e
	}
	defer qfs.file.Close()
	if e = qfs.sync(); e != nil {
		return nil, e
	}
	if e = unix.Syncfs(int(qfs.file.Fd())); e != nil {
		return nil, e
	}
	if e = privateWrite(nodeSnapshotReceiptPath, saved); e != nil {
		return nil, e
	}
	return map[string]any{"prepare_entry_calibration": calibration, "real_nested_kvm": true, "checkpoint_receipt_fsynced": true, "schema3_snapshot_exact_node_policy": true, "publisher_and_daemon_inside_control": true, "two_actual_snapshot_clones_private_quota_shared_inode_pins_checked": true, "inode_pressure_refuses_prepare_publish_but_stop_cleanup_continues": true, "inode_filler_removed_and_headroom_restored": true, "byte_pressure_refuses_prepare_publish_existing_exec_continues": true, "publisher_refusal_specific_and_catalog_unchanged": true, "healthy_synced_low_free_checkpoint_not_inflight_fault": true, "guest_memory_touched_bytes_each": 8 << 20, "inode_filler_files": filled, "inode_pressure_free_before_delete": inodeObservation.Before, "inode_pressure_free_after_delete": inodeObservation.After, "byte_filler_allocated_bytes": saved.Filler.Size, "free_byte_guard": space, "free_inode_guard": ig, "observed_free_bytes": fs.Bavail * uint64(fs.Bsize), "prepare_permit_hardware_trace_claim": false}, nil
}
func (n *node) nodeSnapshotRecover(ctx context.Context) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.nodeSnapshot || n.process != nil {
		return nil, errors.New("fresh node snapshot cold boot required")
	}
	c, e := fixedNodeSnapshotConfig()
	if e != nil {
		return nil, e
	}
	b, e := privatefile.Read(nodeSnapshotReceiptPath, 65536)
	if e != nil {
		return nil, e
	}
	var saved nodeSnapshotSaved
	if e = strictjson.Decode(b, &saved); e != nil {
		return nil, e
	}
	if saved.Version != 1 || len(saved.Guests) != 2 || !switchUUID(saved.L1Boot) || saved.L1Boot == n.boot || !hashPattern.MatchString(saved.Template) || !hashPattern.MatchString(saved.NextTemplate) || saved.Template == saved.NextTemplate || !hashPattern.MatchString(saved.PressureKey) {
		return nil, errors.New("fixed snapshot recovery receipt invalid")
	}
	for p, want := range map[string]string{"/srv/config/backend.json": saved.ConfigSHA, "/srv/state/firecracker/catalog/index.json": saved.IndexSHA, "/srv/export/manifest.json": saved.ManifestSHA} {
		h, err := fileHash(p)
		if err != nil || h != want {
			return nil, errors.New("cold node policy/index/export changed")
		}
	}
	space, ig, e := nodeSnapshotFreeGuards(c)
	if e != nil {
		return nil, e
	}
	fs, e := nodeSnapshotFS()
	if e != nil {
		return nil, e
	}
	if fs.Bavail*uint64(fs.Bsize) >= space || fs.Ffree < ig {
		return nil, errors.New("cold byte-only pressure did not persist")
	}
	for _, g := range saved.Guests {
		if !switchRefValid(g.Ref) || !hashPattern.MatchString(g.Key) || !switchUUID(g.Boot) || !g.Quota.Snapshot || g.Quota.Jail != "/srv/r/j/firecracker/"+g.Ref.ID+g.Ref.Generation {
			return nil, errors.New("cold snapshot guest binding invalid")
		}
		if _, err := os.Lstat(nodeBudgetInstances + "/" + g.Ref.ID + g.Ref.Generation); !os.IsNotExist(err) {
			return nil, errors.New("old snapshot execution survived")
		}
		o, raw, err := nodeSnapshotOwner(g.Ref)
		if err != nil || !bytes.Equal(raw, g.Owner) || o.TemplateID != saved.Template || o.ProjectID != g.Quota.Project {
			return nil, errors.New("cold initialized snapshot owner mismatch")
		}
		q, err := driverQuotaRead(o.ProjectID)
		if err != nil {
			return nil, err
		}
		blocks, inodes, entries, err := driverQuotaTree(g.Quota.Jail, true)
		if err != nil {
			return nil, err
		}
		if err = validateDriverQuotaAccounting(g.Quota, q, blocks, inodes, entries); err != nil {
			return nil, err
		}
		if err = verifySharedQuotaFiles(g.Quota.Jail); err != nil {
			return nil, err
		}
	}
	// Ordinary daemon starts/reclaims while below free guard. No fixture restore
	// of owners/guests, pre-clear, policy retarget or publisher bypass.
	if e = n.start(ctx); e != nil {
		return nil, e
	}
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	defer api.close()
	for _, g := range saved.Guests {
		if e = budgetDestroyed(ctx, api, g.Ref); e != nil {
			return nil, e
		}
		if e = api.call(ctx, "POST", "/v1/sandboxes", g.Key, nodeSpec(), nil, 410); e != nil {
			return nil, e
		}
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	if e = nodeSnapshotPins(ctx, saved.Template, 0); e != nil {
		return nil, e
	}
	if e = api.call(ctx, "POST", "/v1/sandboxes", saved.PressureKey, nodeSpec(), nil, 410); e != nil {
		return nil, e
	}
	fs, e = nodeSnapshotFS()
	if e != nil {
		return nil, e
	}
	if fs.Bavail*uint64(fs.Bsize) >= space {
		return nil, errors.New("low-free recovery was not actually under pressure")
	}
	if e = nodeSnapshotRemoveByteFiller(saved.Filler); e != nil {
		return nil, e
	}
	fs, e = nodeSnapshotFS()
	if e != nil {
		return nil, e
	}
	if fs.Bavail*uint64(fs.Bsize) < space || fs.Ffree < ig {
		return nil, errors.New("byte pressure cleanup did not restore headroom")
	}
	out, e := nodeSnapshotAdmin(ctx, nodeSnapshotPublishArgs()...)
	if e != nil {
		return nil, e
	}
	var pub struct {
		ID string `json:"template_id"`
	}
	if e = strictjson.Decode(out, &pub); e != nil || pub.ID != saved.NextTemplate {
		return nil, errors.New("same unassigned next declaration not published after recovery")
	}
	if _, e = nodeSnapshotAdmin(ctx, "retire", saved.NextTemplate); e != nil {
		return nil, e
	}
	if e = nodeSnapshotGC(ctx, saved.NextTemplate, 1); e != nil {
		return nil, e
	}
	fresh := []sandbox.Record{}
	freshBoots := map[string]bool{}
	for i := 0; i < 2; i++ {
		r, _, boot, err := n.nodeSnapshotGuest(ctx, api)
		if err != nil {
			return nil, err
		}
		if freshBoots[boot] {
			return nil, errors.New("fresh snapshot clone boots collided")
		}
		freshBoots[boot] = true
		for _, old := range saved.Guests {
			if boot == old.Boot {
				return nil, errors.New("assigned old guest boot restored")
			}
		}
		fresh = append(fresh, r)
	}
	if e = nodeSnapshotPins(ctx, saved.Template, 2); e != nil {
		return nil, e
	}
	if _, e = nodeSnapshotAdmin(ctx, "retire", saved.Template); e != nil {
		return nil, e
	}
	if e = nodeSnapshotRetiringPins(ctx, saved.Template, 2); e != nil {
		return nil, e
	}
	if e = nodeSnapshotGC(ctx, "", 0); e != nil {
		return nil, e
	}
	if e = nodeSnapshotDelete(ctx, api, fresh[0].Ref); e != nil {
		return nil, e
	}
	if e = nodeSnapshotRetiringPins(ctx, saved.Template, 1); e != nil {
		return nil, e
	}
	if e = nodeSnapshotGC(ctx, "", 0); e != nil {
		return nil, e
	}
	if _, e = api.executeVM(ctx, fresh[1].Ref, []string{"cat", "snapshot-marker"}); e != nil {
		return nil, e
	}
	if e = nodeSnapshotDelete(ctx, api, fresh[1].Ref); e != nil {
		return nil, e
	}
	if e = nodeSnapshotGC(ctx, saved.Template, 1); e != nil {
		return nil, e
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	if e = n.process.Process.Signal(syscall.SIGTERM); e != nil {
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
	for _, p := range []string{nodeBudgetInstances, nodeGroup + "/control", nodeGroup} {
		if e = os.Remove(p); e != nil {
			return nil, e
		}
	}
	return map[string]any{"l1_boot_changed": true, "exact_policy_owner_namespace_quota_shared_backing_before_daemon": true, "low_free_guard_survived_cold_and_ordinary_start_reclaims": true, "old_keys410_all_four_projects_zero_before_reuse": true, "only_exact_owned_filler_removed_headroom_restored": true, "same_unassigned_declaration_publish_succeeds_after_restore": true, "fresh_two_actual_guests_clean_workspace_new_boots": true, "retire_pins_gc_survivor_exec_and_final_gc_checked": true, "all_four_projects_zero_controller_reaped_entire_node_subtree_removed": true, "no_assigned_guest_or_owner_restoration": true}, nil
}
func nodeSnapshotGC(ctx context.Context, id string, want int) error {
	b, e := nodeSnapshotAdmin(ctx, "gc")
	if e != nil {
		return e
	}
	var out struct {
		Removed []string `json:"removed"`
	}
	if e = strictjson.Decode(b, &out); e != nil {
		return e
	}
	if len(out.Removed) != want || (want == 1 && (out.Removed[0] != id)) {
		return fmt.Errorf("snapshot GC count or exact identity mismatch")
	}
	return nil
}
