//go:build linux && xandbox_host_fixture

package main

// TEST ONLY Linux ext4 prerequisites. These ioctls are never part of sandboxd.
// UAPI: Linux v6.8 include/uapi/linux/{quota,fs}.h; quotactl_fd(2).
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	quotaBase           = "/srv/fixture/quota"
	quotaFirst   uint32 = 1100001
	quotaHardKiB uint64 = 8192
	quotaGetAttr        = 0x801c581f
	quotaSetAttr        = 0x401c5820
	quotaInherit uint32 = 0x200
)

type quotaAttr struct {
	XFlags, ExtSize, Nextents, Project, CowExtSize uint32
	Pad                                            [8]byte
}
type quotaRecord struct {
	BHard, BSoft, Space, IHard, ISoft, Inodes, BTime, ITime uint64
	Valid, Pad                                              uint32
}
type quotaFS struct{ file *os.File }

func requireQuotaChild() error {
	b, e := os.ReadFile("/etc/xandbox-host-fixture")
	if e != nil || string(b) != fixtureMarker || os.Geteuid() != 0 || os.Getpid() == 1 || os.Getppid() != 1 {
		return errors.New("fixed L1 root child of PID1 required")
	}
	return nil
}

func capabilityPresent(status string, field string, bit uint) (bool, error) {
	var count int
	var mask uint64
	for _, line := range strings.Split(status, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == field+":" {
			var e error
			mask, e = strconv.ParseUint(f[1], 16, 64)
			if e != nil {
				return false, e
			}
			count++
		}
	}
	if count != 1 {
		return false, errors.New("missing or duplicate capability field")
	}
	return mask&(uint64(1)<<bit) != 0, nil
}

func quotaNoResourceCapability() error {
	entries, e := os.ReadDir("/proc/self/task")
	if e != nil || len(entries) == 0 {
		return errors.New("cannot inspect all worker threads")
	}
	for _, entry := range entries {
		b, e := os.ReadFile("/proc/self/task/" + entry.Name() + "/status")
		if e != nil {
			return e
		}
		for _, field := range []string{"CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb"} {
			present, e := capabilityPresent(string(b), field, unix.CAP_SYS_RESOURCE)
			if e != nil {
				return e
			}
			if present {
				return errors.New("quota worker retains CAP_SYS_RESOURCE")
			}
		}
	}
	return nil
}

func openQuotaFS(child bool) (*quotaFS, error) {
	var e error
	if child {
		e = requireQuotaChild()
	} else {
		e = requireNode()
	}
	if e != nil {
		return nil, e
	}
	// Require enforcement on the fixed L1 disk, not just loaded accounting.
	b, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil {
		return nil, e
	}
	var disk unix.Stat_t
	if e = unix.Stat("/dev/vda", &disk); e != nil {
		return nil, e
	}
	device := fmt.Sprintf("%d:%d", unix.Major(disk.Rdev), unix.Minor(disk.Rdev))
	found := 0
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.Split(line, " - ")
		if len(parts) != 2 {
			continue
		}
		left, right := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(left) >= 6 && left[4] == "/srv" {
			if left[2] != device || len(right) != 3 || right[0] != "ext4" || !quotaOption(right[2], "prjquota") || !quotaOption(left[5], "rw") {
				return nil, errors.New("fixed ext4 L1 prjquota mount required")
			}
			found++
		}
	}
	if found != 1 {
		return nil, errors.New("ambiguous or missing L1 mount")
	}
	fd, e := unix.Open("/srv", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	q := &quotaFS{os.NewFile(uintptr(fd), "/srv")}
	var format uint32
	if e = q.call(0x800004, 0, unsafe.Pointer(&format)); e != nil || format != 4 {
		q.file.Close()
		return nil, errors.New("enforced v2 project quota required")
	}
	return q, nil
}
func quotaOption(options, wanted string) bool {
	for _, option := range strings.Split(options, ",") {
		if option == wanted {
			return true
		}
	}
	return false
}
func quotaCommand(command, id uint32) (uintptr, error) {
	// No QUOTAON/OFF, block-device paths, global flags, or project-zero writes.
	switch command {
	case 0x800001, 0x800004:
		if id != 0 {
			return 0, errors.New("format/sync require zero selector")
		}
	case 0x800007, 0x800008:
		if id < quotaFirst || id > quotaFirst+2 {
			return 0, errors.New("project outside fixed fixture range")
		}
	default:
		return 0, errors.New("unsupported quota command")
	}
	return uintptr(command<<8 | 2), nil
}

func (q *quotaFS) call(command uint32, id uint32, value unsafe.Pointer) error {
	commandBits, e := quotaCommand(command, id)
	if e != nil {
		return e
	}
	_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL_FD, q.file.Fd(), commandBits, uintptr(id), uintptr(value), 0, 0)
	runtime.KeepAlive(q)
	runtime.KeepAlive(value)
	if errno != 0 {
		return errno
	}
	return nil
}
func (q *quotaFS) get(id uint32) (quotaRecord, error) {
	var r quotaRecord
	e := q.call(0x800007, id, unsafe.Pointer(&r))
	return r, e
}
func (q *quotaFS) sync() error { return q.call(0x800001, 0, nil) }
func quotaEmpty(r quotaRecord) bool {
	return r.BHard|r.BSoft|r.Space|r.IHard|r.ISoft|r.Inodes|r.BTime|r.ITime == 0
}
func (q *quotaFS) reserve(id uint32, blocks, inodes uint64) error {
	r, e := q.get(id)
	if e != nil {
		return e
	}
	if !quotaEmpty(r) {
		return errors.New("unknown nonempty fixture project; no adoption")
	}
	return q.limits(id, blocks, inodes)
}
func (q *quotaFS) limits(id uint32, blocks, inodes uint64) error {
	r := quotaRecord{BHard: blocks, IHard: inodes, Valid: 1 | 4 | 16 | 32}
	if e := q.call(0x800008, id, unsafe.Pointer(&r)); e != nil {
		return e
	}
	got, e := q.get(id)
	if e != nil {
		return e
	}
	if got.BHard != blocks || got.IHard != inodes || got.BSoft != 0 || got.ISoft != 0 {
		return errors.New("quota limit readback mismatch")
	}
	return nil
}
func (q *quotaFS) clear(id uint32) error {
	if e := q.sync(); e != nil {
		return e
	}
	r, e := q.get(id)
	if e != nil {
		return e
	}
	if r.Space != 0 || r.Inodes != 0 {
		return errors.New("cannot release project with retained usage")
	}
	if e = q.limits(id, 0, 0); e != nil {
		return e
	}
	if e = q.sync(); e != nil {
		return e
	}
	r, e = q.get(id)
	if e != nil {
		return e
	}
	if !quotaEmpty(r) {
		return errors.New("project not cleared")
	}
	return nil
}
func quotaAttributes(path string, set *quotaAttr) (quotaAttr, error) {
	var attr quotaAttr
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return attr, e
	}
	defer unix.Close(fd)
	if set != nil {
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), quotaSetAttr, uintptr(unsafe.Pointer(set)))
		runtime.KeepAlive(set)
		if errno != 0 {
			return attr, errno
		}
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), quotaGetAttr, uintptr(unsafe.Pointer(&attr)))
	if errno != 0 {
		return attr, errno
	}
	return attr, nil
}
func quotaTag(path string, id uint32, inherit bool) error {
	a, e := quotaAttributes(path, nil)
	if e != nil {
		return e
	}
	a.Project = id
	a.XFlags &^= quotaInherit
	if inherit {
		a.XFlags |= quotaInherit
	}
	got, e := quotaAttributes(path, &a)
	if e != nil {
		return e
	}
	if got.Project != id || (got.XFlags&quotaInherit != 0) != inherit {
		return errors.New("project attribute readback mismatch")
	}
	return nil
}
func quotaDirectory(path string, id uint32) error {
	if e := os.Mkdir(path, 0700); e != nil {
		return e
	}
	return quotaTag(path, id, true)
}
func quotaAllocate(path string, bytes int64) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = unix.Fallocate(int(f.Fd()), 0, 0, bytes); e != nil {
		return e
	}
	return f.Sync()
}

func (n *node) quotaProbe(ctx context.Context) (map[string]any, error) {
	q, e := openQuotaFS(false)
	if e != nil {
		return nil, e
	}
	defer q.file.Close()
	if _, e = os.Lstat(quotaBase); !os.IsNotExist(e) {
		return nil, errors.New("quota probe requires fresh fixed namespace")
	}
	for id := quotaFirst; id <= quotaFirst+2; id++ {
		r, e := q.get(id)
		if e != nil {
			return nil, e
		}
		if !quotaEmpty(r) {
			return nil, errors.New("fixed project is not initially empty")
		}
	}
	b, e := os.ReadFile("/proc/self/status")
	if e != nil {
		return nil, e
	}
	present, e := capabilityPresent(string(b), "CapEff", unix.CAP_SYS_RESOURCE)
	if e != nil || !present {
		return nil, errors.New("negative root-bypass prerequisite missing")
	}
	if e = os.Mkdir(quotaBase, 0700); e != nil {
		return nil, e
	}
	attr, e := quotaAttributes(quotaBase, nil)
	if e != nil || attr.Project != 0 {
		return nil, errors.New("fixture parent must be project zero")
	}
	if e = q.reserve(quotaFirst, quotaHardKiB, 0); e != nil {
		return nil, e
	}
	path := quotaBase + "/root-bypass"
	if e = quotaDirectory(path, quotaFirst); e != nil {
		return nil, e
	}
	if e = quotaAllocate(path+"/data", 9<<20); e != nil {
		return nil, e
	}
	r, e := q.get(quotaFirst)
	if e != nil {
		return nil, e
	}
	if r.Space <= quotaHardKiB<<10 {
		return nil, errors.New("root quota bypass was not reproduced")
	}
	rootBytes := r.Space
	if e = os.RemoveAll(path); e != nil {
		return nil, e
	}
	if e = q.clear(quotaFirst); e != nil {
		return nil, e
	}
	// Only this fixed child loses one capability; L1 PID1 and L0 are unchanged.
	child := exec.CommandContext(ctx, "/usr/bin/xandbox-host-fixture", "-mode", "quota-drop")
	child.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	child.Stderr = os.Stderr
	var out bytes.Buffer
	child.Stdout = &out
	if e = child.Run(); e != nil {
		return nil, fmt.Errorf("fixed quota worker: %w", e)
	}
	var measured map[string]any
	if out.Len() > 8192 {
		return nil, errors.New("oversized quota worker reply")
	}
	if e = json.Unmarshal(out.Bytes(), &measured); e != nil {
		return nil, e
	}
	checkpoint, e := n.checkpoint(ctx, "running")
	if e != nil {
		return nil, e
	}
	b, e = os.ReadFile("/srv/fixture/receipt.json")
	if e != nil {
		return nil, e
	}
	var receipt nodeReceipt
	if e = json.Unmarshal(b, &receipt); e != nil {
		return nil, e
	}
	receipt.Phase = "quota-prerequisites"
	if e = privateWrite("/srv/fixture/receipt.json", receipt); e != nil {
		return nil, e
	}
	for k, v := range measured {
		checkpoint[k] = v
	}
	checkpoint["phase"] = "quota-prerequisites"
	checkpoint["root_with_sys_resource_bypassed_hard_limit"] = true
	checkpoint["root_bypass_space_bytes"] = rootBytes
	checkpoint["project_block_hard_bytes"] = quotaHardKiB << 10
	checkpoint["production_driver_quota"] = false
	return checkpoint, nil
}

func quotaWorker(mode string) error {
	if e := requireQuotaChild(); e != nil {
		return e
	}
	if mode == "quota-drop" {
		// All existing threads lose the bounding capability. A fixed re-exec
		// then loses effective/permitted copies, including on future threads.
		if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, unix.CAP_SYS_RESOURCE, 0); e != 0 {
			return e
		}
		return unix.Exec("/usr/bin/xandbox-host-fixture", []string{"xandbox-host-fixture", "-mode", "quota-limited"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
	}
	if mode != "quota-limited" {
		return errors.New("invalid quota worker mode")
	}
	if e := quotaNoResourceCapability(); e != nil {
		return e
	}
	q, e := openQuotaFS(true)
	if e != nil {
		return e
	}
	defer q.file.Close()
	if e = q.reserve(quotaFirst, quotaHardKiB, 0); e != nil {
		return e
	}
	path := quotaBase + "/blocks"
	if e = quotaDirectory(path, quotaFirst); e != nil {
		return e
	}
	if e = quotaAllocate(path+"/within", 4<<20); e != nil {
		return e
	}
	if e = quotaAllocate(path+"/over", 8<<20); !errors.Is(e, unix.EDQUOT) {
		return fmt.Errorf("real block EDQUOT required: %v", e)
	}
	r, e := q.get(quotaFirst)
	if e != nil {
		return e
	}
	if r.Space < 4<<20 || r.Space > quotaHardKiB<<10 {
		return errors.New("block quota usage outside hard bound")
	}
	blockBytes := r.Space
	if e = os.RemoveAll(path); e != nil {
		return e
	}
	if e = q.clear(quotaFirst); e != nil {
		return e
	}
	id := quotaFirst + 1
	if e = q.reserve(id, 0, 16); e != nil {
		return e
	}
	path = quotaBase + "/inodes"
	if e = quotaDirectory(path, id); e != nil {
		return e
	}
	created, rejected := 0, false
	for i := 0; i < 32; i++ {
		e = os.WriteFile(fmt.Sprintf("%s/f-%02d", path, i), nil, 0600)
		if errors.Is(e, unix.EDQUOT) {
			rejected = true
			break
		}
		if e != nil {
			return e
		}
		created++
	}
	r, e = q.get(id)
	if e != nil {
		return e
	}
	if !rejected || created == 0 || r.Inodes != 16 {
		return errors.New("real inode EDQUOT/count required")
	}
	if e = os.RemoveAll(path); e != nil {
		return e
	}
	if e = q.clear(id); e != nil {
		return e
	}
	if e = quotaLinks(q, id); e != nil {
		return e
	}
	// Leave a known, bounded project to validate actual cold-boot persistence.
	id = quotaFirst + 2
	if e = q.reserve(id, quotaHardKiB, 16); e != nil {
		return e
	}
	path = quotaBase + "/persistent"
	if e = quotaDirectory(path, id); e != nil {
		return e
	}
	if e = quotaAllocate(path+"/data", 1<<20); e != nil {
		return e
	}
	r, e = q.get(id)
	if e != nil {
		return e
	}
	if r.Space < 1<<20 || r.Inodes != 2 {
		return errors.New("persistent project usage missing")
	}
	if e = privateWrite("/srv/fixture/quota-receipt.json", r); e != nil {
		return e
	}
	for _, p := range []string{path, quotaBase, "/srv/fixture"} {
		f, e := os.Open(p)
		if e != nil {
			return e
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			return e
		}
	}
	if e = q.sync(); e != nil {
		return e
	}
	if e = quotaNoResourceCapability(); e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"limited_writer_is_root": os.Geteuid() == 0,
		"sys_resource_absent_all_worker_threads": true, "limited_block_edquot": true, "limited_space_bytes": blockBytes,
		"limited_inode_edquot": true, "limited_files_before_inode_edquot": created,
		"cross_project_inherit_link_exdev": true, "trusted_link_before_reseal": true,
		"shared_inode_project_zero": true, "shared_link_not_double_charged": true,
		"new_file_inherits_project_after_reseal": true, "persistent_quota_receipt_fsynced": true})
}

func quotaLinks(q *quotaFS, id uint32) error {
	shared, path := quotaBase+"/shared", quotaBase+"/links"
	if e := quotaAllocate(shared, 1<<20); e != nil {
		return e
	}
	if e := os.Chmod(shared, 0444); e != nil {
		return e
	}
	a, e := quotaAttributes(shared, nil)
	if e != nil || a.Project != 0 {
		return errors.New("shared inode must be project zero")
	}
	if e = q.reserve(id, quotaHardKiB, 16); e != nil {
		return e
	}
	if e = quotaDirectory(path, id); e != nil {
		return e
	}
	before, e := q.get(id)
	if e != nil {
		return e
	}
	if e = os.Link(shared, path+"/template"); !errors.Is(e, unix.EXDEV) {
		return fmt.Errorf("cross-project inherited link must fail EXDEV: %v", e)
	}
	if e = quotaTag(path, id, false); e != nil {
		return e
	}
	if e = os.Link(shared, path+"/template"); e != nil {
		return e
	}
	if e = quotaTag(path, id, true); e != nil {
		return e
	}
	a, e = quotaAttributes(path+"/template", nil)
	if e != nil || a.Project != 0 {
		return errors.New("shared inode project changed")
	}
	after, e := q.get(id)
	if e != nil {
		return e
	}
	if after.Space != before.Space || after.Inodes != before.Inodes {
		return errors.New("shared inode was charged to clone")
	}
	if e = quotaAllocate(path+"/mutable", 1<<20); e != nil {
		return e
	}
	a, e = quotaAttributes(path+"/mutable", nil)
	if e != nil || a.Project != id {
		return errors.New("new mutable file failed inheritance")
	}
	if e = os.RemoveAll(path); e != nil {
		return e
	}
	if e = os.Remove(shared); e != nil {
		return e
	}
	return q.clear(id)
}

func recoverQuotaProbe() (map[string]any, error) {
	q, e := openQuotaFS(false)
	if e != nil {
		return nil, e
	}
	defer q.file.Close()
	b, e := os.ReadFile("/srv/fixture/quota-receipt.json")
	if e != nil {
		return nil, e
	}
	var old quotaRecord
	if e = json.Unmarshal(b, &old); e != nil {
		return nil, e
	}
	id := quotaFirst + 2
	r, e := q.get(id)
	if e != nil {
		return nil, e
	}
	if r != old || r.BHard != quotaHardKiB || r.IHard != 16 || r.Space < 1<<20 || r.Inodes != 2 {
		return nil, errors.New("quota limits/usage did not persist exactly")
	}
	for _, p := range []string{quotaBase + "/persistent", quotaBase + "/persistent/data"} {
		a, e := quotaAttributes(p, nil)
		if e != nil || a.Project != id {
			return nil, errors.New("project attribute not persistent")
		}
	}
	a, e := quotaAttributes(quotaBase+"/persistent", nil)
	if e != nil || a.XFlags&quotaInherit == 0 {
		return nil, errors.New("project inheritance not persistent")
	}
	if e = os.RemoveAll(quotaBase + "/persistent"); e != nil {
		return nil, e
	}
	if e = q.clear(id); e != nil {
		return nil, e
	}
	for id := quotaFirst; id <= quotaFirst+2; id++ {
		r, e := q.get(id)
		if e != nil {
			return nil, e
		}
		if !quotaEmpty(r) {
			return nil, errors.New("fixture project retained after cleanup")
		}
	}
	entries, e := os.ReadDir(quotaBase)
	if e != nil || len(entries) != 0 {
		return nil, errors.New("fixture files retained")
	}
	if e = os.Remove(quotaBase); e != nil {
		return nil, e
	}
	if e = os.Remove("/srv/fixture/quota-receipt.json"); e != nil {
		return nil, e
	}
	return map[string]any{"quota_persisted_after_power_cut": true, "all_fixture_project_records_cleared": true}, nil
}
