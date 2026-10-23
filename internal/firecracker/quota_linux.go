//go:build linux

package firecracker

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux v6.8 UAPI: quota.h, fs.h, ext4.h. The UUID ioctl encodes the 8-byte
// flexible-array header, NOT the size of the full 24-byte userspace buffer.
const (
	projectInherit uint32 = 0x200
	getProjectAttr        = 0x801c581f
	setProjectAttr        = 0x401c5820
	getExt4UUID           = 0x8008662c
)

type projectAttr struct {
	Flags, ExtSize, Nextents, ID, CowExtSize uint32
	Pad                                      [8]byte
}
type projectRecord struct {
	BHard, BSoft, Space, IHard, ISoft, Inodes, BTime, ITime uint64
	Valid, Pad                                              uint32
}
type ext4UUID struct {
	Length, Flags uint32
	Value         [16]byte
}

// One anchor FD lives with the driver (not one per generation). Failures in New
// close it; on successful construction os.File retains its normal finalizer and
// the descriptor is CLOEXEC. It is never inherited by the warden or VMM.
type projectQuota struct {
	cfg     Config
	anchor  *os.File
	mountID string
	get     func(uint32) (projectRecord, error)
	set     func(uint32, projectRecord) error
	sync    func() error
}

func quotaCapsAbsent(status string) error {
	seen := map[string]bool{}
	for _, line := range strings.Split(status, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		for _, field := range []string{"CapEff:", "CapPrm:", "CapBnd:", "CapInh:", "CapAmb:"} {
			if f[0] != field {
				continue
			}
			if seen[field] {
				return errors.New("duplicate capability field")
			}
			seen[field] = true
			mask, e := strconv.ParseUint(f[1], 16, 64)
			if e != nil || mask&(1<<unix.CAP_SYS_RESOURCE) != 0 {
				return errors.New("quota requires CAP_SYS_RESOURCE absent from all capability sets")
			}
		}
	}
	if len(seen) != 5 {
		return errors.New("incomplete capability status")
	}
	return nil
}
func checkQuotaCapabilities() error {
	es, e := os.ReadDir("/proc/self/task")
	if e != nil || len(es) == 0 {
		return errors.New("cannot inspect controller capability boundary")
	}
	for _, entry := range es {
		b, e := os.ReadFile("/proc/self/task/" + entry.Name() + "/status")
		if os.IsNotExist(e) {
			continue
		} // Exited threads cannot create descendants.
		if e != nil {
			return e
		}
		if e = quotaCapsAbsent(string(b)); e != nil {
			return e
		}
	}
	return nil
}
func quotaMountID(raw string) (string, error) {
	var id string
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == "mnt_id:" {
			if len(f) != 2 || id != "" {
				return "", errors.New("ambiguous mount identity")
			}
			n, e := strconv.ParseUint(f[1], 10, 64)
			if e != nil || n == 0 || strconv.FormatUint(n, 10) != f[1] {
				return "", errors.New("invalid mount identity")
			}
			id = f[1]
		}
	}
	if id == "" {
		return "", errors.New("missing mount identity")
	}
	return id, nil
}
func quotaMountEnforced(raw, id, device string) error {
	found := 0
	for _, line := range strings.Split(raw, "\n") {
		sides := strings.Split(line, " - ")
		if len(sides) != 2 {
			continue
		}
		left, right := strings.Fields(sides[0]), strings.Fields(sides[1])
		if len(left) < 6 || left[0] != id {
			continue
		}
		found++
		if left[2] != device || len(right) != 3 || right[0] != "ext4" || !hasQuotaOption(left[5], "rw") || !hasQuotaOption(right[2], "prjquota") {
			return errors.New("quota requires the exact writable ext4 mount with enforced prjquota")
		}
	}
	if found != 1 {
		return errors.New("quota mount identity is missing or ambiguous")
	}
	return nil
}
func hasQuotaOption(raw, want string) bool {
	for _, s := range strings.Split(raw, ",") {
		if s == want {
			return true
		}
	}
	return false
}
func ioctlQuota(fd uintptr, request uintptr, p unsafe.Pointer) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, fd, request, uintptr(p))
	runtime.KeepAlive(p)
	if e != 0 {
		return e
	}
	return nil
}
func inspectQuotaMount(f *os.File, uuid string) (string, error) {
	var st unix.Stat_t
	var stats unix.Statfs_t
	if e := unix.Fstat(int(f.Fd()), &st); e != nil {
		return "", e
	}
	if e := unix.Fstatfs(int(f.Fd()), &stats); e != nil {
		return "", e
	}
	if stats.Type != unix.EXT4_SUPER_MAGIC || stats.Flags&unix.ST_RDONLY != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return "", errors.New("quota runtime must be writable ext4")
	}
	u := ext4UUID{Length: 16}
	if e := ioctlQuota(f.Fd(), getExt4UUID, unsafe.Pointer(&u)); e != nil {
		return "", e
	}
	if u.Length != 16 || u.Flags != 0 || hex.EncodeToString(u.Value[:]) != uuid {
		return "", errors.New("quota runtime filesystem UUID changed")
	}
	b, e := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", f.Fd()))
	if e != nil {
		return "", e
	}
	id, e := quotaMountID(string(b))
	if e != nil {
		return "", e
	}
	b, e = os.ReadFile("/proc/self/mountinfo")
	if e != nil {
		return "", e
	}
	if e = quotaMountEnforced(string(b), id, fmt.Sprintf("%d:%d", unix.Major(st.Dev), unix.Minor(st.Dev))); e != nil {
		return "", e
	}
	return id, nil
}
func openProjectQuota(cfg Config) (*projectQuota, error) {
	if cfg.Quota == nil {
		return nil, nil
	}
	if e := cfg.Quota.validate(cfg.UIDCount); e != nil {
		return nil, e
	}
	if e := checkQuotaCapabilities(); e != nil {
		return nil, e
	}
	if e := securePath(cfg.RuntimeRoot); e != nil {
		return nil, e
	}
	fd, e := unix.Open(cfg.RuntimeRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	q := &projectQuota{cfg: cfg, anchor: os.NewFile(uintptr(fd), "quota-runtime-anchor")}
	ok := false
	defer func() {
		if !ok {
			q.anchor.Close()
		}
	}()
	q.mountID, e = inspectQuotaMount(q.anchor, cfg.Quota.FilesystemUUID)
	if e != nil {
		return nil, e
	}
	var format uint32
	if e = q.call(0x800004, 0, unsafe.Pointer(&format)); e != nil {
		return nil, e
	}
	if format != 4 {
		return nil, errors.New("quota requires v2 64-bit accounting")
	}
	a, e := readProjectAttr(q.anchor)
	if e != nil {
		return nil, e
	}
	if a.ID != 0 || a.Flags&projectInherit != 0 {
		return nil, errors.New("quota runtime root must be unassigned project zero without inheritance")
	}
	q.get = func(id uint32) (projectRecord, error) {
		var r projectRecord
		e := q.call(0x800007, id, unsafe.Pointer(&r))
		return r, e
	}
	q.set = func(id uint32, r projectRecord) error { return q.call(0x800008, id, unsafe.Pointer(&r)) }
	q.sync = func() error {
		return quotaCommitBarrier(func() error { return q.call(0x800001, 0, nil) }, func() error { return unix.Syncfs(int(q.anchor.Fd())) })
	}
	ok = true
	return q, nil
}

// ext4's internal journalled quota uses DQUOT_QUOTA_SYS_FILE/NOLIST_DIRTY:
// Linux v6.8 dquot_quota_sync may return without sync_fs or sync_blockdev.
// Commit this exact anchored filesystem before Prepare or owner release may
// proceed. This is filesystem-wide, not a per-project flush or bounded IO.
func quotaCommitBarrier(quotaSync, filesystemSync func() error) error {
	if e := quotaSync(); e != nil {
		return e
	}
	return filesystemSync()
}
func (q *projectQuota) revalidate() error {
	if e := checkQuotaCapabilities(); e != nil {
		return e
	}
	if e := securePath(q.cfg.RuntimeRoot); e != nil {
		return e
	}
	f, e := os.Open(q.cfg.RuntimeRoot)
	if e != nil {
		return e
	}
	defer f.Close()
	id, e := inspectQuotaMount(f, q.cfg.Quota.FilesystemUUID)
	if e != nil {
		return e
	}
	if id != q.mountID {
		return errors.New("quota runtime mount was replaced")
	}
	id, e = inspectQuotaMount(q.anchor, q.cfg.Quota.FilesystemUUID)
	if e != nil {
		return e
	}
	if id != q.mountID {
		return errors.New("quota runtime anchor lost its mount")
	}
	return nil
}
func (q *projectQuota) call(command, id uint32, value unsafe.Pointer) error {
	switch command {
	case 0x800001, 0x800004:
		if id != 0 {
			return errors.New("invalid quota global selector")
		}
	case 0x800007, 0x800008:
		if id < q.cfg.Quota.ProjectStart || uint64(id) >= uint64(q.cfg.Quota.ProjectStart)+uint64(q.cfg.UIDCount) {
			return errors.New("quota project outside reserved policy")
		}
	default:
		return errors.New("quota command is not allowed")
	}
	_, _, e := unix.Syscall6(unix.SYS_QUOTACTL_FD, q.anchor.Fd(), uintptr(command<<8|2), uintptr(id), uintptr(value), 0, 0)
	runtime.KeepAlive(q)
	runtime.KeepAlive(value)
	if e != 0 {
		return e
	}
	return nil
}
func emptyProject(r projectRecord) bool {
	return r.BHard|r.BSoft|r.Space|r.IHard|r.ISoft|r.Inodes|r.BTime|r.ITime == 0
}
func (q *projectQuota) limits() projectRecord {
	return projectRecord{BHard: q.cfg.Quota.MaxBytes >> 10, IHard: q.cfg.Quota.MaxInodes, Valid: 1 | 4 | 16 | 32}
}
func (q *projectQuota) knownRecord(r projectRecord) bool {
	if emptyProject(r) {
		return true
	}
	want := q.limits()
	return r.BHard == want.BHard && r.IHard == want.IHard && r.BSoft == 0 && r.ISoft == 0 && r.BTime == 0 && r.ITime == 0 && r.Space <= q.cfg.Quota.MaxBytes && r.Inodes <= q.cfg.Quota.MaxInodes
}
func (q *projectQuota) reconcile(owners map[string]ownership) error {
	known := map[uint32]ownership{}
	for _, o := range owners {
		if !validOwnership(o, q.cfg) {
			return errors.New("invalid durable quota ownership")
		}
		known[o.ProjectID] = o
	}
	for n := 0; n < q.cfg.UIDCount; n++ {
		id := q.cfg.Quota.ProjectStart + uint32(n)
		r, e := q.get(id)
		if e != nil {
			return e
		}
		o, owned := known[id]
		if (!owned || !o.QuotaAttempted) && !emptyProject(r) {
			return errors.New("unowned nonempty quota record requires operator reconciliation")
		}
		if owned && o.QuotaAttempted && !q.knownRecord(r) {
			return errors.New("owned quota limits or usage conflict with immutable policy")
		}
	}
	return nil
}
func (q *projectQuota) reserve(o ownership, markAttempt func() error) error {
	if e := q.revalidate(); e != nil {
		return e
	}
	return q.reserveKnown(o, markAttempt)
}
func (q *projectQuota) reserveKnown(o ownership, markAttempt func() error) error {
	if !validOwnership(o, q.cfg) || o.QuotaAttempted || markAttempt == nil {
		return errors.New("fresh durable quota ownership required before limits")
	}
	r, e := q.get(o.ProjectID)
	if e != nil {
		return e
	}
	if !emptyProject(r) {
		return errors.New("new generation quota is not empty")
	}
	if e = markAttempt(); e != nil {
		return e
	}
	want := q.limits()
	if e = q.set(o.ProjectID, want); e != nil {
		return e
	}
	r, e = q.get(o.ProjectID)
	if e != nil {
		return e
	}
	if r.BHard != want.BHard || r.IHard != want.IHard || !q.knownRecord(r) || r.Space != 0 || r.Inodes != 0 {
		return errors.New("quota limit readback mismatch")
	}
	return q.sync()
}
func (q *projectQuota) release(o ownership) error {
	if !validOwnership(o, q.cfg) {
		return errors.New("known quota ownership required for release")
	}
	if e := q.revalidate(); e != nil {
		return e
	}
	k, e := key(o.Ref)
	if e != nil {
		return e
	}
	for _, path := range []string{filepath.Join(q.cfg.CgroupRoot, k), filepath.Join(q.cfg.RuntimeRoot, "j/firecracker", k)} {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			return errors.New("quota resources remain; ownership cannot be released")
		}
	}
	return q.clearKnown(o)
}
func (q *projectQuota) clearKnown(o ownership) error {
	// All handles/writers and the exact generation jail must be gone before
	// registry calls this hook. In-use or mismatched records are never reset.
	if e := q.sync(); e != nil {
		return e
	}
	r, e := q.get(o.ProjectID)
	if e != nil {
		return e
	}
	if !o.QuotaAttempted {
		if !emptyProject(r) {
			return errors.New("quota record was never claimed by this owner")
		}
		return nil
	}
	if !q.knownRecord(r) || r.Space != 0 || r.Inodes != 0 {
		return errors.New("quota usage remains or immutable limits changed; retain ownership")
	}
	if e = q.set(o.ProjectID, projectRecord{Valid: 1 | 4 | 16 | 32}); e != nil {
		return e
	}
	if e = q.sync(); e != nil {
		return e
	}
	r, e = q.get(o.ProjectID)
	if e != nil {
		return e
	}
	if !emptyProject(r) {
		return errors.New("quota clear was not confirmed")
	}
	return nil
}
func readProjectAttr(f *os.File) (projectAttr, error) {
	var a projectAttr
	e := ioctlQuota(f.Fd(), getProjectAttr, unsafe.Pointer(&a))
	return a, e
}
func (q *projectQuota) setDir(path string, o ownership, inherit bool) error {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), "quota-directory")
	defer f.Close()
	id, e := quotaFDMountID(f)
	if e != nil {
		return e
	}
	if id != q.mountID {
		return errors.New("generation directory crosses quota mount")
	}
	a, e := readProjectAttr(f)
	if e != nil {
		return e
	}
	if a.ID != 0 && a.ID != o.ProjectID {
		return errors.New("generation directory belongs to another project")
	}
	a.ID = o.ProjectID
	a.Flags &^= projectInherit
	if inherit {
		a.Flags |= projectInherit
	}
	if e = ioctlQuota(f.Fd(), setProjectAttr, unsafe.Pointer(&a)); e != nil {
		return e
	}
	got, e := readProjectAttr(f)
	if e != nil {
		return e
	}
	if got.ID != o.ProjectID || (got.Flags&projectInherit != 0) != inherit {
		return errors.New("project inheritance readback mismatch")
	}
	return f.Sync()
}
func quotaFDMountID(f *os.File) (string, error) {
	b, e := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", f.Fd()))
	if e != nil {
		return "", e
	}
	return quotaMountID(string(b))
}
func (q *projectQuota) verifyPrepared(jail string, o ownership) error {
	if e := q.revalidate(); e != nil {
		return e
	}
	count := uint64(0)
	return filepath.WalkDir(jail, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		count++
		if count > q.cfg.Quota.MaxInodes+2 {
			return errors.New("unexpected prepared inode count")
		}
		if d.Type()&os.ModeSymlink != 0 || (!d.IsDir() && !d.Type().IsRegular()) {
			return errors.New("unexpected prepared inode type")
		}
		fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return e
		}
		f := os.NewFile(uintptr(fd), "prepared-quota-inode")
		defer f.Close()
		id, e := quotaFDMountID(f)
		if e != nil {
			return e
		}
		if id != q.mountID {
			return errors.New("prepared inode crosses mount")
		}
		a, e := readProjectAttr(f)
		if e != nil {
			return e
		}
		shared := q.cfg.Snapshot != nil && (path == filepath.Join(jail, "root/template.mem") || path == filepath.Join(jail, "root/template.state"))
		if shared {
			info, e := f.Stat()
			if e != nil {
				return e
			}
			var st unix.Stat_t
			if e = unix.Fstat(int(f.Fd()), &st); e != nil {
				return e
			}
			if a.ID != 0 || !info.Mode().IsRegular() || st.Uid != 0 || info.Mode().Perm()&0222 != 0 {
				return errors.New("shared template must remain root-owned read-only project zero")
			}
		} else if a.ID != o.ProjectID || (d.IsDir() && a.Flags&projectInherit == 0) {
			return errors.New("mutable prepared inode lacks sealed project inheritance")
		}
		return nil
	})
}

// Read-only admission guard. The extra inherited filter is installed before
// jailer exec; at READY the pinned VMM must also have its normal seccomp filter.
func (q *projectQuota) verifyDomain(group string, o ownership) error {
	data, e := os.ReadFile(filepath.Join(group, "cgroup.procs"))
	if e != nil {
		return e
	}
	want := "0::/" + strings.TrimPrefix(group, "/sys/fs/cgroup/")
	vmm := false
	for _, pid := range strings.Fields(string(data)) {
		n, e := strconv.ParseUint(pid, 10, 32)
		if e != nil || n == 0 || strconv.FormatUint(n, 10) != pid {
			return errors.New("invalid quota domain process")
		}
		base := "/proc/" + pid
		membership, e := os.ReadFile(base + "/cgroup")
		if e != nil {
			return e
		}
		if strings.TrimSpace(string(membership)) != want {
			return errors.New("quota process left its execution domain")
		}
		status, e := os.ReadFile(base + "/status")
		if e != nil {
			return e
		}
		if e = quotaCapsAbsent(string(status)); e != nil {
			return e
		}
		fields := map[string][]string{}
		for _, line := range strings.Split(string(status), "\n") {
			f := strings.Fields(line)
			if len(f) > 1 {
				if _, ok := fields[f[0]]; ok {
					return errors.New("duplicate process status")
				}
				fields[f[0]] = f[1:]
			}
		}
		if len(fields["NoNewPrivs:"]) != 1 || fields["NoNewPrivs:"][0] != "1" || len(fields["Seccomp:"]) != 1 || fields["Seccomp:"][0] != "2" || len(fields["Seccomp_filters:"]) != 1 {
			return errors.New("quota mutation filter or no-new-privileges missing")
		}
		filters, e := strconv.ParseUint(fields["Seccomp_filters:"][0], 10, 32)
		if e != nil || filters < 1 {
			return errors.New("quota mutation filter missing")
		}
		ids := fields["Uid:"]
		if len(ids) != 4 {
			return errors.New("missing execution-domain credentials")
		}
		if ids[0] != ids[1] || ids[0] != ids[2] || ids[0] != ids[3] {
			return errors.New("ambiguous execution-domain credentials")
		}
		if ids[0] == strconv.Itoa(o.UID) {
			if filters < 2 {
				return errors.New("VMM default and quota seccomp filters required")
			}
			vmm = true
		} else if ids[0] != "0" {
			return errors.New("unexpected execution-domain UID")
		}
		after, e := os.ReadFile(base + "/cgroup")
		if e != nil || string(after) != string(membership) {
			return errors.New("quota process membership changed during admission")
		}
	}
	if !vmm {
		return errors.New("quota admission requires the reserved VMM process")
	}
	return nil
}
