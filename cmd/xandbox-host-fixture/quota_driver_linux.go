//go:build linux && xandbox_host_fixture

package main

// Fixed ordinary-daemon integration fixture, separate from the prerequisite
// writer. Only L1 PID1 may read these four reserved project records; only the
// ordinary driver sets or clears their limits. No generic command/ID surface.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const driverProjectFirst uint32 = 1300000

type driverQuotaEntry struct {
	Inode, Links, Device uint64
	Mode, UID, GID       uint32
	Shared               bool
	Size                 int64
	Blocks               uint64
}
type driverQuotaReceipt struct {
	Snapshot bool
	Entries  map[string]driverQuotaEntry

	Phase           string
	NamespaceBlocks uint64
	NamespaceInodes uint64
	Jail            string
	Project         uint32
	Record          quotaRecord
}

func runQuotaDaemon() error { return runQuotaDaemonCapacity(1) }
func runQuotaDaemonCapacity(capacity int) error {
	if e := requireQuotaChild(); e != nil {
		return e
	}
	if capacity != 1 && capacity != 2 {
		return errors.New("fixed driver capacity required")
	}
	if capacity == 2 {
		if _, e := os.Stat("/srv/config/snapshot-fixture.json"); e != nil {
			return e
		}
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, unix.CAP_SYS_RESOURCE, 0); e != 0 {
		return e
	}
	return unix.Exec("/srv/assets/sandboxd", []string{"sandboxd", "-backend", "firecracker", "-state-dir", "/srv/state", "-auth-file", "/srv/config/auth.json", "-firecracker-config", "/srv/config/backend.json", "-max-instances", strconv.Itoa(capacity), "-metrics"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
}
func driverQuotaRead(id uint32) (quotaRecord, error) { return driverQuotaReadOn(id, nil) }
func driverQuotaReadOn(id uint32, mapper *stateMapper) (quotaRecord, error) {
	var r quotaRecord
	if id < driverProjectFirst || id >= driverProjectFirst+4 {
		return r, errors.New("fixed driver quota project required")
	}
	q, e := openQuotaFSWithMapper(false, mapper)
	if e != nil {
		return r, e
	}
	defer q.file.Close()
	_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL_FD, q.file.Fd(), 0x80000702, uintptr(id), uintptr(unsafe.Pointer(&r)), 0, 0)
	if errno != 0 {
		return r, errno
	}
	return r, nil
}
func driverQuotaAllClear() error { return driverQuotaAllClearOn(nil) }
func driverQuotaAllClearOn(mapper *stateMapper) error {
	for id := driverProjectFirst; id < driverProjectFirst+4; id++ {
		r, e := driverQuotaReadOn(id, mapper)
		if e != nil {
			return e
		}
		if !quotaEmpty(r) {
			return errors.New("ordinary driver retained project accounting or limits")
		}
	}
	return nil
}
func (n *node) quotaDriverCheckpoint(ctx context.Context, phase string) (map[string]any, error) {
	out, e := n.checkpoint(ctx, phase)
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile("/srv/fixture/receipt.json")
	if e != nil {
		return nil, e
	}
	var old nodeReceipt
	if e = strictjson.Decode(b, &old); e != nil {
		return nil, e
	}
	qr, observed, e := n.observeDriverQuota(old.Ref, phase, nil)
	if e != nil {
		return nil, e
	}
	for k, v := range observed {
		out[k] = v
	}
	if e = privateWrite("/srv/fixture/driver-quota-receipt.json", qr); e != nil {
		return nil, e
	}
	out["ordinary_driver_quota_enabled"] = true
	out["durable_project_ownership_checked"] = true
	out["mutable_project_inheritance_checked"] = true
	return out, nil
}
func (n *node) observeDriverQuota(ref sandbox.Ref, phase string, mapper *stateMapper) (qr driverQuotaReceipt, out map[string]any, err error) {
	if e := requireNode(); e != nil {
		return qr, nil, e
	}
	var b []byte
	var e error
	out = map[string]any{}
	qr = driverQuotaReceipt{Phase: phase, Snapshot: n.quotaSnapshot}
	if phase == "destroyed" {
		if e = driverQuotaAllClearOn(mapper); e != nil {
			return qr, nil, e
		}
	} else {
		k := ref.ID + ref.Generation
		b, e = os.ReadFile("/srv/state/firecracker/" + k + ".json")
		if e != nil {
			return qr, nil, e
		}
		var owner struct {
			Version int    `json:"version"`
			Project uint32 `json:"project_id"`
			Attempt bool   `json:"quota_attempted"`
		}
		if e = json.Unmarshal(b, &owner); e != nil {
			return qr, nil, e
		}
		wantVersion := 3
		if n.quotaSnapshot {
			wantVersion = 4
		}
		if owner.Version != wantVersion || !owner.Attempt {
			return qr, nil, errors.New("ordinary driver did not persist project ownership before limit setup")
		}
		jail := "/srv/r/j/firecracker/" + k
		for _, path := range []string{jail, jail + "/root"} {
			a, e := quotaAttributes(path, nil)
			if e != nil || a.Project != owner.Project || a.XFlags&quotaInherit == 0 {
				return qr, nil, errors.New("jail/project inheritance not set")
			}
		}
		for _, name := range privateQuotaAssets(n.quotaSnapshot) {
			path := jail + "/root/" + name
			fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if e != nil {
				return qr, nil, e
			}
			f := os.NewFile(uintptr(fd), "private-integration-file")
			e = f.Sync()
			f.Close()
			if e != nil {
				return qr, nil, e
			}
			a, e := quotaAttributes(path, nil)
			if e != nil || a.Project != owner.Project {
				return qr, nil, errors.New("mutable prepared file outside instance project")
			}
		}
		q, e := openQuotaFSWithMapper(false, mapper)
		if e != nil {
			return qr, nil, e
		}
		e = q.sync()
		q.file.Close()
		if e != nil {
			return qr, nil, e
		}
		qr.Jail = jail
		qr.NamespaceBlocks, qr.NamespaceInodes, qr.Entries, e = driverQuotaTree(jail, n.quotaSnapshot)
		if e != nil {
			return qr, nil, e
		}
		qr.Project = owner.Project
		qr.Record, e = driverQuotaReadOn(owner.Project, mapper)
		if e != nil {
			return qr, nil, e
		}
		if qr.Record.BHard != 192<<10 || qr.Record.IHard != 128 || qr.Record.Space < 128<<20 || qr.Record.Space > 192<<20 || qr.Record.Inodes == 0 || qr.Record.Inodes > 128 {
			return qr, nil, errors.New("ordinary driver quota limits/usage mismatch")
		}
		if e = validateDriverQuotaAccounting(qr, qr.Record, qr.NamespaceBlocks, qr.NamespaceInodes, qr.Entries); e != nil {
			return qr, nil, e
		}
		out["linked_namespace_accounted_before_cut"] = true
		if n.quotaSnapshot {
			if e = verifySharedQuotaFiles(jail); e != nil {
				return qr, nil, e
			}
			out["shared_inodes_not_charged_to_clone"] = true
			out["snapshot_owner_version4_checked"] = true
		}
		out["private_project_space_bytes"] = qr.Record.Space
		out["private_project_inodes"] = qr.Record.Inodes
		if phase == "running" {
			procs, e := os.ReadFile(nodeGroup + "/" + k + "/cgroup.procs")
			if e != nil {
				return qr, nil, e
			}
			vmm := false
			for _, pid := range strings.Fields(string(procs)) {
				status, e := os.ReadFile("/proc/" + pid + "/status")
				if e != nil {
					return qr, nil, e
				}
				for _, field := range []string{"CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb"} {
					present, e := capabilityPresent(string(status), field, unix.CAP_SYS_RESOURCE)
					if e != nil || present {
						return qr, nil, errors.New("execution domain can bypass quota")
					}
				}
				if !strings.Contains(string(status), "NoNewPrivs:\t1\n") || !strings.Contains(string(status), "Seccomp:\t2\n") {
					return qr, nil, errors.New("execution domain lacks inherited quota filter")
				}
				for _, line := range strings.Split(string(status), "\n") {
					f := strings.Fields(line)
					if len(f) == 2 && f[0] == "Seccomp_filters:" {
						count, e := strconv.Atoi(f[1])
						if e != nil {
							return qr, nil, e
						}
						if count >= 2 {
							vmm = true
						}
					}
				}
			}
			if !vmm {
				return qr, nil, errors.New("pinned VMM default plus quota filters not observed")
			}
			out["quota_filter_inherited_with_default_vmm_seccomp"] = true
		}
	}
	out["ordinary_driver_quota_enabled"] = true
	out["durable_project_ownership_checked"] = true
	out["mutable_project_inheritance_checked"] = true
	return qr, out, nil
}
func verifyDriverQuotaColdBoot() (map[string]any, error) { return verifyDriverQuotaColdBootOn(nil) }
func verifyDriverQuotaColdBootOn(mapper *stateMapper) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	b, e := os.ReadFile("/srv/fixture/driver-quota-receipt.json")
	if e != nil {
		return nil, e
	}
	var old driverQuotaReceipt
	if e = strictjson.Decode(b, &old); e != nil {
		return nil, e
	}
	result := map[string]any{"quota_limits_and_ownership_survived_cold_boot": true, "quota_accounting_matches_recovered_namespace": true}
	if old.Phase == "destroyed" {
		if e = driverQuotaAllClearOn(mapper); e != nil {
			return nil, e
		}
	} else {
		r, e := driverQuotaReadOn(old.Project, mapper)
		if e != nil {
			return nil, e
		}
		blocks, inodes, entries, statErr := driverQuotaTree(old.Jail, old.Snapshot)
		if statErr != nil {
			return nil, statErr
		}
		if e = validateDriverQuotaAccounting(old, r, blocks, inodes, entries); e != nil {
			fmt.Fprintf(os.Stderr, "private quota coldboot comparison failed: before=%+v after=%+v; named-after blocks=%d inodes=%d\n", old.Record, r, blocks, inodes)
			return nil, e
		}
		result["quota_charge_before_cold_boot_bytes"] = old.Record.Space
		result["quota_charge_after_cold_boot_bytes"] = r.Space
		if before, ok := old.Entries["root/firecracker.pid"]; ok {
			after := entries["root/firecracker.pid"]
			result["non_authoritative_pid_file_not_used_for_recovery"] = true
			result["pid_file_was_empty_after_cold_boot"] = before.Size > 0 && after.Size == 0
		}
		if old.Snapshot {
			if e = verifySharedQuotaFiles(old.Jail); e != nil {
				return nil, e
			}
			result["shared_template_project_zero_after_cold_boot"] = true
		}
		// A live VM may change backing allocation after the checkpoint. Limits
		// must be immutable; recovered charge must match independent inode stats.
		paths := []string{old.Jail, old.Jail + "/root"}
		for _, name := range privateQuotaAssets(old.Snapshot) {
			paths = append(paths, old.Jail+"/root/"+name)
		}
		for _, path := range paths {
			a, e := quotaAttributes(path, nil)
			if e != nil || a.Project != old.Project {
				return nil, errors.New("persistent private project attribute mismatch")
			}
			if (path == old.Jail || path == old.Jail+"/root") && a.XFlags&quotaInherit == 0 {
				return nil, errors.New("persistent project inheritance missing")
			}
		}
		immutable := []string{"kernel", "initrd", "firecracker"}
		if old.Snapshot {
			immutable = []string{"firecracker"}
		}
		for _, name := range immutable {
			actual, e := fileHash(old.Jail + "/root/" + name)
			if e != nil {
				return nil, e
			}
			want, e := fileHash("/srv/assets/" + name)
			if e != nil || want != actual {
				return nil, errors.New("immutable staged asset contents changed across coldboot")
			}
		}
	}
	return result, nil
}

func driverQuotaTree(jail string, snapshot bool) (uint64, uint64, map[string]driverQuotaEntry, error) {
	if e := requireNode(); e != nil {
		return 0, 0, nil, e
	}
	suffix := strings.TrimPrefix(jail, "/srv/r/j/firecracker/")
	if suffix == jail || len(suffix) != 64 || strings.Trim(suffix, "0123456789abcdef") != "" {
		return 0, 0, nil, errors.New("fixed private generation jail required")
	}
	seen := map[uint64]bool{}
	entries := map[string]driverQuotaEntry{}
	var blocks, inodes uint64
	e := filepath.WalkDir(jail, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		var st unix.Stat_t
		if e = unix.Lstat(path, &st); e != nil {
			return e
		}
		rel, e := filepath.Rel(jail, path)
		if e != nil {
			return e
		}
		shared := snapshot && (rel == "root/template.mem" || rel == "root/template.state")
		entries[rel] = driverQuotaEntry{Shared: shared, Inode: st.Ino, Links: uint64(st.Nlink), Device: uint64(st.Rdev), Mode: st.Mode, UID: st.Uid, GID: st.Gid, Size: st.Size, Blocks: uint64(st.Blocks) * 512}
		if len(entries) > 256 {
			return errors.New("bounded fixed quota diagnostic exceeded")
		}
		if !shared && !seen[st.Ino] {
			seen[st.Ino] = true
			inodes++
			blocks += uint64(st.Blocks) * 512
		}
		return nil
	})
	return blocks, inodes, entries, e
}
func validateDriverQuotaAccounting(old driverQuotaReceipt, actual quotaRecord, blocks, inodes uint64, entries map[string]driverQuotaEntry) error {
	// Current charge is mutable, not an immutable policy field. Never accept
	// limit drift, unaccounted physical allocation, lost names or lost identity.
	want := old.Record
	if actual.BHard != 192<<10 || actual.IHard != 128 || actual.BHard != want.BHard || actual.IHard != want.IHard ||
		actual.BSoft != 0 || actual.ISoft != 0 || actual.BTime != 0 || actual.ITime != 0 ||
		actual.Valid != want.Valid || actual.Space > 192<<20 || actual.Inodes > 128 ||
		actual.Space < 128<<20 || actual.Inodes == 0 || actual.Space != blocks || actual.Inodes != inodes || len(old.Entries) == 0 || len(entries) != len(old.Entries) {
		return errors.New("quota limits or independent recovered allocation mismatch")
	}
	for path, before := range old.Entries {
		after, ok := entries[path]
		if !ok {
			return errors.New("persistent jail entry lost")
		}
		before.Blocks, after.Blocks = 0, 0
		// The pinned jailer writes this diagnostic PID file without fsync.
		// Its bytes are NOT ownership or kill authority. Empty content after
		// power loss is valid; never make recovery depend on a saved PID.
		if path == "root/firecracker.pid" {
			if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 0 || before.Size > 20 || after.Size < 0 || after.Size > 20 {
				return errors.New("unexpected non-authoritative PID file metadata")
			}
			before.Size, after.Size = 0, 0
		}
		if !reflect.DeepEqual(before, after) {
			return errors.New("persistent inode logical metadata changed")
		}
	}
	return nil
}

// Only bounded enums and allocation numbers leave this PRIVATE fixture RPC.
// No raw PID, UID, project, inode number, generation or filesystem path is sent.
func driverQuotaDiagnostic() (map[string]any, error) { return driverQuotaDiagnosticOn(nil) }
func driverQuotaDiagnosticOn(mapper *stateMapper) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	b, e := os.ReadFile("/srv/fixture/driver-quota-receipt.json")
	if e != nil {
		return nil, e
	}
	var old driverQuotaReceipt
	if e = strictjson.Decode(b, &old); e != nil {
		return nil, e
	}
	actual, e := driverQuotaReadOn(old.Project, mapper)
	if e != nil {
		return nil, e
	}
	blocks, inodes, entries, e := driverQuotaTree(old.Jail, old.Snapshot)
	if e != nil {
		return nil, e
	}
	changes := []map[string]any{}
	for path, before := range old.Entries {
		after, ok := entries[path]
		fields := []string{}
		if !ok {
			fields = append(fields, "missing")
		}
		if before.Inode != after.Inode {
			fields = append(fields, "inode_changed")
		}
		if before.Links != after.Links {
			fields = append(fields, "links_changed")
		}
		if before.Device != after.Device {
			fields = append(fields, "device_changed")
		}
		if before.Mode != after.Mode {
			fields = append(fields, "mode_changed")
		}
		if before.UID != after.UID {
			fields = append(fields, "owner_changed")
		}
		if before.GID != after.GID {
			fields = append(fields, "group_changed")
		}
		if before.Size != after.Size {
			fields = append(fields, "size_changed")
		}
		if len(fields) > 0 {
			class := "other"
			switch path {
			case ".":
				class = "jail"
			case "root":
				class = "root_directory"
			case "root/workspace.ext4":
				class = "workspace"
			case "root/kernel":
				class = "kernel"
			case "root/initrd":
				class = "initrd"
			case "root/firecracker":
				class = "vmm_binary"
			case "root/firecracker.pid":
				class = "non_authoritative_pid_file"
			case "root/dev":
				class = "device_directory"
			case "root/dev/net":
				class = "network_device_directory"
			case "root/dev/kvm":
				class = "kvm_device"
			case "root/api.sock":
				class = "api_socket"
			case "root/v.sock":
				class = "vsock_socket"
			}
			row := map[string]any{"entry_class": class, "changed_fields": fields}
			if before.Size != after.Size {
				row["size_before"] = before.Size
				row["size_after"] = after.Size
			}
			changes = append(changes, row)
		}
	}
	return map[string]any{"space_before": old.Record.Space, "space_after": actual.Space, "named_blocks_before": old.NamespaceBlocks, "named_blocks_after": blocks, "inodes_before": old.Record.Inodes, "inodes_after": actual.Inodes, "named_inodes_after": inodes, "block_hard_before": old.Record.BHard, "block_hard_after": actual.BHard, "inode_hard_before": old.Record.IHard, "inode_hard_after": actual.IHard, "changes": changes}, nil
}

func privateQuotaAssets(snapshot bool) []string {
	if snapshot {
		return []string{"workspace.ext4", "firecracker"}
	}
	return []string{"workspace.ext4", "kernel", "initrd", "firecracker"}
}
func sharedQuotaHash(path string, expected int64) (string, error) {
	if expected < 1 || expected > 512<<20 {
		return "", errors.New("bounded shared snapshot size required")
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return "", e
	}
	f := os.NewFile(uintptr(fd), "shared-snapshot-check")
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() != expected {
		return "", errors.New("shared snapshot size/type mismatch")
	}
	h := sha256.New()
	if _, e = io.CopyN(h, f, expected); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func verifySharedQuotaFiles(jail string) error {
	if e := requireNode(); e != nil {
		return e
	}
	b, e := os.ReadFile("/srv/export/manifest.json")
	if e != nil {
		return e
	}
	var m struct {
		Memory     string `json:"memory_sha256"`
		State      string `json:"state_sha256"`
		StateBytes int64  `json:"state_bytes"`
	}
	if e = json.Unmarshal(b, &m); e != nil {
		return e
	}
	for name, item := range map[string]struct {
		hash string
		size int64
	}{"template.mem": {m.Memory, 512 << 20}, "template.state": {m.State, m.StateBytes}} {
		path := jail + "/root/" + name
		a, e := quotaAttributes(path, nil)
		if e != nil || a.Project != 0 {
			return errors.New("shared template left project zero")
		}
		var st unix.Stat_t
		if e = unix.Lstat(path, &st); e != nil {
			return e
		}
		if st.Uid != 0 || st.Mode&0222 != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink < 2 {
			return errors.New("shared template is not a read-only catalog hardlink")
		}
		actual, e := sharedQuotaHash(path, item.size)
		if e != nil || actual != item.hash {
			return errors.New("shared template content changed")
		}
	}
	return nil
}
