//go:build linux && xandbox_host_fixture

package main

// Fixed ordinary-daemon integration fixture, separate from the prerequisite
// writer. Only L1 PID1 may read these four reserved project records; only the
// ordinary driver sets or clears their limits. No generic command/ID surface.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const driverProjectFirst uint32 = 1300000

type driverQuotaReceipt struct {
	Phase           string
	NamespaceBlocks uint64
	NamespaceInodes uint64
	Jail            string
	Project         uint32
	Record          quotaRecord
}

func runQuotaDaemon() error {
	if e := requireQuotaChild(); e != nil {
		return e
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, unix.CAP_SYS_RESOURCE, 0); e != 0 {
		return e
	}
	return unix.Exec("/srv/assets/sandboxd", []string{"sandboxd", "-backend", "firecracker", "-state-dir", "/srv/state", "-auth-file", "/srv/config/auth.json", "-firecracker-config", "/srv/config/backend.json", "-max-instances", "1", "-metrics"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
}
func driverQuotaRead(id uint32) (quotaRecord, error) {
	var r quotaRecord
	if id < driverProjectFirst || id >= driverProjectFirst+4 {
		return r, errors.New("fixed driver quota project required")
	}
	q, e := openQuotaFS(false)
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
func driverQuotaAllClear() error {
	for id := driverProjectFirst; id < driverProjectFirst+4; id++ {
		r, e := driverQuotaRead(id)
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
	qr := driverQuotaReceipt{Phase: phase}
	if phase == "destroyed" {
		if e = driverQuotaAllClear(); e != nil {
			return nil, e
		}
	} else {
		k := old.Ref.ID + old.Ref.Generation
		b, e = os.ReadFile("/srv/state/firecracker/" + k + ".json")
		if e != nil {
			return nil, e
		}
		var owner struct {
			Version int    `json:"version"`
			Project uint32 `json:"project_id"`
			Attempt bool   `json:"quota_attempted"`
		}
		if e = json.Unmarshal(b, &owner); e != nil {
			return nil, e
		}
		if owner.Version != 3 || !owner.Attempt {
			return nil, errors.New("ordinary driver did not persist project ownership before limit setup")
		}
		jail := "/srv/r/j/firecracker/" + k
		for _, path := range []string{jail, jail + "/root"} {
			a, e := quotaAttributes(path, nil)
			if e != nil || a.Project != owner.Project || a.XFlags&quotaInherit == 0 {
				return nil, errors.New("jail/project inheritance not set")
			}
		}
		for _, name := range []string{"workspace.ext4", "kernel", "initrd", "firecracker"} {
			path := jail + "/root/" + name
			fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if e != nil {
				return nil, e
			}
			f := os.NewFile(uintptr(fd), "private-integration-file")
			e = f.Sync()
			f.Close()
			if e != nil {
				return nil, e
			}
			a, e := quotaAttributes(path, nil)
			if e != nil || a.Project != owner.Project {
				return nil, errors.New("mutable prepared file outside instance project")
			}
		}
		q, e := openQuotaFS(false)
		if e != nil {
			return nil, e
		}
		e = q.sync()
		q.file.Close()
		if e != nil {
			return nil, e
		}
		qr.Jail = jail
		qr.NamespaceBlocks, qr.NamespaceInodes, e = driverQuotaNamespace(jail)
		if e != nil {
			return nil, e
		}
		qr.Project = owner.Project
		qr.Record, e = driverQuotaRead(owner.Project)
		if e != nil {
			return nil, e
		}
		if qr.Record.BHard != 192<<10 || qr.Record.IHard != 128 || qr.Record.Space < 128<<20 || qr.Record.Space > 192<<20 || qr.Record.Inodes == 0 || qr.Record.Inodes > 128 {
			return nil, errors.New("ordinary driver quota limits/usage mismatch")
		}
		out["private_project_space_bytes"] = qr.Record.Space
		out["private_project_inodes"] = qr.Record.Inodes
		if phase == "running" {
			procs, e := os.ReadFile(nodeGroup + "/" + k + "/cgroup.procs")
			if e != nil {
				return nil, e
			}
			vmm := false
			for _, pid := range strings.Fields(string(procs)) {
				status, e := os.ReadFile("/proc/" + pid + "/status")
				if e != nil {
					return nil, e
				}
				for _, field := range []string{"CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb"} {
					present, e := capabilityPresent(string(status), field, unix.CAP_SYS_RESOURCE)
					if e != nil || present {
						return nil, errors.New("execution domain can bypass quota")
					}
				}
				if !strings.Contains(string(status), "NoNewPrivs:\t1\n") || !strings.Contains(string(status), "Seccomp:\t2\n") {
					return nil, errors.New("execution domain lacks inherited quota filter")
				}
				for _, line := range strings.Split(string(status), "\n") {
					f := strings.Fields(line)
					if len(f) == 2 && f[0] == "Seccomp_filters:" {
						count, e := strconv.Atoi(f[1])
						if e != nil {
							return nil, e
						}
						if count >= 2 {
							vmm = true
						}
					}
				}
			}
			if !vmm {
				return nil, errors.New("pinned VMM default plus quota filters not observed")
			}
			out["quota_filter_inherited_with_default_vmm_seccomp"] = true
		}
	}
	if e = privateWrite("/srv/fixture/driver-quota-receipt.json", qr); e != nil {
		return nil, e
	}
	out["ordinary_driver_quota_enabled"] = true
	out["durable_project_ownership_checked"] = true
	out["mutable_project_inheritance_checked"] = true
	return out, nil
}
func verifyDriverQuotaColdBoot() (map[string]any, error) {
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
	if old.Phase == "destroyed" {
		if e = driverQuotaAllClear(); e != nil {
			return nil, e
		}
	} else {
		r, e := driverQuotaRead(old.Project)
		if e != nil {
			return nil, e
		}
		if r != old.Record {
			blocks, inodes, statErr := driverQuotaNamespace(old.Jail)
			fmt.Fprintf(os.Stderr, "private quota coldboot numeric diagnostic: before=%+v after=%+v; named-before blocks=%d inodes=%d; named-after blocks=%d inodes=%d stat-error=%v\n", old.Record, r, old.NamespaceBlocks, old.NamespaceInodes, blocks, inodes, statErr)
			// Keep the failure strict; allow only the private UART diagnostic to drain.
			time.Sleep(200 * time.Millisecond)
			return nil, fmt.Errorf("ordinary driver quota record changed across coldboot")
		}
	}
	return map[string]any{"quota_record_survived_cold_boot": true}, nil
}

func driverQuotaNamespace(jail string) (uint64, uint64, error) {
	if e := requireNode(); e != nil {
		return 0, 0, e
	}
	if !strings.HasPrefix(jail, "/srv/r/j/firecracker/") || len(strings.TrimPrefix(jail, "/srv/r/j/firecracker/")) != 64 || filepath.Clean(jail) != jail {
		return 0, 0, errors.New("fixed private generation jail required")
	}
	seen := map[uint64]bool{}
	blocks := uint64(0)
	inodes := uint64(0)
	e := filepath.WalkDir(jail, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		var st unix.Stat_t
		if e = unix.Lstat(path, &st); e != nil {
			return e
		}
		if seen[st.Ino] {
			return nil
		}
		seen[st.Ino] = true
		inodes++
		if inodes > 256 {
			return errors.New("bounded fixed quota diagnostic exceeded")
		}
		blocks += uint64(st.Blocks) * 512
		return nil
	})
	return blocks, inodes, e
}
