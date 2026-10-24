//go:build linux

package launch

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
)

// ServiceFile reads a bounded root-private file through anchored NOFOLLOW FDs.
// It does not make mutable root-owned data immutable or validate its schema.
func ServiceFile(path string, limit int64) ([]byte, error) {
	if limit < 1 || limit > 512<<10 {
		return nil, errPolicy
	}
	f, e := trustedFile(path, true, limit)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, errPolicy
	}
	return b, nil
}
func PinnedServiceFile(a firecracker.Asset, limit int64) ([]byte, error) {
	if limit < 1 || limit > 512<<10 {
		return nil, errPolicy
	}
	return pinnedBytes(a, limit)
}
func StaticServiceELF(a firecracker.Asset) (*os.File, error) { return staticDaemon(a) }
func RejectServiceDescriptors() error                        { return rejectInheritedDescriptors() }
func SystemdService() error {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("root service required")
	}
	s, e := proc("/proc/1/comm", 32)
	if e != nil {
		return e
	}
	if s != "systemd" {
		return errors.New("systemd PID1 required")
	}
	return nil
}
func ServicePlacement(unit string) error {
	value, e := proc("/proc/self/cgroup", 4096)
	if e != nil {
		return e
	}
	if value != "0::"+strings.TrimPrefix(unit, "/sys/fs/cgroup") {
		return errors.New("exact own service placement required")
	}
	return nil
}

// CheckServiceEnvelope is read-only. For a leaf ingress service it also rejects
// helpers, delegated children and any process except the caller. A daemon parent
// instead must have no direct processes; its existing node inventory is validated
// by the ordinary daemon, not adopted or rewritten here.
func CheckServiceEnvelope(path, device string, p ParentEnvelope, leaf bool, pid int) error {
	g, e := openGroupPath(path)
	if e != nil {
		return e
	}
	defer g.Close()
	return checkServiceEnvelope(g, device, p, leaf, pid)
}
func checkServiceEnvelope(g group, device string, p ParentEnvelope, leaf bool, pid int) error {
	if e := expect(g, "cgroup.type", "domain"); e != nil {
		return e
	}
	procs := ""
	if leaf {
		procs = strconv.Itoa(pid)
	}
	if e := expect(g, "cgroup.procs", procs); e != nil {
		return e
	}
	if leaf {
		children, e := g.Children()
		if e != nil {
			return e
		}
		if len(children) != 0 {
			return errors.New("ingress children forbidden")
		}
		if e = expect(g, "cgroup.subtree_control", ""); e != nil {
			return e
		}
		if e = expect(g, "memory.oom.group", "1"); e != nil {
			return e
		}
	}
	for _, v := range []struct{ k, w string }{{"memory.max", strconv.FormatUint(p.MemoryMax, 10)}, {"memory.swap.max", "0"}, {"pids.max", strconv.FormatUint(p.PidsMax, 10)}, {"cpu.max", strconv.FormatUint(p.CPUQuota, 10) + " 100000"}} {
		if e := expect(g, v.k, v.w); e != nil {
			return e
		}
	}
	return checkIO(g, ioLine(device, p.IOBytesPerSecond, p.IOOperationsPerSecond))
}

// ServiceCapabilities requires an exact root capability ceiling on every
// observed thread. No ambient/inheritable capability or privilege gain is allowed.
func ServiceCapabilities(mask uint64) error {
	entries, e := os.ReadDir("/proc/self/task")
	if e != nil {
		return e
	}
	if len(entries) < 1 || len(entries) > 256 {
		return errPolicy
	}
	checked := 0
	for _, entry := range entries {
		if _, e = strconv.ParseUint(entry.Name(), 10, 32); e != nil {
			return errPolicy
		}
		s, err := proc("/proc/self/task/"+entry.Name()+"/status", 65536)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if err = exactServiceCapabilities(s, mask); err != nil {
			return err
		}
		checked++
	}
	if checked == 0 {
		return errPolicy
	}
	return nil
}
func exactServiceCapabilities(status string, mask uint64) error {
	want := map[string]string{"Uid": "0 0 0 0", "Gid": "0 0 0 0", "NoNewPrivs": "1"}
	seen := map[string]bool{}
	for _, line := range strings.Split(status, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if w, yes := want[name]; yes {
			if seen[name] || !sameWords(value, w) {
				return errPolicy
			}
			seen[name] = true
			continue
		}
		switch name {
		case "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb":
			if seen[name] {
				return errPolicy
			}
			seen[name] = true
			v, e := strconv.ParseUint(value, 16, 64)
			w := mask
			if name == "CapInh" || name == "CapAmb" {
				w = 0
			}
			if e != nil || v != w {
				return errPolicy
			}
		}
	}
	if len(seen) != 8 {
		return errPolicy
	}
	return nil
}

// CheckServiceBackend reuses the ordinary launcher's nested node contract.
func (m Manifest) CheckServiceBackend(c firecracker.Config) error { return m.checkBackend(c) }
