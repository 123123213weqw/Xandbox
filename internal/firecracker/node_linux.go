//go:build linux

package firecracker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/123123213weqw/Xandbox/internal/telemetry"

	"golang.org/x/sys/unix"
)

type nodeAnchor struct {
	file *os.File
	path string
}
type nodeEnvelope struct {
	cfg                                      Config
	policy                                   NodePolicy
	reservation                              NodeReservation
	root, control, instances, runtime, state nodeAnchor
	preparing                                *prepareGate
}

func openNodeAnchor(path string, cgroup bool) (nodeAnchor, error) {
	var a nodeAnchor
	if e := securePath(path); e != nil {
		return a, e
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return a, e
	}
	a = nodeAnchor{file: os.NewFile(uintptr(fd), "node-envelope-anchor"), path: path}
	if e = a.verify(cgroup); e != nil {
		a.file.Close()
		return nodeAnchor{}, e
	}
	return a, nil
}
func (a nodeAnchor) verify(cgroup bool) error {
	if e := securePath(a.path); e != nil {
		return e
	}
	f, e := a.file.Stat()
	if e != nil {
		return e
	}
	now, e := os.Lstat(a.path)
	if e != nil || !f.IsDir() || !os.SameFile(f, now) {
		return errors.New("node envelope anchor replaced")
	}
	var fs unix.Statfs_t
	if e = unix.Fstatfs(int(a.file.Fd()), &fs); e != nil {
		return e
	}
	if cgroup && fs.Type != unix.CGROUP2_SUPER_MAGIC || !cgroup && fs.Type != unix.EXT4_SUPER_MAGIC {
		return errors.New("node envelope filesystem type changed")
	}
	return nil
}
func (a nodeAnchor) read(name string) (string, error) {
	if strings.ContainsAny(name, "/\\") || name == "" || name == "." || name == ".." {
		return "", errors.New("invalid node interface name")
	}
	fd, e := unix.Openat(int(a.file.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return "", e
	}
	f := os.NewFile(uintptr(fd), "node-envelope-interface")
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil {
		return "", e
	}
	if len(b) > 4096 {
		return "", errors.New("node interface exceeds bound")
	}
	return strings.TrimSpace(string(b)), nil
}
func (n *nodeEnvelope) close() {
	for _, a := range []nodeAnchor{n.root, n.control, n.instances, n.runtime, n.state} {
		if a.file != nil {
			a.file.Close()
		}
	}
}
func openNodeEnvelope(c Config, state string) (result *nodeEnvelope, err error) {
	if c.Node == nil {
		return nil, nil
	}
	r, e := c.Node.validate(c)
	if e != nil {
		return nil, e
	}
	n := &nodeEnvelope{cfg: c, policy: *c.Node, reservation: r, preparing: newPrepareGate(c.Node.PrepareWorkers)}
	defer func() {
		if err != nil {
			n.close()
		}
	}()
	for _, item := range []struct {
		path string
		cg   bool
		out  *nodeAnchor
	}{{c.Node.CgroupRoot, true, &n.root}, {filepath.Join(c.Node.CgroupRoot, "control"), true, &n.control}, {c.CgroupRoot, true, &n.instances}, {c.RuntimeRoot, false, &n.runtime}, {state, false, &n.state}} {
		*item.out, e = openNodeAnchor(item.path, item.cg)
		if e != nil {
			return nil, e
		}
	}
	if e = n.check(false); e != nil {
		return nil, e
	}
	return n, nil
}
func requireInterface(a nodeAnchor, name, want string) error {
	got, e := a.read(name)
	if e != nil {
		return e
	}
	if got != want {
		return fmt.Errorf("node envelope %s readback mismatch", name)
	}
	return nil
}
func (n *nodeEnvelope) check(space bool) error {
	if n == nil {
		return nil
	}
	for _, a := range []nodeAnchor{n.root, n.control, n.instances} {
		if e := a.verify(true); e != nil {
			return e
		}
	}
	for _, a := range []nodeAnchor{n.runtime, n.state} {
		if e := a.verify(false); e != nil {
			return e
		}
	}
	a, e := n.runtime.file.Stat()
	if e != nil {
		return e
	}
	b, e := n.state.file.Stat()
	if e != nil {
		return e
	}
	if a.Sys().(*syscall.Stat_t).Dev != b.Sys().(*syscall.Stat_t).Dev {
		return errors.New("version3 state and runtime require same quota filesystem")
	}
	if e = checkRuntimeIO(n.cfg.RuntimeRoot, *n.cfg.IO); e != nil {
		return e
	}
	for _, a := range []nodeAnchor{n.root, n.instances} {
		if e = requireInterface(a, "cgroup.procs", ""); e != nil {
			return e
		}
		controllers, e := a.read("cgroup.subtree_control")
		if e != nil || !hasWords(controllers, "memory", "pids", "cpu", "io") {
			return errors.New("node root/instances require all delegated controllers")
		}
	}
	for _, anchor := range []nodeAnchor{n.root, n.control, n.instances} {
		if e = requireInterface(anchor, "cgroup.type", "domain"); e != nil {
			return e
		}
	}
	for _, bound := range []struct {
		name string
		want uint64
	}{{"memory.max", uint64(n.policy.MaxInstances) * instanceMemoryMax}, {"pids.max", uint64(n.policy.MaxInstances) * instancePidsMax}} {
		raw, err := n.instances.read(bound.name)
		if err != nil {
			return err
		}
		if err = nodeAncestorLimit(raw, bound.want); err != nil {
			return err
		}
	}
	vmCPU, err := n.instances.read("cpu.max")
	if err != nil {
		return err
	}
	if err = nodeAncestorCPU(vmCPU, uint64(n.policy.MaxInstances)*instanceCPUQuota); err != nil {
		return err
	}
	for _, item := range []struct {
		a          nodeAnchor
		name, want string
	}{
		{n.root, "memory.max", strconv.FormatUint(n.policy.MemoryMax, 10)}, {n.root, "memory.swap.max", "0"},
		{n.root, "pids.max", strconv.FormatUint(n.policy.PidsMax, 10)}, {n.root, "cpu.max", fmt.Sprintf("%d %d", n.policy.CPUQuota, nodeCPUPeriod)},
		{n.control, "memory.max", strconv.FormatUint(n.policy.ControllerMemoryMax, 10)}, {n.control, "memory.swap.max", "0"},
		{n.control, "memory.oom.group", "1"}, {n.control, "pids.max", strconv.FormatUint(n.policy.ControllerPidsMax, 10)},
	} {
		if e = requireInterface(item.a, item.name, item.want); e != nil {
			return e
		}
	}
	np := *n.cfg.IO
	np.BytesPerSecond = n.policy.IOBytesPerSecond
	np.OperationsPerSecond = n.policy.IOOperationsPerSecond
	raw, e := n.root.read("io.max")
	if e != nil {
		return e
	}
	if e = np.verifyKernelLimit(raw); e != nil {
		return e
	}
	fd, e := unix.Openat(int(n.root.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	directory := os.NewFile(uintptr(fd), "node-inventory")
	entries, e := directory.ReadDir(-1)
	directory.Close()
	if e != nil {
		return e
	}
	for _, d := range entries {
		if d.IsDir() && d.Name() != "control" && d.Name() != "instances" {
			return errors.New("unknown node cgroup subtree")
		}
	}
	proc, e := readNodeProc("/proc/self/cgroup", 4096)
	if e != nil {
		return e
	}
	if e = nodeControllerPlacement(proc, n.policy.CgroupRoot); e != nil {
		return e
	}
	status, e := readNodeProc("/proc/self/status", 64<<10)
	if e != nil {
		return e
	}
	cores, e := allowedNodeCPUs(status)
	if e != nil || uint64(cores)*nodeCPUPeriod < n.policy.CPUQuota {
		return errors.New("node CPU envelope exceeds effective controller affinity")
	}
	mem, e := readNodeProc("/proc/meminfo", 64<<10)
	if e != nil {
		return e
	}
	total, e := nodeMemTotal(mem)
	if e != nil {
		return e
	}
	need, e := checkedSum(n.policy.MemoryMax, n.policy.HostMemoryReserve)
	if e != nil || need > total {
		return errors.New("node memory plus host reserve exceeds physical memory")
	}
	if e = checkNodeAncestors(n.policy); e != nil {
		return e
	}
	var fs unix.Statfs_t
	if e = unix.Fstatfs(int(n.runtime.file.Fd()), &fs); e != nil {
		return e
	}
	return checkNodeFS(n.policy, n.reservation, uint64(fs.Bsize), fs.Blocks, fs.Bavail, fs.Files, fs.Ffree, space)
}
func readNodeProc(path string, max int64) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil {
		return "", e
	}
	if int64(len(b)) > max {
		return "", errors.New("node proc inventory exceeds bound")
	}
	return string(b), nil
}
func checkNodeAncestors(p NodePolicy) error {
	for path := filepath.Dir(p.CgroupRoot); ; path = filepath.Dir(path) {
		if !strings.HasPrefix(path, "/sys/fs/cgroup") {
			return errors.New("node hierarchy escaped cgroup mount")
		}
		a, e := openNodeAnchor(path, true)
		if e != nil {
			return e
		}
		for _, item := range []struct {
			name string
			want uint64
		}{{"memory.max", p.MemoryMax}, {"pids.max", p.PidsMax}} {
			raw, err := a.read(item.name)
			if os.IsNotExist(err) && path == "/sys/fs/cgroup" {
				continue
			}
			if err != nil {
				a.file.Close()
				return err
			}
			if err = nodeAncestorLimit(raw, item.want); err != nil {
				a.file.Close()
				return err
			}
		}
		raw, err := a.read("cpu.max")
		a.file.Close()
		if !(os.IsNotExist(err) && path == "/sys/fs/cgroup") {
			if err != nil {
				return err
			}
			if err = nodeAncestorCPU(raw, p.CPUQuota); err != nil {
				return err
			}
		}
		if path == "/sys/fs/cgroup" {
			return nil
		}
	}
}
func (n *nodeEnvelope) acquirePrepare(ctx context.Context) error {
	waitActivity := telemetry.StartCreationActivity(ctx, telemetry.CreationPermitWait)
	defer waitActivity.End()
	acquireErr := n.preparing.acquire(ctx)
	waitActivity.End()
	if acquireErr != nil {
		return acquireErr
	}
	checkActivity := telemetry.StartCreationActivity(ctx, telemetry.CreationNodeCheck)
	defer checkActivity.End()
	checkErr := n.check(true)
	checkActivity.End()
	if checkErr != nil {
		n.preparing.release()
		return checkErr
	}
	return nil
}
