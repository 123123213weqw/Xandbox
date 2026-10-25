package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func nodeTestConfig() Config {
	c := policy()
	c.Version = 3
	c.CgroupRoot = "/sys/fs/cgroup/xb-node/instances"
	c.UIDCount = 4
	c.Quota = &QuotaPolicy{Version: 1, FilesystemUUID: strings.Repeat("a", 32), ProjectStart: 65536, MaxBytes: 192 << 20, MaxInodes: 128}
	c.IO = &IOPolicy{Version: 1, FilesystemDevice: "252:0", Device: "252:0", BytesPerSecond: 8 << 20, OperationsPerSecond: 1024}
	c.Node = &NodePolicy{Version: 1, CgroupRoot: "/sys/fs/cgroup/xb-node", MaxInstances: 2, MaxRecords: 128, MaxSessions: 16, PrepareWorkers: 1, MemoryMax: 5 << 30, ControllerMemoryMax: 512 << 20, HostMemoryReserve: 512 << 20, PidsMax: 256, ControllerPidsMax: 128, CPUQuota: 400000, IOBytesPerSecond: 64 << 20, IOOperationsPerSecond: 4096, DiskBytes: 7 << 30, DiskInodes: 50000, ExternalDiskBytes: 512 << 20, ExternalInodes: 1024, MinFreeBytes: 256 << 20, MinFreeInodes: 1024}
	return c
}
func TestNodeEnvelopeAllResourceDimensionsAndOverflow(t *testing.T) {
	c := nodeTestConfig()
	if e := c.validate(); e != nil {
		t.Fatal(e)
	}
	r, e := c.Node.validate(c)
	if e != nil {
		t.Fatal(e)
	}
	if r.Memory != 2*instanceMemoryMax+c.Node.ControllerMemoryMax+2<<20 || r.Pids != 256 || r.CPUQuota != 400000 || r.ManagedDisk <= 2*c.Quota.MaxBytes || r.RequiredDisk != 2*r.ManagedDisk+c.Node.ExternalDiskBytes+c.Node.MinFreeBytes || r.FreeDiskGuard != r.ManagedDisk+c.Node.MinFreeBytes {
		t.Fatalf("unaccounted aggregate reservation %+v", r)
	}
	for name, change := range map[string]func(*Config){
		"node memory": func(c *Config) { c.Node.MemoryMax = r.Memory - 1 }, "control memory": func(c *Config) { c.Node.ControllerMemoryMax = r.ControllerMemory - 1 }, "pids": func(c *Config) { c.Node.PidsMax = r.Pids - 1 }, "cpu": func(c *Config) { c.Node.CPUQuota = r.CPUQuota - 1 }, "io bytes": func(c *Config) { c.Node.IOBytesPerSecond = 2*c.IO.BytesPerSecond - 1 }, "io ops": func(c *Config) { c.Node.IOOperationsPerSecond = 2*c.IO.OperationsPerSecond - 1 }, "disk": func(c *Config) { c.Node.DiskBytes = r.RequiredDisk - 1 }, "inodes": func(c *Config) { c.Node.DiskInodes = r.RequiredInodes - 1 }, "prepare": func(c *Config) { c.Node.PrepareWorkers = 3 }, "slot count": func(c *Config) { c.Node.MaxInstances = 5 }, "quota required": func(c *Config) { c.Quota = nil }, "io required": func(c *Config) { c.IO = nil }, "parent": func(c *Config) { c.Node.CgroupRoot += "other" }, "vm subtree": func(c *Config) { c.CgroupRoot = filepath.Join(c.Node.CgroupRoot, "control") }, "host memory reserve": func(c *Config) { c.Node.HostMemoryReserve = 0 }, "free reserve": func(c *Config) { c.Node.MinFreeBytes = 0 }, "metadata maximum": func(c *Config) { c.Node.MaxRecords = sandbox.MaxLedgerRecords + 1 }, "session maximum": func(c *Config) { c.Node.MaxSessions = 10001 }, "overflow": func(c *Config) { c.Node.ExternalDiskBytes = math.MaxUint64 },
	} {
		t.Run(name, func(t *testing.T) {
			v := nodeTestConfig()
			change(&v)
			if v.validate() == nil {
				t.Fatal("incomplete/overcommitted node envelope accepted")
			}
		})
	}
	if _, e = checkedProduct(math.MaxUint64, 2); e == nil {
		t.Fatal("product overflow")
	}
	if _, e = checkedSum(math.MaxUint64, 1); e == nil {
		t.Fatal("sum overflow")
	}
	c.Snapshot = &SnapshotPolicy{Version: 1, AgentSHA256: strings.Repeat("b", 64), MemoryMiB: 512, VCPUs: 2, MaxEntries: 4, MaxBytes: 2 << 30}
	if e = c.validate(); e != nil {
		t.Fatal("complete snapshot envelope", e)
	}
	s, e := c.Node.validate(c)
	if e != nil || s.Memory != r.Memory+2<<30 || s.ManagedDisk < r.ManagedDisk+2<<30 {
		t.Fatal("shared catalog memory/disk not reserved", e)
	}
	c.Node.MemoryMax = r.Memory
	if c.validate() == nil {
		t.Fatal("ignored shared cache when adding snapshot")
	}
}
func TestNodeSchemaIsExplicitAndOldDigestNotSilentlyUpgraded(t *testing.T) {
	old := policy()
	b, e := json.Marshal(old)
	if e != nil || strings.Contains(string(b), "node") {
		t.Fatal("legacy binding changed")
	}
	for _, version := range []int{1, 2} {
		c := nodeTestConfig()
		c.Version = version
		if c.validate() == nil {
			t.Fatal("legacy version accepted node policy")
		}
	}
	unit := nodeTestConfig()
	unit.Node.CgroupRoot = "/sys/fs/cgroup/system.slice/xandbox.service/node"
	unit.CgroupRoot = unit.Node.CgroupRoot + "/instances"
	if unit.validate() != nil {
		t.Fatal("version3 rejected canonical delegated service hierarchy")
	}
	c := nodeTestConfig()
	c.Node = nil
	if c.validate() == nil {
		t.Fatal("version3 without complete envelope")
	}
	c = nodeTestConfig()
	digest := configDigest(c)
	c.Node.MinFreeBytes += 4096
	if configDigest(c) == digest {
		t.Fatal("node reserve drift absent from immutable fingerprint")
	}
}
func TestNodeServiceAdmissionAndRecoveredUnreclaimedInventory(t *testing.T) {
	p := nodeTestConfig().Node
	if e := p.match(sandbox.AdmissionLimits{MaxInstances: 2, MaxRecords: 128, MaxSessions: 16, AllocatedInstances: 2, RetainedRecords: 128, RetainedSessions: 16}, true); e != nil {
		t.Fatal(e)
	}
	for _, l := range []sandbox.AdmissionLimits{{}, {MaxInstances: 32, MaxRecords: 128, MaxSessions: 16}, {MaxInstances: 2, MaxRecords: 10000, MaxSessions: 16}, {MaxInstances: 2, MaxRecords: 128, MaxSessions: 1000}, {MaxInstances: 2, MaxRecords: 128, MaxSessions: 16, AllocatedInstances: 3}, {MaxInstances: 2, MaxRecords: 128, MaxSessions: 16, RetainedRecords: 129}, {MaxInstances: 2, MaxRecords: 128, MaxSessions: 16, RetainedSessions: 17}} {
		if p.match(l, true) == nil {
			t.Fatal("unsafe service/import inventory", l)
		}
	}
	if p.match(sandbox.AdmissionLimits{MaxInstances: 2, MaxRecords: 128}, false) != nil || p.match(sandbox.AdmissionLimits{MaxSessions: 16}, false) != nil || p.match(sandbox.AdmissionLimits{AllocatedInstances: -1}, false) == nil {
		t.Fatal("layer-specific validation invalid")
	}
}
func TestNodeRegistryCapacityRetainedUntilDurableOwnerRelease(t *testing.T) {
	cfg := nodeTestConfig()
	dir := t.TempDir()
	r, e := newRegistry(dir, cfg, nil)
	if e != nil {
		t.Fatal(e)
	}
	one, e := r.reserve(reference("1"))
	if e != nil {
		t.Fatal(e)
	}
	two, e := r.reserve(reference("2"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.reserve(reference("3")); !errors.Is(e, sandbox.ErrCapacity) {
		t.Fatal("UID slots bypassed node envelope", e)
	}
	r.beforeRelease = func(ownership) error { return nil }
	r.syncDirectory = func(string) error { return errors.New("unconfirmed directory fsync") }
	k, _ := key(one.Ref)
	if r.release(k) == nil {
		t.Fatal("expected unconfirmed release")
	}
	if _, e = r.reserve(reference("3")); !errors.Is(e, sandbox.ErrCapacity) {
		t.Fatal("returned node reservation before owner commit", e)
	}
	r.syncDirectory = syncDir
	if e = r.release(k); e != nil {
		t.Fatal(e)
	}
	if _, e = r.reserve(reference("3")); e != nil {
		t.Fatal(e)
	}
	changed := cfg
	p := *cfg.Node
	changed.Node = &p
	changed.Node.MinFreeBytes += 4096
	if _, e = newRegistry(dir, changed, []sandbox.Record{ledger(two.Ref)}); e == nil {
		t.Fatal("changed node policy overwrote binding")
	}
}
func TestNodePureKernelInventoryAndPressureBoundaries(t *testing.T) {
	c := nodeTestConfig()
	p := *c.Node
	r, e := p.validate(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = checkNodeFS(p, r, 4096, 8<<30/4096, r.FreeDiskGuard/4096+1, 100000, r.FreeInodeGuard, true); e != nil {
		t.Fatal(e)
	}
	if checkNodeFS(p, r, 4096, 8<<30/4096, (r.FreeDiskGuard-1)/4096, 100000, 100000, true) == nil || checkNodeFS(p, r, 4096, 8<<30/4096, 8<<30/4096, 100000, r.FreeInodeGuard-1, true) == nil {
		t.Fatal("disk/inode pressure not refused")
	}
	if e = checkNodeFS(p, r, 4096, 8<<30/4096, 0, 100000, 0, false); e != nil {
		t.Fatal("free-space admission must not block recovery", e)
	}
	if checkNodeFS(p, r, 4096, 1, 0, 100000, 0, false) == nil || checkNodeFS(p, r, 512, math.MaxUint64, 0, 100000, 0, true) == nil {
		t.Fatal("invalid filesystem capacity/type")
	}
	for _, raw := range []string{"0::/xb-node/control\n", "0::/xb-node/control/admin\n"} {
		if e = nodeControllerPlacement(raw, p.CgroupRoot); e != nil {
			t.Fatal(e)
		}
	}
	for _, raw := range []string{"0::/\n", "0::/xb-node/instances/x\n", "0::/xb-node/control-other\n", "0::/xb-node/control/../instances\n", "0::/xb-node/control\n0::/xb-node/control\n"} {
		if nodeControllerPlacement(raw, p.CgroupRoot) == nil {
			t.Fatal("bad controller placement", raw)
		}
	}
	if cores, e := nodeCPUCount("0-3,8,10-11"); e != nil || cores != 7 {
		t.Fatal("CPU inventory", cores, e)
	}
	for _, raw := range []string{"", "0-4,4", "2-1", "0-999999", "-1", "a", "0,,1"} {
		if _, e = nodeCPUCount(raw); e == nil {
			t.Fatal("bad affinity", raw)
		}
	}
	if n, e := nodeMemTotal("MemTotal: 6291456 kB\n"); e != nil || n != 6<<30 {
		t.Fatal(n, e)
	}
	for _, raw := range []string{"", "MemTotal: 0 kB\nMemTotal: 1 kB", "MemTotal: 1 bytes", "MemTotal: 18446744073709551615 kB"} {
		if _, e = nodeMemTotal(raw); e == nil {
			t.Fatal("bad memory inventory")
		}
	}
	if nodeAncestorLimit("max", p.MemoryMax) != nil || nodeAncestorLimit("1", p.MemoryMax) == nil || nodeAncestorCPU("max 100000", p.CPUQuota) != nil || nodeAncestorCPU("40000 10000", p.CPUQuota) != nil || nodeAncestorCPU("39999 10000", p.CPUQuota) == nil || nodeAncestorCPU("99999999999999999999 100000", p.CPUQuota) == nil {
		t.Fatal("ancestor ceilings ignored")
	}
}

func TestNodePrepareGateIsBoundedAndCanceledWaitersDoNotLeak(t *testing.T) {
	g := newPrepareGate(2)
	ctx := context.Background()
	if g.acquire(ctx) != nil || g.acquire(ctx) != nil {
		t.Fatal("failed initial permits")
	}
	wait, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()
	if !errors.Is(g.acquire(wait), context.DeadlineExceeded) || len(g.tokens) != 2 {
		t.Fatal("queued waiter bypassed bound or leaked")
	}
	g.release()
	g.release()
	for i := 0; i < 100; i++ {
		c, stop := context.WithCancel(ctx)
		stop()
		if !errors.Is(g.acquire(c), context.Canceled) || len(g.tokens) != 0 {
			t.Fatal("canceled permit leaked")
		}
	}
	var running, peak atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := g.acquire(ctx); e != nil {
				t.Error(e)
				return
			}
			n := running.Add(1)
			for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
			}
			time.Sleep(time.Millisecond)
			running.Add(-1)
			g.release()
		}()
	}
	wg.Wait()
	if peak.Load() != 2 || len(g.tokens) != 0 {
		t.Fatal("preparation parallelism not enforced", peak.Load(), len(g.tokens))
	}
}

// This fixed fixture policy also appears in the TEST-only L1 pressure helper;
// prove its exact guards against the real production planner, not a new credit.
func TestNodeSnapshotFixtureGuardMatchesProductionPlanner(t *testing.T) {
	c := nodeTestConfig()
	c.UIDCount = 4
	c.IO.BytesPerSecond = 16 << 20
	c.IO.OperationsPerSecond = 1024
	c.Snapshot = &SnapshotPolicy{Version: 1, AgentSHA256: strings.Repeat("b", 64), MemoryMiB: 512, VCPUs: 2, MaxEntries: 4, MaxBytes: 2 << 30}
	c.Node = &NodePolicy{Version: 1, CgroupRoot: "/sys/fs/cgroup/xb-node", MaxInstances: 4, MaxRecords: 1024, MaxSessions: 32, PrepareWorkers: 1, MemoryMax: 7 << 30, ControllerMemoryMax: 1 << 30, HostMemoryReserve: 512 << 20, PidsMax: 384, ControllerPidsMax: 128, CPUQuota: 800000, IOBytesPerSecond: 256 << 20, IOOperationsPerSecond: 8192, DiskBytes: 10 << 30, DiskInodes: 100000, ExternalDiskBytes: 2 << 30, ExternalInodes: 2048, MinFreeBytes: 256 << 20, MinFreeInodes: 2048}
	if e := c.validate(); e != nil {
		t.Fatal(e)
	}
	r, e := c.Node.validate(c)
	if e != nil || r.FreeDiskGuard != 3362619392 || r.FreeInodeGuard != 5776 {
		t.Fatalf("fixture no longer matches real conservative planner %+v %v", r, e)
	}
}
