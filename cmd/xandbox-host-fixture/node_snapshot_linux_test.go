//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"strings"
	"testing"
)

func snapshotNodeTestConfig() firecracker.Config {
	p := budgetPolicy()
	return firecracker.Config{Version: 3, RuntimeRoot: "/srv/r", CgroupRoot: nodeBudgetInstances, UIDStart: 400000, UIDCount: 4, ReservedUIDRange: true, Node: &p, Quota: &firecracker.QuotaPolicy{Version: 1, ProjectStart: driverProjectFirst, MaxBytes: 192 << 20, MaxInodes: 128}, IO: &firecracker.IOPolicy{Version: 1, BytesPerSecond: 16 << 20, OperationsPerSecond: 1024}, Snapshot: &firecracker.SnapshotPolicy{Version: 1, AgentSHA256: strings.Repeat("a", 64), MemoryMiB: 512, VCPUs: 2, MaxEntries: 4, MaxBytes: 2 << 30}}
}
func TestNodeSnapshotFixedPolicyAndIndependentResourceGuards(t *testing.T) {
	c := snapshotNodeTestConfig()
	if e := validateNodeSnapshotConfig(c); e != nil {
		t.Fatal(e)
	}
	b, i, e := nodeSnapshotFreeGuards(c)
	if e != nil || b != 3362619392 || i != 5776 {
		t.Fatal("fixed planner drift", b, i, e)
	}
	for name, change := range map[string]func(*firecracker.Config){"legacy": func(c *firecracker.Config) { c.Version = 2 }, "cold": func(c *firecracker.Config) { c.Snapshot = nil }, "budget": func(c *firecracker.Config) { c.Node.MaxInstances = 3 }, "wrongroot": func(c *firecracker.Config) { c.CgroupRoot = nodeGroup }, "counts": func(c *firecracker.Config) { c.UIDCount = 8 }, "capacity": func(c *firecracker.Config) { c.Node.MaxSessions = 1000 }, "catalog": func(c *firecracker.Config) { c.Snapshot.MaxEntries = 2 }, "sharedcache": func(c *firecracker.Config) { c.Snapshot.MaxBytes = 1 << 30 }, "agent": func(c *firecracker.Config) { c.Snapshot.AgentSHA256 = strings.Repeat("0", 64) }, "IO": func(c *firecracker.Config) { c.IO.OperationsPerSecond = 2048 }, "quota": func(c *firecracker.Config) { c.Quota.MaxInodes = 256 }} {
		t.Run(name, func(t *testing.T) {
			c := snapshotNodeTestConfig()
			change(&c)
			if validateNodeSnapshotConfig(c) == nil {
				t.Fatal("fixed scope silently changed")
			}
		})
	}
	p := testPolicy()
	p.Profile = "node-snapshot-v1"
	m, d, cg, e := p.resources()
	if e != nil || p.validate() != nil || m != 8192 || d != 12<<30 || cg != 10<<30 || p.cpuCount() != 8 || p.pidCount() != 256 {
		t.Fatal("new explicit launch policy")
	}
	p.Profile = "node-snapshot-v2"
	if p.validate() == nil {
		t.Fatal("unknown profile")
	}
}
func TestNodeSnapshotAllFixedControlAndFillerRoutesRejectL0(t *testing.T) {
	ctx := context.Background()
	n := &node{nodeBudget: true, nodeSnapshot: true, quotaDriver: true, quotaSnapshot: true}
	if n.initializeNodeSnapshotBudget() == nil || n.initializeNodeBudget() == nil || n.initializeBudgetCgroups(firecracker.Config{}) == nil || runNodeSnapshotDaemon() == nil {
		t.Fatal("setup/child escaped L1")
	}
	if _, e := n.nodeSnapshotCheckpoint(ctx); e == nil {
		t.Fatal("checkpoint escaped L1")
	}
	if _, e := n.nodeSnapshotRecover(ctx); e == nil {
		t.Fatal("recovery escaped L1")
	}
	if _, _, _, e := n.nodeSnapshotGuest(ctx, nil); e == nil {
		t.Fatal("guest helper escaped L1")
	}
	if _, e := nodeSnapshotAdmin(ctx, "status"); e == nil {
		t.Fatal("admin escaped L1")
	}
	if _, e := nodeSnapshotFS(); e == nil {
		t.Fatal("FS escaped L1")
	}
	if _, e := nodeSnapshotPressureRefusals(ctx, nil); e == nil {
		t.Fatal("refusal helper escaped L1")
	}
	if _, e := nodeSnapshotBytePressure(snapshotNodeTestConfig()); e == nil {
		t.Fatal("byte fill escaped L1")
	}
	if nodeSnapshotRemoveByteFiller(nodeByteFiller{}) == nil {
		t.Fatal("unlink escaped L1")
	}
	if _, e := nodeSnapshotInodePressure(ctx, nil, snapshotNodeTestConfig(), sandbox.Ref{}, &nodeInodeObservation{}); e == nil {
		t.Fatal("inode fill escaped L1")
	}
	if nodeSnapshotDelete(ctx, nil, sandbox.Ref{}) == nil || nodeSnapshotGC(ctx, "", 0) == nil {
		t.Fatal("cleanup escaped L1")
	}
	for _, op := range []string{"node-snapshot-checkpoint", "node-snapshot-recover"} {
		if (nodeRequest{Version: 1, Operation: op}).validate() != nil || (nodeRequest{Version: 1, Operation: op, Phase: "anything"}).validate() == nil {
			t.Fatal("fixed phase-less operation only")
		}
	}
}
