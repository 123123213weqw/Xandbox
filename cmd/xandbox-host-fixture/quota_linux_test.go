//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

func TestQuotaUAPIAndFixedOperationAllowlist(t *testing.T) {
	if unsafe.Sizeof(quotaAttr{}) != 28 || unsafe.Offsetof(quotaAttr{}.Project) != 12 || unsafe.Sizeof(quotaRecord{}) != 72 || unsafe.Offsetof(quotaRecord{}.Valid) != 64 {
		t.Fatal("wrong Linux quota/file attribute UAPI layout")
	}
	for _, q := range []struct{ command, id uint32 }{{0x800001, 0}, {0x800004, 0}, {0x800007, quotaFirst}, {0x800008, quotaFirst + 2}} {
		bits, e := quotaCommand(q.command, q.id)
		if e != nil || bits != uintptr(q.command<<8|2) {
			t.Fatal("missing fixed quota operation", e)
		}
	}
	for _, q := range []struct{ command, id uint32 }{{0x800002, 0}, {0x800003, 0}, {0x800006, 0}, {0x800008, 0}, {0x800007, 42}, {0x800008, quotaFirst + 3}, {0x800001, quotaFirst}, {0x800004, quotaFirst}} {
		if _, e := quotaCommand(q.command, q.id); e == nil {
			t.Fatal("unsafe quota operation accepted")
		}
	}
}
func TestQuotaFixturesNeverRunInOrdinaryTestOrL0Process(t *testing.T) {
	if os.Getpid() == 1 {
		t.Fatal("test must not run as PID1")
	}
	if _, e := openQuotaFS(false); e == nil {
		t.Fatal("L1-only hardware guard bypassed")
	}
	if e := requireQuotaChild(); e == nil {
		t.Fatal("L1-only root child guard bypassed")
	}
	if e := quotaWorker("quota-drop"); e == nil {
		t.Fatal("capability-drop fixture escaped L1 guard")
	}
}
func TestQuotaMountAndCapabilityParsingIsExact(t *testing.T) {
	if !quotaOption("rw,prjquota", "prjquota") || quotaOption("rw,noprjquota", "prjquota") {
		t.Fatal("substring mount option match")
	}
	for _, status := range []string{"", "CapEff:\tbadmask\n", "CapEff:\t0000000001000000\nCapEff:\t0\n"} {
		if _, e := capabilityPresent(status, "CapEff", 24); e == nil {
			t.Fatal("malformed capability status accepted")
		}
	}
	present, e := capabilityPresent("CapEff:\t0000000001000000\n", "CapEff", 24)
	if e != nil || !present {
		t.Fatal("missing resource capability")
	}
	present, e = capabilityPresent("CapBnd:\t0000000000000000\n", "CapBnd", 24)
	if e != nil || present {
		t.Fatal("invented resource capability")
	}
}
func TestQuotaRequestAcceptsOnlyFixedPhaseLessOperation(t *testing.T) {
	if e := (nodeRequest{Version: 1, Operation: "quota-probe"}).validate(); e != nil {
		t.Fatal(e)
	}
	for _, phase := range []string{"1100001", "/dev/vda", "running"} {
		if e := (nodeRequest{Version: 1, Operation: "quota-probe", Phase: phase}).validate(); e == nil {
			t.Fatal("quota argument injection accepted")
		}
	}
}

func TestOrdinaryQuotaDriverHelpersCannotRunOnL0(t *testing.T) {
	if e := runQuotaDaemon(); e == nil {
		t.Fatal("fixed daemon cap drop escaped L1 guard")
	}
	if _, e := driverQuotaRead(driverProjectFirst); e == nil {
		t.Fatal("driver quota read escaped L1 guard")
	}
	if _, e := driverQuotaRead(0); e == nil {
		t.Fatal("arbitrary project read accepted")
	}
	for _, phase := range []string{"running", "stopped", "destroyed"} {
		if e := (nodeRequest{Version: 1, Operation: "quota-checkpoint", Phase: phase}).validate(); e != nil {
			t.Fatal(e)
		}
	}
	if e := (nodeRequest{Version: 1, Operation: "quota-checkpoint", Phase: "1300000"}).validate(); e == nil {
		t.Fatal("arbitrary quota phase accepted")
	}
}

func TestDriverQuotaColdBootChecksPolicyAndIndependentChargeNotFrozenLiveBlocks(t *testing.T) {
	entry := driverQuotaEntry{Inode: 100, Links: 1, Mode: 0100600, UID: 400000, GID: 400000, Size: 128 << 20, Blocks: (128 << 20) + 4096}
	old := driverQuotaReceipt{Record: quotaRecord{BHard: 192 << 10, IHard: 128, Space: (128 << 20) + 4096, Inodes: 1, Valid: 63}, Entries: map[string]driverQuotaEntry{"root/workspace.ext4": entry}}
	after := old.Record
	after.Space = 128 << 20
	entry.Blocks = 128 << 20
	entries := map[string]driverQuotaEntry{"root/workspace.ext4": entry}
	if e := validateDriverQuotaAccounting(old, after, 128<<20, 1, entries); e != nil {
		t.Fatal("actual lower named allocation misclassified as lost quota", e)
	}
	for _, bad := range []quotaRecord{
		{BHard: 191 << 10, IHard: 128, Space: 128 << 20, Inodes: 1, Valid: 63},
		{BHard: 192 << 10, IHard: 128, Space: (128 << 20) - 4096, Inodes: 1, Valid: 63},
		{BHard: 192 << 10, IHard: 128, Space: 128 << 20, Inodes: 2, Valid: 63},
		{BHard: 192 << 10, IHard: 128, Space: 128 << 20, Inodes: 1, BSoft: 1, Valid: 63},
	} {
		if e := validateDriverQuotaAccounting(old, bad, 128<<20, 1, entries); e == nil {
			t.Fatal("quota drift/unaccounted charge accepted")
		}
	}
	entry.Inode++
	if e := validateDriverQuotaAccounting(old, after, 128<<20, 1, map[string]driverQuotaEntry{"root/workspace.ext4": entry}); e == nil {
		t.Fatal("changed persistent inode accepted")
	}
	if e := validateDriverQuotaAccounting(old, after, 128<<20, 1, map[string]driverQuotaEntry{"other": entry}); e == nil {
		t.Fatal("lost name accepted")
	}
}

func TestColdBootNeverDependsOnNonDurableJailerPIDFileContents(t *testing.T) {
	workspace := driverQuotaEntry{Inode: 1, Links: 1, Mode: 0100600, UID: 400000, GID: 400000, Size: 128 << 20, Blocks: 128 << 20}
	pid := driverQuotaEntry{Inode: 2, Links: 1, Mode: 0100600, Size: 3, Blocks: 4096}
	old := driverQuotaReceipt{Record: quotaRecord{BHard: 192 << 10, IHard: 128, Space: (128 << 20) + 4096, Inodes: 2, Valid: 63}, Entries: map[string]driverQuotaEntry{"root/workspace.ext4": workspace, "root/firecracker.pid": pid}}
	after := old.Record
	after.Space = 128 << 20
	pid.Size = 0
	pid.Blocks = 0
	if e := validateDriverQuotaAccounting(old, after, 128<<20, 2, map[string]driverQuotaEntry{"root/workspace.ext4": workspace, "root/firecracker.pid": pid}); e != nil {
		t.Fatal("empty diagnostic PID file prevents safe ownership-based recovery", e)
	}
	pid.Inode++
	if e := validateDriverQuotaAccounting(old, after, 128<<20, 2, map[string]driverQuotaEntry{"root/workspace.ext4": workspace, "root/firecracker.pid": pid}); e == nil {
		t.Fatal("replaced PID inode accepted")
	}
	pid.Inode--
	pid.Size = 21
	if e := validateDriverQuotaAccounting(old, after, 128<<20, 2, map[string]driverQuotaEntry{"root/workspace.ext4": workspace, "root/firecracker.pid": pid}); e == nil {
		t.Fatal("unexpected PID file accepted")
	}
	workspace.Size--
	pid.Size = 0
	if e := validateDriverQuotaAccounting(old, after, 128<<20, 2, map[string]driverQuotaEntry{"root/workspace.ext4": workspace, "root/firecracker.pid": pid}); e == nil {
		t.Fatal("lost mutable backing size accepted")
	}
}

func TestSnapshotProfileIsExclusiveAndNeverRunsBuilderOnL0(t *testing.T) {
	if e := runNodeAllProfiles(false, false, true, true); e == nil {
		t.Fatal("mixed ordinary/snapshot quota profile accepted")
	}
	if _, e := (&node{quotaDriver: true, quotaSnapshot: true}).quotaSnapshotSetup(context.Background()); e == nil {
		t.Fatal("snapshot builder escaped L1 PID1 guard")
	}
	if e := runQuotaDaemonCapacity(2); e == nil {
		t.Fatal("snapshot daemon escaped L1 guard")
	}
	if e := (nodeRequest{Version: 1, Operation: "quota-snapshot-setup"}).validate(); e != nil {
		t.Fatal(e)
	}
	if e := (nodeRequest{Version: 1, Operation: "quota-snapshot-setup", Phase: "arbitrary"}).validate(); e == nil {
		t.Fatal("arbitrary snapshot setup parameter accepted")
	}
	if e := verifySharedQuotaFiles("/srv/not-an-owned-fixture"); e == nil {
		t.Fatal("shared template probe escaped L1 guard")
	}
}

func TestSharedSnapshotHashChecksWholeExactRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "memory")
	content := []byte("a full snapshot payload")
	if e := os.WriteFile(path, content, 0400); e != nil {
		t.Fatal(e)
	}
	got, e := sharedQuotaHash(path, int64(len(content)))
	if e != nil || got != fmt.Sprintf("%x", sha256.Sum256(content)) {
		t.Fatal("incorrect full hash", e)
	}
	for _, size := range []int64{0, -1, int64(len(content) - 1), int64(len(content) + 1), (512 << 20) + 1} {
		if _, e = sharedQuotaHash(path, size); e == nil {
			t.Fatal("invalid/excess/truncated length accepted")
		}
	}
	link := filepath.Join(dir, "symlink")
	if e = os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e = sharedQuotaHash(link, int64(len(content))); e == nil {
		t.Fatal("symlink accepted")
	}
	if _, e = sharedQuotaHash(dir, int64(len(content))); e == nil {
		t.Fatal("directory accepted")
	}
}
