//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"

	"fmt"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
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

func TestNegativeQuotaHelpersAreFixedAndNeverRunOnL0(t *testing.T) {
	for _, name := range []string{"", "../block", "block/../../", "/srv", "shell"} {
		if _, e := negativeBase(name); e == nil {
			t.Fatal("arbitrary case path accepted")
		}
		if _, e := negativeDaemonArgs(name); e == nil {
			t.Fatal("arbitrary daemon config accepted")
		}
	}
	for _, name := range negativeQuotaCases {
		args, e := negativeDaemonArgs(name)
		want := []string{"sandboxd", "-backend", "firecracker", "-state-dir", "/srv/nq/" + name + "/s", "-auth-file", "/srv/config/auth.json", "-firecracker-config", "/srv/nq/" + name + "/backend.json", "-max-instances", "1", "-metrics"}
		if e != nil || !slices.Equal(args, want) {
			t.Fatal("bad fixed daemon arguments", e, args)
		}
		if e = runNegativeQuotaDaemon(name); e == nil {
			t.Fatal("negative helper escaped L1 guard")
		}
		if _, e = startNegativeDaemon(context.Background(), name, "first"); e == nil {
			t.Fatal("negative daemon launched on L0")
		}
	}
	if _, e := (&node{quotaDriver: true}).quotaNegativeSetup(context.Background()); e == nil {
		t.Fatal("negative setup escaped L1 PID1 guard")
	}
	if e := (nodeRequest{Version: 1, Operation: "quota-negative-setup"}).validate(); e != nil {
		t.Fatal(e)
	}
	if e := (nodeRequest{Version: 1, Operation: "quota-negative-setup", Phase: "block"}).validate(); e == nil {
		t.Fatal("arbitrary negative protocol phase accepted")
	}
}

func TestNegativeLedgerInspectionIsReadOnlyBoundedAndExact(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "s/ledger")
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	refs := []sandbox.Ref{{ID: strings.Repeat("1", 32), Generation: strings.Repeat("2", 32)}, {ID: strings.Repeat("3", 32), Generation: strings.Repeat("4", 32)}}
	write := func(ref sandbox.Ref) {
		t.Helper()
		b, e := json.Marshal(map[string]any{"version": 1, "record": sandbox.Record{Ref: ref}})
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, ref.ID+".json"), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(refs[0])
	if r, e := negativeLedgerRef(base, sandbox.Ref{}); e != nil || r != refs[0] {
		t.Fatal("single ref not read exactly", r, e)
	}
	write(refs[1])
	if r, e := negativeLedgerRef(base, refs[0]); e != nil || r != refs[1] {
		t.Fatal("second capacity attempt not distinct", r, e)
	}
	if _, e := negativeLedgerRef(base, sandbox.Ref{}); e == nil {
		t.Fatal("unexpected multiple identities accepted")
	}
	if e := os.WriteFile(filepath.Join(dir, refs[1].ID+".json"), []byte(strings.Repeat("x", (64<<10)+1)), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := negativeLedgerRef(base, refs[0]); e == nil {
		t.Fatal("oversized private envelope accepted")
	}
}

func TestUnenforcedQuotaProbeCannotRunOnL0AndHasNoParameters(t *testing.T) {
	if _, e := (&node{quotaDriver: true}).quotaUnenforced(context.Background()); e == nil {
		t.Fatal("unenforced fixture escaped L1 PID1 guard")
	}
	if e := (nodeRequest{Version: 1, Operation: "quota-unenforced"}).validate(); e != nil {
		t.Fatal(e)
	}
	for _, phase := range []string{"off", "/dev/vda", "running"} {
		if e := (nodeRequest{Version: 1, Operation: "quota-unenforced", Phase: phase}).validate(); e == nil {
			t.Fatal("arbitrary quota mutation accepted")
		}
	}
}

func TestQuotaIOProfileAndMappedReadersCannotEscapeL1(t *testing.T) {
	if e := runNodeQuotaIOProfiles(true, false, false, false, true); e == nil {
		t.Fatal("mixed ordinary/quota IO profile accepted")
	}
	if e := runNodeQuotaIOProfiles(false, false, true, false, true); e == nil {
		t.Fatal("mixed quota/IO profile accepted")
	}
	if e := runNodeQuotaIOProfiles(false, false, false, false, true); e == nil {
		t.Fatal("quota IO node escaped L1 PID1 guard")
	}
	m := &stateMapper{}
	if _, e := openQuotaFSWithMapper(false, m); e == nil {
		t.Fatal("mapped quota reader escaped L1 PID1 guard")
	}
	if _, e := driverQuotaReadOn(driverProjectFirst, m); e == nil {
		t.Fatal("mapped project read escaped L1 guard")
	}
	if _, e := driverQuotaReadOn(quotaFirst, m); e == nil {
		t.Fatal("non-driver project accepted")
	}
	if _, _, e := (&node{quotaDriver: true, quotaStateIO: true}).observeDriverQuota(sandbox.Ref{}, "running", m); e == nil {
		t.Fatal("quota IO checkpoint escaped L1 guard")
	}
}

func TestQuotaClearWindowCannotOperateOutsideFixedL1(t *testing.T) {
	n := &node{quotaDriver: true, quotaSnapshot: true}
	if _, e := n.quotaClearCheckpoint(context.Background()); e == nil {
		t.Fatal("window escaped L1 guard")
	}
	if _, e := n.recoverQuotaClear(context.Background()); e == nil {
		t.Fatal("recovery escaped L1 guard")
	}
	if _, e := n.openClearLock(); e == nil {
		t.Fatal("catalog lock escaped L1 guard")
	}
	if _, e := n.fixedCatalogStatus(context.Background()); e == nil {
		t.Fatal("fixed admin escaped L1 guard")
	}
	if _, e := n.clearCatalogFDCount("", nil); e == nil {
		t.Fatal("proc observer escaped L1 guard")
	}
	for _, operation := range []string{"quota-clear-checkpoint", "quota-clear-recover"} {
		if e := (nodeRequest{Version: 1, Operation: operation}).validate(); e != nil {
			t.Fatal(e)
		}
		if e := (nodeRequest{Version: 1, Operation: operation, Phase: "arbitrary"}).validate(); e == nil {
			t.Fatal("window accepts arguments")
		}
	}
}
func TestClearWindowOwnerRequiresExactInitializedQuotaIdentity(t *testing.T) {
	ref := sandbox.Ref{ID: strings.Repeat("1", 32), Generation: strings.Repeat("2", 32)}
	good := clearWindowOwner{Version: 4, Ref: ref, UID: 400001, ProjectID: driverProjectFirst + 1, QuotaAttempted: true, InitializationAttempted: true, TemplateID: strings.Repeat("a", 64)}
	encode := func(o clearWindowOwner) []byte {
		b, e := json.Marshal(o)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	if _, e := decodeClearWindowOwner(encode(good), ref); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*clearWindowOwner){
		func(o *clearWindowOwner) { o.Version = 2 }, func(o *clearWindowOwner) { o.QuotaAttempted = false }, func(o *clearWindowOwner) { o.InitializationAttempted = false }, func(o *clearWindowOwner) { o.UID = 400004 }, func(o *clearWindowOwner) { o.ProjectID++ }, func(o *clearWindowOwner) { o.TemplateID = strings.Repeat("0", 64) }, func(o *clearWindowOwner) { o.Ref.Generation = strings.Repeat("3", 32) },
	} {
		bad := good
		change(&bad)
		if _, e := decodeClearWindowOwner(encode(bad), ref); e == nil {
			t.Fatal("invalid owner accepted")
		}
	}
}
func TestClearKeeperOnlyDropsTheTwoKnownSharedLinks(t *testing.T) {
	workspace := driverQuotaEntry{Inode: 1, Links: 1, Mode: 0100600, UID: 400001, GID: 400001, Size: 128 << 20, Blocks: 128 << 20}
	shared := driverQuotaEntry{Shared: true, Inode: 2, Links: 3, Mode: 0100444, Size: 512 << 20, Blocks: 512 << 20}
	state := shared
	state.Inode = 3
	state.Size = 8192
	state.Blocks = 8192
	before := driverQuotaReceipt{Snapshot: true, Phase: "running", Record: quotaRecord{BHard: 192 << 10, IHard: 128, Space: 128 << 20, Inodes: 1, Valid: 63}, Entries: map[string]driverQuotaEntry{"root/workspace.ext4": workspace, "root/template.mem": shared, "root/template.state": state}}
	shared.Links--
	state.Links--
	after := map[string]driverQuotaEntry{"root/workspace.ext4": workspace, "root/template.mem": shared, "root/template.state": state}
	if _, e := adjustedKeeperQuota(before, before.Record, 128<<20, 1, after); e != nil {
		t.Fatal("one victim unlink misclassified", e)
	}
	if before.Entries["root/template.mem"].Links != 3 {
		t.Fatal("baseline map mutated")
	}
	for _, name := range []string{"root/workspace.ext4", "root/template.mem", "root/template.state"} {
		bad := map[string]driverQuotaEntry{}
		for k, v := range after {
			bad[k] = v
		}
		entry := bad[name]
		entry.Links++
		bad[name] = entry
		if _, e := adjustedKeeperQuota(before, before.Record, 128<<20, 1, bad); e == nil {
			t.Fatal("unexpected link delta accepted")
		}
	}
	bad := before.Record
	bad.Space -= 4096
	if _, e := adjustedKeeperQuota(before, bad, 128<<20, 1, after); e == nil {
		t.Fatal("unaccounted quota accepted")
	}
}
