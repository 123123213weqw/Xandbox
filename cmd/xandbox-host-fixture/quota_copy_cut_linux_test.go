//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

func testCopyCutReceipt(t *testing.T) copyCutReceipt {
	t.Helper()
	r := copyCutReceipt{Version: 1, Boot: "11111111-1111-4111-8111-111111111111", KeeperBoot: "22222222-2222-4222-8222-222222222222", Config: strings.Repeat("a", 64), Manifest: strings.Repeat("b", 64), Index: strings.Repeat("7", 64), Template: strings.Repeat("c", 64), Keeper: sandbox.Ref{ID: strings.Repeat("d", 32), Generation: strings.Repeat("e", 32)}, Victim: sandbox.Ref{ID: strings.Repeat("f", 32), Generation: strings.Repeat("1", 32)}, KeeperKey: strings.Repeat("2", 64), VictimKey: strings.Repeat("3", 64)}
	for i, ref := range []sandbox.Ref{r.Keeper, r.Victim} {
		o := clearWindowOwner{Version: 4, Ref: ref, UID: 400000 + i, ProjectID: driverProjectFirst + uint32(i), TemplateID: r.Template, QuotaAttempted: true, InitializationAttempted: i == 0}
		b, e := json.Marshal(o)
		if e != nil {
			t.Fatal(e)
		}
		if i == 0 {
			r.KeeperOwner = b
		} else {
			r.VictimOwner = b
		}
	}
	entries := map[string]driverQuotaEntry{}
	// Include realistic large inode/size values and all14 names, not an empty
	// synthetic receipt that would hide unchanged8KiB scanner overflow.
	for i, name := range []string{".", "root", "root/workspace.ext4", "root/template.mem", "root/template.state", "root/firecracker", "root/firecracker.pid", "root/dev", "root/dev/kvm", "root/run", "root/run/agent", "root/api.sock", "root/vsock.sock", "root/config.json"} {
		entries[name] = driverQuotaEntry{Inode: 999999999999 + uint64(i), Links: 3, Device: 123456789, Mode: unix.S_IFREG | 0600, UID: 400000, GID: 400000, Size: 512 << 20, Blocks: 512 << 20, Shared: strings.Contains(name, "template.")}
	}
	r.KeeperQuota = driverQuotaReceipt{Snapshot: true, Phase: "running", Jail: "/srv/r/j/firecracker/" + r.Keeper.ID + r.Keeper.Generation, Project: driverProjectFirst, Entries: entries, NamespaceBlocks: 128 << 20, NamespaceInodes: 12, Record: quotaRecord{BHard: 192 << 10, IHard: 128, Space: 128 << 20, Inodes: 12}}
	return r
}
func TestCopyCutPrivateControlBudgetAndFixedRouting(t *testing.T) {
	r := testCopyCutReceipt(t)
	b, e := marshalCopyCutReceipt(r)
	if e != nil {
		t.Fatal(e)
	}
	var decoded copyCutReceipt
	if e = strictjson.Decode(b, &decoded); e != nil || validateCopyCutReceipt(decoded) != nil {
		t.Fatal("private receipt roundtrip", e)
	}
	q := nodeRequest{Version: 1, Operation: "quota-copy-cut-recover", Receipt: b}
	wire, e := json.Marshal(q)
	if e != nil || len(wire)+1 >= 8192 || q.validate() != nil {
		t.Fatal("unchanged control scanner budget", len(b), len(wire), e)
	}
	t.Logf("private receipt %d bytes, complete recovery request %d bytes including newline", len(b), len(wire)+1)
	if (nodeRequest{Version: 1, Operation: "quota-copy-cut-checkpoint"}).validate() != nil {
		t.Fatal("fixed checkpoint rejected")
	}
	for _, bad := range []nodeRequest{{Version: 1, Operation: "quota-copy-cut-recover"}, {Version: 1, Operation: "quota-copy-cut-recover", Phase: "arbitrary", Receipt: b}, {Version: 2, Operation: "quota-copy-cut-recover", Receipt: b}, {Version: 1, Operation: "quota-copy-cut-recover", Receipt: json.RawMessage(strings.Repeat("x", copyCutReceiptMax+1))}, {Version: 1, Operation: "probe", Receipt: b}, {Version: 1, Operation: "quota-copy-cut-checkpoint", Receipt: b}, {Version: 1, Operation: "quota-copy-cut-checkpoint", Phase: "16MiB"}} {
		if bad.validate() == nil {
			t.Fatal("unbounded or cross-operation private receipt accepted")
		}
	}
	for name, change := range map[string]func(*copyCutReceipt){"version": func(v *copyCutReceipt) { v.Version = 2 }, "samebootkey": func(v *copyCutReceipt) { v.KeeperKey = v.VictimKey }, "refs": func(v *copyCutReceipt) { v.Victim = v.Keeper }, "owner": func(v *copyCutReceipt) { v.VictimOwner = v.KeeperOwner }, "template": func(v *copyCutReceipt) { v.Template = strings.Repeat("9", 64) }, "phase": func(v *copyCutReceipt) { v.KeeperQuota.Phase = "other" }, "jail": func(v *copyCutReceipt) { v.KeeperQuota.Jail = "/tmp/other" }, "project": func(v *copyCutReceipt) { v.KeeperQuota.Project++ }, "snapshot": func(v *copyCutReceipt) { v.KeeperQuota.Snapshot = false }} {
		v := testCopyCutReceipt(t)
		change(&v)
		if validateCopyCutReceipt(v) == nil {
			t.Fatal("bad private receipt accepted", name)
		}
	}
	r.KeeperQuota.Entries[strings.Repeat("x", 7000)] = driverQuotaEntry{}
	if _, e = marshalCopyCutReceipt(r); e == nil {
		t.Fatal("oversized receipt accepted")
	}
}
func TestCopyCutNeverTouchesL0(t *testing.T) {
	n := &node{quotaSnapshot: true}
	if _, _, e := n.quotaCopyCutCheckpoint(context.Background()); e == nil {
		t.Fatal("checkpoint escaped owned L1")
	}
	if _, e := n.quotaCopyCutRecover(context.Background(), []byte(`{}`)); e == nil {
		t.Fatal("recovery escaped owned L1")
	}
	if _, e := captureCopyKeeper(sandbox.Ref{}, driverProjectFirst); e == nil {
		t.Fatal("keeper sync escaped owned L1")
	}
	if e := copyCutPinsReadOnly(copyCutReceipt{}); e == nil {
		t.Fatal("pin scan escaped owned L1")
	}
	if _, e := n.startCopyObservedOn(context.Background(), true); e == nil {
		t.Fatal("held observer escaped owned L1")
	}
}
func testColdPartialEntries(size int64) map[string]driverQuotaEntry {
	return map[string]driverQuotaEntry{".": {Inode: 10, Mode: unix.S_IFDIR | 0700, Links: 3, Blocks: 4096}, "root": {Inode: 11, Mode: unix.S_IFDIR | 0700, Links: 2, Blocks: 4096}, "root/workspace.ext4": {Inode: 12, Mode: unix.S_IFREG | 0600, Links: 1, Size: size, Blocks: 4096}}
}
func TestCopyCutColdActualSubsetNotStablePrecutAccounting(t *testing.T) {
	q := quotaRecord{BHard: 192 << 10, IHard: 128}
	if _, e := validateColdPartialCopy(q, 0, 0, nil); e != nil {
		t.Fatal("legitimate lost partial namespace", e)
	}
	q.Space = 4096
	q.Inodes = 1
	if _, e := validateColdPartialCopy(q, 4096, 1, map[string]driverQuotaEntry{".": {Inode: 10, Mode: unix.S_IFDIR | 0700, Links: 2, Blocks: 4096}}); e != nil {
		t.Fatal("legitimate top-only namespace", e)
	}
	for _, size := range []int64{0, 4096, copyPrefix} {
		entries := testColdPartialEntries(size)
		q.Space = 12288
		q.Inodes = 3
		if got, e := validateColdPartialCopy(q, 12288, 3, entries); e != nil || got != size {
			t.Fatal("actual cold subset rejected", size, e)
		}
	}
	for name, change := range map[string]func(map[string]driverQuotaEntry){"unknown": func(v map[string]driverQuotaEntry) {
		v["root/other"] = v["root/workspace.ext4"]
		delete(v, "root/workspace.ext4")
	}, "parent": func(v map[string]driverQuotaEntry) { delete(v, "root") }, "large": func(v map[string]driverQuotaEntry) {
		a := v["root/workspace.ext4"]
		a.Size = copyPrefix + 1
		v["root/workspace.ext4"] = a
	}, "shared": func(v map[string]driverQuotaEntry) {
		a := v["root/workspace.ext4"]
		a.Shared = true
		v["root/workspace.ext4"] = a
	}, "uid": func(v map[string]driverQuotaEntry) { a := v["root"]; a.UID = 400001; v["root"] = a }, "alias": func(v map[string]driverQuotaEntry) {
		a := v["root/workspace.ext4"]
		a.Inode = 11
		v["root/workspace.ext4"] = a
	}, "link": func(v map[string]driverQuotaEntry) {
		a := v["root/workspace.ext4"]
		a.Links = 2
		v["root/workspace.ext4"] = a
	}, "toplinks": func(v map[string]driverQuotaEntry) { a := v["."]; a.Links = 2; v["."] = a }, "blocks": func(v map[string]driverQuotaEntry) {
		a := v["root/workspace.ext4"]
		a.Blocks = 8192
		v["root/workspace.ext4"] = a
	}} {
		entries := testColdPartialEntries(4096)
		change(entries)
		q.Space = 12288
		q.Inodes = 3
		if _, e := validateColdPartialCopy(q, 12288, 3, entries); e == nil {
			t.Fatal("invalid cold subset accepted", name)
		}
	}
	entries := testColdPartialEntries(4096)
	for _, q := range []quotaRecord{{BHard: 192 << 10, IHard: 128, Space: 16384, Inodes: 3}, {BHard: 192 << 10, IHard: 128, Space: 12288, Inodes: 2}, {BHard: 192 << 10, IHard: 128, Space: 12288, Inodes: 3, BSoft: 1}, {BHard: 193 << 10, IHard: 128, Space: 12288, Inodes: 3}} {
		if _, e := validateColdPartialCopy(q, 12288, 3, entries); e == nil {
			t.Fatal("wrong cold quota accepted")
		}
	}
}

func TestCopyCutReadOnlyIndexPinsExactBaselineIncludingRetiredTombstone(t *testing.T) {
	r := testCopyCutReceipt(t)
	index := map[string]any{"version": 1, "config_sha256": strings.Repeat("8", 64), "registry_sha256": strings.Repeat("9", 64), "active": r.Template, "entries": map[string]any{r.Template: map[string]any{"phase": "AVAILABLE", "bytes": 512 << 20}, strings.Repeat("6", 64): map[string]any{"phase": "RETIRED", "bytes": 512 << 20}}}
	check := func() error {
		b, e := json.Marshal(index)
		if e != nil {
			t.Fatal(e)
		}
		h := sha256.Sum256(b)
		r.Index = hex.EncodeToString(h[:])
		return validateCopyCutIndex(b, r)
	}
	if e := check(); e != nil {
		t.Fatal("known retired tombstone rejected", e)
	}
	b, _ := json.Marshal(index)
	if validateCopyCutIndex(append(b, ' '), r) == nil {
		t.Fatal("pre-victim index byte drift accepted")
	}
	index["active"] = strings.Repeat("4", 64)
	if check() == nil {
		t.Fatal("active template drift accepted")
	}
	index["active"] = r.Template
	index["entries"].(map[string]any)[strings.Repeat("6", 64)] = map[string]any{"phase": "AVAILABLE", "bytes": 512 << 20}
	if check() == nil {
		t.Fatal("unknown additional available entry accepted")
	}
}
