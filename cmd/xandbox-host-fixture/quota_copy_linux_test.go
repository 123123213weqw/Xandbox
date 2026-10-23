//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCopyFixtureIsFixedAndCannotRunOnL0(t *testing.T) {
	if runCopyDaemon() == nil {
		t.Fatal("copy child escaped L1 guard")
	}
	n := &node{quotaSnapshot: true}
	if _, e := n.quotaCopySetup(context.Background()); e == nil {
		t.Fatal("setup escaped L1")
	}
	if _, e := n.startCopyObserved(context.Background()); e == nil {
		t.Fatal("start escaped L1")
	}
	if _, _, e := (&copyObserver{}).match(quotaNotif{}); e == nil {
		t.Fatal("proc observation escaped L1")
	}
	if _, e := copyAdmin(context.Background(), "status"); e == nil {
		t.Fatal("admin escaped L1")
	}
	if (nodeRequest{Version: 1, Operation: "quota-copy-setup"}).validate() != nil || (nodeRequest{Version: 1, Operation: "quota-copy-setup", Phase: "16MiB"}).validate() == nil {
		t.Fatal("copy RPC must be fixed and phase-less")
	}
	p := testPolicy()
	p.Profile = "quota-copy-v1"
	m, d, c, e := p.resources()
	if e != nil || m != 3072 || d != 4<<30 || c != 4<<30 || p.validate() != nil {
		t.Fatal("explicit copy resource bound")
	}
	p.Profile = "quota-copy-v2"
	if p.validate() == nil || p.arguments() != nil {
		t.Fatal("arbitrary resource profile")
	}
	good := "/srv/r/j/firecracker/" + strings.Repeat("a", 32) + strings.Repeat("b", 32) + "/root/workspace.ext4"
	ref, ok := copyWriteRef(good)
	if !ok || ref.ID != strings.Repeat("a", 32) || ref.Generation != strings.Repeat("b", 32) {
		t.Fatal("fixed workspace target")
	}
	for _, s := range []string{good + " (deleted)", good + "/extra", strings.Replace(good, "workspace.ext4", "template.mem", 1), strings.Replace(good, "/srv/r/", "/tmp/r/", 1), strings.Replace(good, strings.Repeat("a", 32), "../escape", 1)} {
		if _, ok := copyWriteRef(s); ok {
			t.Fatal("unbounded copy target")
		}
	}
}
func TestCopyNotifyProgramSelectsOnlyFull128KiBWriteAndExactArchitecture(t *testing.T) {
	p, e := copyNotifyProgram()
	if e != nil {
		t.Fatal(e)
	}
	run := func(arch, nr uint32, count uint64) uint32 {
		var a uint32
		for pc := 0; pc < len(p); pc++ {
			i := p[pc]
			switch i.Code {
			case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
				switch i.K {
				case 0:
					a = nr
				case 4:
					a = arch
				case 32:
					a = uint32(count)
				case 36:
					a = uint32(count >> 32)
				default:
					t.Fatal("unexpected pointer/data load")
				}
			case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
				if a == i.K {
					pc += int(i.Jt)
				} else {
					pc += int(i.Jf)
				}
			case unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K:
				if a >= i.K {
					pc += int(i.Jt)
				} else {
					pc += int(i.Jf)
				}
			case unix.BPF_RET | unix.BPF_K:
				return i.K
			default:
				t.Fatal("unexpected BPF instruction")
			}
		}
		t.Fatal("filter escaped")
		return 0
	}
	for _, v := range []struct {
		arch, nr uint32
		count    uint64
		want     uint32
	}{
		{unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_WRITE), copyChunk, unix.SECCOMP_RET_USER_NOTIF},
		{unix.AUDIT_ARCH_I386, uint32(unix.SYS_WRITE), copyChunk, unix.SECCOMP_RET_KILL_PROCESS},
		{unix.AUDIT_ARCH_X86_64, 0x40000000 | uint32(unix.SYS_WRITE), copyChunk, unix.SECCOMP_RET_KILL_PROCESS},
		{unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_WRITE), copyChunk - 1, unix.SECCOMP_RET_ALLOW},
		{unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_WRITE), copyChunk + (1 << 32), unix.SECCOMP_RET_ALLOW},
		{unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_PWRITE64), copyChunk, unix.SECCOMP_RET_ALLOW},
		{unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_COPY_FILE_RANGE), copyChunk, unix.SECCOMP_RET_ALLOW},
		{unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_QUOTACTL_FD), copyChunk, unix.SECCOMP_RET_ALLOW},
	} {
		if got := run(v.arch, v.nr, v.count); got != v.want {
			t.Fatalf("filter got%x want%x", got, v.want)
		}
	}
}
func TestPartialCopyAccountingRejectsFullCopiesUnknownNamesAndUnaccountedAllocation(t *testing.T) {
	entries := map[string]driverQuotaEntry{
		".": {Mode: unix.S_IFDIR | 0700, Links: 3}, "root": {Mode: unix.S_IFDIR | 0700, Links: 2},
		"root/workspace.ext4": {Mode: unix.S_IFREG | 0600, Links: 1, Size: copyPrefix},
	}
	q := quotaRecord{BHard: 192 << 10, IHard: 128, Space: copyPrefix + 8192, Inodes: 3}
	if copyPartialAccounting(q, q.Space, 3, entries) != nil {
		t.Fatal("actual prefix rejected")
	}
	for _, bad := range []quotaRecord{{BHard: 192 << 10, IHard: 128, Space: 128 << 20, Inodes: 3}, {BHard: 192 << 10, IHard: 128, Space: copyPrefix - 4096, Inodes: 3}, {BHard: 192 << 10, IHard: 128, Space: q.Space, Inodes: 2}, {BHard: 192 << 10, IHard: 128, Space: q.Space, Inodes: 3, BSoft: 1}} {
		if copyPartialAccounting(bad, bad.Space, bad.Inodes, entries) == nil {
			t.Fatal("invalid partial namespace quota")
		}
	}
	if copyPartialAccounting(q, q.Space+4096, 3, entries) == nil {
		t.Fatal("unaccounted allocation")
	}
	original := entries["root/workspace.ext4"]
	for _, bad := range []driverQuotaEntry{{Mode: unix.S_IFREG | 0600, Links: 1, Size: 128 << 20}, {Mode: unix.S_IFREG | 0600, Links: 2, Size: copyPrefix}, {Mode: unix.S_IFREG | 0444, Links: 1, Size: copyPrefix}, {Mode: unix.S_IFREG | 0600, Links: 1, Size: copyPrefix, Shared: true}, {Mode: unix.S_IFREG | 0600, Links: 1, Size: copyPrefix, UID: 400001}} {
		entries["root/workspace.ext4"] = bad
		if copyPartialAccounting(q, q.Space, 3, entries) == nil {
			t.Fatal("bad partial inode accepted")
		}
	}
	entries["root/workspace.ext4"] = original
	entries["other"] = entries["root"]
	delete(entries, "root")
	if copyPartialAccounting(q, q.Space, 3, entries) == nil {
		t.Fatal("unknown or missing names accepted")
	}
}
