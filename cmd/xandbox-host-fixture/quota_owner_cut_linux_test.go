//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

func testOwnerCutReceipt(t *testing.T) ownerCutReceipt {
	t.Helper()
	base := testCopyCutReceipt(t)
	var o clearWindowOwner
	if e := strictjson.Decode(base.VictimOwner, &o); e != nil {
		t.Fatal(e)
	}
	o.InitializationAttempted = true
	b, e := json.Marshal(o)
	if e != nil {
		t.Fatal(e)
	}
	base.VictimOwner = b
	return ownerCutReceipt{copyCutReceipt: base, VictimBoot: "33333333-3333-4333-8333-333333333333", Ledger: strings.Repeat("8", 64)}
}
func TestOwnerCutPrivateReceiptBudgetAndCrossProfileRejection(t *testing.T) {
	r := testOwnerCutReceipt(t)
	b, e := marshalOwnerCutReceipt(r)
	if e != nil {
		t.Fatal(e)
	}
	var round ownerCutReceipt
	if e = strictjson.Decode(b, &round); e != nil || validateOwnerCutReceipt(round) != nil {
		t.Fatal("owner control roundtrip", e)
	}
	if validateCopyCutReceipt(r.copyCutReceipt) == nil {
		t.Fatal("initialized victim accepted as partial-copy victim")
	}
	partial := testCopyCutReceipt(t)
	if validateOwnerCutReceipt(ownerCutReceipt{copyCutReceipt: partial, VictimBoot: r.VictimBoot, Ledger: r.Ledger}) == nil {
		t.Fatal("uninitialized partial victim accepted as owner unlink")
	}
	q := nodeRequest{Version: 1, Operation: "quota-owner-cut-recover", Receipt: b}
	wire, e := json.Marshal(q)
	if e != nil || len(wire)+1 >= 8192 || q.validate() != nil {
		t.Fatal("owner receipt exceeded unchanged scanner", len(b), e)
	}
	t.Logf("actual realistic14-entry private receipt %d bytes; wire %d bytes including newline", len(b), len(wire)+1)
	for _, change := range []func(*ownerCutReceipt){func(v *ownerCutReceipt) { v.Ledger = "bad" }, func(v *ownerCutReceipt) { v.VictimBoot = v.KeeperBoot }, func(v *ownerCutReceipt) { v.KeeperKey = v.VictimKey }, func(v *ownerCutReceipt) { v.VictimOwner = v.KeeperOwner }, func(v *ownerCutReceipt) { v.KeeperQuota.Project++ }} {
		v := testOwnerCutReceipt(t)
		change(&v)
		if validateOwnerCutReceipt(v) == nil {
			t.Fatal("bad owner receipt accepted")
		}
	}
	r.KeeperQuota.Entries[strings.Repeat("x", copyCutReceiptMax)] = driverQuotaEntry{}
	if _, e = marshalOwnerCutReceipt(r); e == nil {
		t.Fatal("oversized owner receipt accepted")
	}
	if (nodeRequest{Version: 1, Operation: "quota-owner-cut-checkpoint"}).validate() != nil {
		t.Fatal("fixed checkpoint rejected")
	}
	for _, bad := range []nodeRequest{{Version: 1, Operation: "quota-owner-cut-recover"}, {Version: 1, Operation: "quota-owner-cut-recover", Phase: "other", Receipt: b}, {Version: 1, Operation: "quota-owner-cut-checkpoint", Receipt: b}, {Version: 1, Operation: "quota-owner-cut-checkpoint", Phase: "other"}, {Version: 2, Operation: "quota-owner-cut-recover", Receipt: b}, {Version: 1, Operation: "quota-owner-cut-recover", Receipt: json.RawMessage(strings.Repeat("x", 7001))}} {
		if bad.validate() == nil {
			t.Fatal("unbounded owner-cut operation")
		}
	}
}
func TestOwnerCutAndReadOnlyHelpersCannotRunOnL0(t *testing.T) {
	n := &node{quotaSnapshot: true}
	ctx := context.Background()
	if runOwnerDaemon() == nil {
		t.Fatal("owner child escaped L1 guard")
	}
	if _, e := n.startOwnerObserved(ctx); e == nil {
		t.Fatal("owner launch escaped L1 guard")
	}
	if _, _, e := n.quotaOwnerCutCheckpoint(ctx); e == nil {
		t.Fatal("owner checkpoint escaped L1")
	}
	if _, e := n.quotaOwnerCutRecover(ctx, []byte(`{}`)); e == nil {
		t.Fatal("owner recovery escaped L1")
	}
	if _, e := ownerCutOwners(copyCutReceipt{}); e == nil {
		t.Fatal("owner scan escaped L1")
	}
	if _, e := ownerReclaimingLedger(sandbox.Ref{}); e == nil {
		t.Fatal("owner ledger escaped L1")
	}
	if _, e := captureCutKeeper(sandbox.Ref{}, driverProjectFirst, false); e == nil {
		t.Fatal("read-only keeper escaped L1")
	}
	if e := n.finishCutRecovery(ctx, copyCutReceipt{}, ""); e == nil {
		t.Fatal("ordinary recovery helper escaped L1")
	}
	o := &ownerObserver{}
	if _, e := o.match(quotaNotif{}); e == nil {
		t.Fatal("notification escaped L1")
	}
	if e := o.checkHeld(); e == nil {
		t.Fatal("held notification escaped L1")
	}
	if o.arm(sandbox.Ref{}, driverProjectFirst) == nil {
		t.Fatal("invalid target ref accepted")
	}
	good := sandbox.Ref{ID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}
	if o.arm(good, driverProjectFirst+4) == nil {
		t.Fatal("outside4 projects target")
	}
	if o.arm(good, driverProjectFirst) != nil || o.arm(good, driverProjectFirst) == nil {
		t.Fatal("fixed single arm policy")
	}
}
func TestOwnerFsyncProgramPreservesArchitectureAndNeverTargetsOtherCalls(t *testing.T) {
	p, e := ownerNotifyProgram()
	if e != nil {
		t.Fatal(e)
	}
	run := func(arch, nr uint32) uint32 {
		var a uint32
		for pc := 0; pc < len(p); pc++ {
			i := p[pc]
			switch i.Code {
			case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
				if i.K == 4 {
					a = arch
				} else if i.K == 0 {
					a = nr
				} else {
					t.Fatal("unexpected tracee data read")
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
				t.Fatal("unexpected fsync BPF instruction")
			}
		}
		t.Fatal("fsync BPF escaped")
		return 0
	}
	for _, row := range []struct{ arch, nr, want uint32 }{{unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_FSYNC), unix.SECCOMP_RET_USER_NOTIF}, {unix.AUDIT_ARCH_I386, uint32(unix.SYS_FSYNC), unix.SECCOMP_RET_KILL_PROCESS}, {unix.AUDIT_ARCH_X86_64, 0x40000000 | uint32(unix.SYS_FSYNC), unix.SECCOMP_RET_KILL_PROCESS}, {unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_FDATASYNC), unix.SECCOMP_RET_ALLOW}, {unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_SYNCFS), unix.SECCOMP_RET_ALLOW}, {unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_QUOTACTL_FD), unix.SECCOMP_RET_ALLOW}, {unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_WRITE), unix.SECCOMP_RET_ALLOW}} {
		if got := run(row.arch, row.nr); got != row.want {
			t.Fatal("wrong fsync BPF return", got, row.want)
		}
	}
}

func TestOwnerCutLockObservationAcceptsBusyWithoutAcquiring(t *testing.T) {
	if e := ownerCutLockBusy(unix.EWOULDBLOCK); e != nil {
		t.Fatal("expected held catalog lock treated as failure", e)
	}
	if ownerCutLockBusy(nil) == nil {
		t.Fatal("unheld catalog accepted")
	}
	if e := ownerCutLockBusy(unix.EBADF); !errors.Is(e, unix.EBADF) {
		t.Fatal("unrelated probe failure hidden", e)
	}
	if ownerCutCatalogLocked() == nil {
		t.Fatal("lock inode probe escaped L1 guard")
	}
}
