//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"golang.org/x/sys/unix"
	"testing"
)

func TestOperatorShutdownNoL0OrGenericRPC(t *testing.T) {
	n := &node{nodeBudget: true, quotaDriver: true}
	ctx := context.Background()
	if runOperatorObservedDaemon(true) == nil {
		t.Fatal("L0 shutdown filter installation")
	}
	if _, _, e := n.startOperatorObserved(ctx, true); e == nil {
		t.Fatal("L0 observed startup")
	}
	if _, e := n.nodeOperatorShutdownCheckpoint(ctx); e == nil {
		t.Fatal("L0 shutdown")
	}
	if _, e := n.nodeOperatorShutdownRecover(ctx); e == nil {
		t.Fatal("L0 recovery")
	}
	if shutdownDurable(storeTestReceipt(operatorStorePre).Raw) == nil {
		t.Fatal("L0 ledger observation")
	}
	if _, e := shutdownInventory(); e == nil {
		t.Fatal("L0 inventory")
	}
	s := newOperatorShutdownObserver(&operatorStoreObserver{})
	if s.signal() == nil || s.bothValid() == nil || s.invalidAfterReap() == nil {
		t.Fatal("L0 notification checks")
	}
	if _, e := s.targetTGID(quotaNotif{}); e == nil {
		t.Fatal("L0 TGID")
	}
	if n.shutdownContender(ctx, s, nodecontrol.State{}) == nil {
		t.Fatal("L0 contender")
	}
	for _, op := range []string{"node-operator-shutdown-checkpoint", "node-operator-shutdown-recover"} {
		q := nodeRequest{Version: 1, Operation: op}
		if q.validate() != nil {
			t.Fatal("fixed RPC")
		}
		q.Phase = "pre-file"
		if q.validate() == nil {
			t.Fatal("generic phase")
		}
		q.Phase = ""
		q.Receipt = []byte(`{}`)
		if q.validate() == nil {
			t.Fatal("generic receipt")
		}
	}
	if _, e := n.recoverOperatorStore(ctx, operatorStorePre, "/tmp/receipt"); e == nil {
		t.Fatal("arbitrary recovery path")
	}
	if _, e := n.recoverOperatorStore(ctx, operatorStorePost, operatorShutdownReceipt); e == nil {
		t.Fatal("shutdown cannot claim post-commit")
	}
}
func TestOperatorShutdownErrorMustBeExactControlCloseNotOtherFailure(t *testing.T) {
	good := []byte(`level=ERROR msg="sandboxd failed" error="control mutation unfinished; retain state ownership: context deadline exceeded"`)
	if shutdownErrorLog(good) != nil {
		t.Fatal("expected real exit diagnostic")
	}
	for _, bad := range [][]byte{nil, []byte("context deadline exceeded"), []byte("sandboxd failed"), append(append([]byte(nil), good...), []byte(" cleanup unfinished")...), append(append([]byte(nil), good...), []byte(" session mutations unfinished")...), append(append([]byte(nil), good...), []byte(" operator listener failed")...), make([]byte, 65537)} {
		if shutdownErrorLog(bad) == nil {
			t.Fatal("unrelated/fatal/bounded diagnostic accepted")
		}
	}
}
func TestOperatorShutdownProgramOnlyFsyncExitGroupAndSameArchitecture(t *testing.T) {
	p, e := operatorShutdownProgram()
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
	for _, row := range []struct{ arch, nr, want uint32 }{{unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_EXIT_GROUP), unix.SECCOMP_RET_USER_NOTIF}, {unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_EXIT), unix.SECCOMP_RET_ALLOW}, {unix.AUDIT_ARCH_X86_64, 0x40000000 | uint32(unix.SYS_EXIT_GROUP), unix.SECCOMP_RET_KILL_PROCESS}, {unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_FSYNC), unix.SECCOMP_RET_USER_NOTIF}, {unix.AUDIT_ARCH_I386, uint32(unix.SYS_FSYNC), unix.SECCOMP_RET_KILL_PROCESS}, {unix.AUDIT_ARCH_X86_64, 0x40000000 | uint32(unix.SYS_FSYNC), unix.SECCOMP_RET_KILL_PROCESS}, {unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_FDATASYNC), unix.SECCOMP_RET_ALLOW}, {unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_SYNCFS), unix.SECCOMP_RET_ALLOW}, {unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_QUOTACTL_FD), unix.SECCOMP_RET_ALLOW}, {unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_WRITE), unix.SECCOMP_RET_ALLOW}} {
		if got := run(row.arch, row.nr); got != row.want {
			t.Fatal("wrong fsync BPF return", got, row.want)
		}
	}
}
