//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

func TestTLSPolicyNoL0OrArbitraryProtocol(t *testing.T) {
	ctx := context.Background()
	n := &node{nodeBudget: true, quotaDriver: true}
	if _, e := tlsPolicyInventory(tlsPolicyOrphan{}, false, 0); e == nil {
		t.Fatal("L0 inventory")
	}
	if tlsPolicyColdRefusalProbes(ctx, tlsPolicySaved{}, tlsSavedForTestConfig()) == nil {
		t.Fatal("L0 probe files")
	}
	if _, e := captureTLSPolicyOrphan(&tlsPolicyObserver{}); e == nil {
		t.Fatal("L0 orphan inspection")
	}
	if tlsPolicyDirSync() == nil {
		t.Fatal("L0 policy directory Sync")
	}
	if runTLSPolicyGateway() == nil {
		t.Fatal("L0 filter install")
	}
	if _, _, e := startTLSPolicyGateway(ctx); e == nil {
		t.Fatal("L0 observed launcher")
	}
	if _, e := tlsPolicyRead(); e == nil {
		t.Fatal("L0 authority read")
	}
	if _, e := tlsPolicyExpected(tlsSavedForTestConfig()); e == nil {
		t.Fatal("L0 credential reads")
	}
	o := &tlsPolicyObserver{}
	if o.arm(tlsPolicyPre, tlsPolicyRecord{}, tlsPolicyRecord{}) == nil || o.heldValid() == nil || o.invalidAfterReap() == nil {
		t.Fatal("L0 notify access")
	}
	if _, e := o.target(quotaNotif{}); e == nil {
		t.Fatal("L0 proc inspection")
	}
	for _, m := range []tlsPolicyMode{tlsPolicyPre, tlsPolicyPost, "custom"} {
		if _, e := n.nodeTLSPolicyCheckpoint(ctx, m); e == nil {
			t.Fatal("L0 checkpoint")
		}
		if _, e := n.nodeTLSPolicyRecover(ctx, m); e == nil {
			t.Fatal("L0 cold")
		}
	}
	for _, op := range []string{"node-tls-policy-checkpoint", "node-tls-policy-recover"} {
		for _, phase := range []string{"pre-file", "post-commit"} {
			q := nodeRequest{Version: 1, Operation: op, Phase: phase}
			if q.validate() != nil {
				t.Fatal("fixed phase")
			}
			q.Receipt = []byte(`{}`)
			if q.validate() == nil {
				t.Fatal("arbitrary receipt")
			}
		}
		for _, phase := range []string{"", "post-root", "/srv/custom"} {
			if (nodeRequest{Version: 1, Operation: op, Phase: phase}).validate() == nil {
				t.Fatal("unfixed phase")
			}
		}
	}
}

// Only zero input is needed for the L0 fail-before-read assertion.
func tlsSavedForTestConfig() gateway.Config { return gateway.Config{} }
func policySavedForTest(m tlsPolicyMode) tlsPolicySaved {
	old := storeTestReceipt(operatorStorePre)
	before := tlsPolicyRecord{Version: 1, Revision: 1, Digest: strings.Repeat("a", 64)}
	next := tlsPolicyRecord{Version: 1, Revision: 2, Digest: strings.Repeat("b", 64)}
	v := tlsPolicySaved{Version: 2, Mode: m, L1Boot: old.L1Boot, Config: strings.Repeat("c", 64), Auth: strings.Repeat("d", 64), Policy: strings.Repeat("e", 64), Identity: strings.Repeat("f", 64), Lock: strings.Repeat("a", 64), CA: strings.Repeat("b", 64), IngressConfig: strings.Repeat("c", 64), Before: old.Before, Baseline: before, Attempted: next, Observed: tlsPolicyExpectedDisk(m, before, next), Raw: old.Raw, Binding: old.Session, RawKey: strings.Repeat("1", 64), SessionKey: strings.Repeat("2", 64), AlphaOld: strings.Repeat("3", 64), AlphaNew: strings.Repeat("4", 64), BetaExternal: strings.Repeat("5", 64), Boots: [2]string{old.RawBoot, old.SessionBoot}}
	if m == tlsPolicyPre {
		v.Orphan = tlsPolicyOrphan{Name: ".policy-123", SHA: strings.Repeat("e", 64), Bytes: 128}
	}
	return v
}
func TestTLSPolicyReceiptDistinguishesUnacknowledgedAndDurable(t *testing.T) {
	const boot = "55555555-5555-4555-8555-555555555555"
	for _, m := range []tlsPolicyMode{tlsPolicyPre, tlsPolicyPost} {
		good := policySavedForTest(m)
		if e := validateTLSPolicySaved(good, boot); e != nil {
			t.Fatal(e)
		}
		for _, mutate := range []func(*tlsPolicySaved){func(s *tlsPolicySaved) { s.Version++ }, func(s *tlsPolicySaved) { s.Mode = "custom" }, func(s *tlsPolicySaved) { s.L1Boot = boot }, func(s *tlsPolicySaved) { s.Baseline.Revision = 2 }, func(s *tlsPolicySaved) { s.Attempted.Revision = 1 }, func(s *tlsPolicySaved) { s.Attempted.Digest = s.Baseline.Digest }, func(s *tlsPolicySaved) { s.Observed.Revision = 3 }, func(s *tlsPolicySaved) { s.Identity = "bad" }, func(s *tlsPolicySaved) { s.Lock = "bad" }, func(s *tlsPolicySaved) { s.Orphan.Name = "../foreign" }, func(s *tlsPolicySaved) { s.AlphaOld = s.AlphaNew }, func(s *tlsPolicySaved) { s.Raw = s.Binding.Current }, func(s *tlsPolicySaved) { s.Binding.Revision = 2 }, func(s *tlsPolicySaved) {
			s.Binding.Previous = sandbox.Ref{ID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}
		}, func(s *tlsPolicySaved) { s.Boots[1] = s.Boots[0] }, func(s *tlsPolicySaved) { s.Before.Revision++ }} {
			bad := good
			mutate(&bad)
			if validateTLSPolicySaved(bad, boot) == nil {
				t.Fatal("changed private receipt accepted")
			}
		}
	}
}
func TestTLSPolicyFixedCheckedSequence(t *testing.T) {
	for _, m := range []tlsPolicyMode{tlsPolicyPre, tlsPolicyPost} {
		s := tlsPolicySnapshot{HeldID: 1, HeldAt: time.Now(), FileEntries: 1}
		if m == tlsPolicyPost {
			s.DirEntries = 1
			s.MemfdEntries = 1
		}
		if tlsPolicySequence(m, s) != nil {
			t.Fatal("fixed sequence")
		}
		for _, f := range []func(*tlsPolicySnapshot){func(s *tlsPolicySnapshot) { s.HeldID = 0 }, func(s *tlsPolicySnapshot) { s.HeldAt = time.Time{} }, func(s *tlsPolicySnapshot) { s.FileEntries++ }, func(s *tlsPolicySnapshot) { s.DirEntries++ }, func(s *tlsPolicySnapshot) { s.MemfdEntries++ }} {
			bad := s
			f(&bad)
			if tlsPolicySequence(m, bad) == nil {
				t.Fatal("sequence gap accepted")
			}
		}
	}
}
func TestTLSPolicyFilterOnlyFsyncMemfdAndArchitecture(t *testing.T) {
	if tlsPolicyGatewaySHA != "41e9735696072936388d5481b7dcd595e38e2346437379b0f2999b5cc47b730a" {
		t.Fatal("fixed current gateway calibration changed")
	}
	p, e := tlsPolicyProgram()
	if e != nil {
		t.Fatal(e)
	}
	run := func(arch, nr uint32) uint32 {
		var a uint32
		for pc := 0; pc < len(p); pc++ {
			v := p[pc]
			switch v.Code {
			case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
				if v.K == 4 {
					a = arch
				} else if v.K == 0 {
					a = nr
				} else {
					t.Fatal("unexpected load")
				}
			case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
				if a == v.K {
					pc += int(v.Jt)
				} else {
					pc += int(v.Jf)
				}
			case unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K:
				if a >= v.K {
					pc += int(v.Jt)
				} else {
					pc += int(v.Jf)
				}
			case unix.BPF_RET | unix.BPF_K:
				return v.K
			default:
				t.Fatal("unexpected BPF")
			}
		}
		t.Fatal("missing return")
		return 0
	}
	for _, nr := range []uint32{uint32(unix.SYS_FSYNC), uint32(unix.SYS_MEMFD_CREATE), uint32(unix.SYS_SYNCFS), uint32(unix.SYS_WRITE), uint32(unix.SYS_SENDMSG), uint32(unix.SYS_EXIT_GROUP)} {
		want := uint32(unix.SECCOMP_RET_ALLOW)
		if nr == uint32(unix.SYS_FSYNC) || nr == uint32(unix.SYS_MEMFD_CREATE) {
			want = unix.SECCOMP_RET_USER_NOTIF
		}
		if run(unix.AUDIT_ARCH_X86_64, nr) != want {
			t.Fatal("wrong notification selection")
		}
		if run(unix.AUDIT_ARCH_AARCH64, nr) != unix.SECCOMP_RET_KILL_PROCESS {
			t.Fatal("foreign architecture allowed")
		}
	}
	if run(unix.AUDIT_ARCH_X86_64, 0x40000000) != unix.SECCOMP_RET_KILL_PROCESS {
		t.Fatal("x32 allowed")
	}
}
