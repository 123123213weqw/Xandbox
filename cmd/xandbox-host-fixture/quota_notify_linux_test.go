//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestQuotaNotifyUAPIAndNoL0Entry(t *testing.T) {
	if unsafe.Sizeof(quotaNotifData{}) != 64 || unsafe.Sizeof(quotaNotif{}) != 80 || unsafe.Offsetof(quotaNotif{}.Data) != 16 || unsafe.Sizeof(quotaNotifResponse{}) != 24 || unsafe.Sizeof(quotaNotifSizes{}) != 6 || quotaNotifIDValid != 0x40082102 {
		t.Fatal("unexpected Linux v6.8 seccomp UAPI")
	}
	if e := runQuotaSyscallDaemon("reserve-set-eio"); e == nil {
		t.Fatal("listener install escaped L1 guard")
	}
	if _, _, e := startQuotaNotified(context.Background(), "reserve-set-eio", "/srv/sr/0"); e == nil {
		t.Fatal("launcher escaped L1 guard")
	}
	if _, e := (&node{quotaDriver: true}).quotaSyscallSetup(context.Background()); e == nil {
		t.Fatal("setup escaped L1 guard")
	}
	o := &quotaNotifier{}
	if e := o.inspect(quotaNotif{}); e == nil {
		t.Fatal("observer escaped L1 guard")
	}
	if e := o.boundary(quotaNotif{}); e == nil {
		t.Fatal("quota observation escaped L1 guard")
	}
	for _, name := range []string{"", "../clear-set-eio", "reserve-set-eio/extra", "quotactl", "/dev/vda"} {
		if _, e := quotaSyscallBase(name); e == nil {
			t.Fatal("arbitrary case accepted")
		}
		if _, e := quotaSyscallRuntime(name); e == nil {
			t.Fatal("arbitrary runtime accepted")
		}
	}
	for _, name := range quotaSyscallCases {
		if _, e := quotaSyscallBase(name); e != nil {
			t.Fatal(e)
		}
	}
	if e := (nodeRequest{Version: 1, Operation: "quota-syscall-setup"}).validate(); e != nil {
		t.Fatal(e)
	}
	if e := (nodeRequest{Version: 1, Operation: "quota-syscall-setup", Phase: "reserve-set-eio"}).validate(); e == nil {
		t.Fatal("parameterized control operation")
	}
}

func TestQuotaNotifyProgramExactSyscallAndArchitecture(t *testing.T) {
	p, e := quotaNotifyProgram()
	if e != nil {
		t.Fatal(e)
	}
	run := func(arch, nr uint32) uint32 {
		a := uint32(0)
		for pc := 0; pc < len(p); pc++ {
			i := p[pc]
			switch i.Code {
			case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
				if i.K == 4 {
					a = arch
				} else if i.K == 0 {
					a = nr
				} else {
					t.Fatal("unexpected BPF load")
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
				t.Fatal("unexpected BPF operation")
			}
		}
		t.Fatal("BPF escaped")
		return 0
	}
	for _, v := range []struct{ arch, nr, want uint32 }{
		{unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_QUOTACTL_FD), unix.SECCOMP_RET_USER_NOTIF},
		{unix.AUDIT_ARCH_I386, uint32(unix.SYS_QUOTACTL_FD), unix.SECCOMP_RET_KILL_PROCESS},
		{unix.AUDIT_ARCH_X86_64, 0x40000000 | uint32(unix.SYS_QUOTACTL_FD), unix.SECCOMP_RET_KILL_PROCESS},
		{unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_IOCTL), unix.SECCOMP_RET_ALLOW},
		{unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_QUOTACTL), unix.SECCOMP_RET_ALLOW},
		{unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_EXECVE), unix.SECCOMP_RET_ALLOW},
	} {
		if got := run(v.arch, v.nr); got != v.want {
			t.Fatalf("unexpected action %x != %x", got, v.want)
		}
	}
}
func TestQuotaNotifyOnlyExactStageAndNeverSyntheticSuccess(t *testing.T) {
	for _, name := range quotaSyscallCases {
		s := quotaNotifyState{name: name}
		for _, command := range []uint64{0x80000102, 0x80000402, 0x80000702, 0x80000802} {
			if s.wants(command) {
				t.Fatal("unarmed injection")
			}
		}
		s.armed = true
		want := uint64(0x80000802)
		if name == "reserve-read-erofs" || name == "clear-read-eio" {
			want = 0x80000702
		}
		if name == "reserve-sync-eio" || name == "clear-sync-erofs" {
			want = 0x80000102
		}
		if want != 0x80000802 && s.wants(want) {
			t.Fatal("GET/SYNC targeted before preceding SET")
		}
		s.seenSet = true
		for _, command := range []uint64{0, 0x80000102, 0x80000402, 0x80000702, 0x80000802} {
			if s.wants(command) != (command == want) {
				t.Fatal("wrong syscall targeted")
			}
		}
		pass := s.response(7, false)
		if pass.ID != 7 || pass.Value != 0 || pass.Error != 0 || pass.Flags != unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE {
			t.Fatal("success was emulated rather than continued")
		}
		fail := s.response(9, true)
		errno := -int32(unix.EIO)
		if name == "reserve-read-erofs" || name == "clear-sync-erofs" {
			errno = -int32(unix.EROFS)
		}
		if fail.ID != 9 || fail.Value != 0 || fail.Error != errno || fail.Flags != 0 {
			t.Fatal("wrong explicit injected errno response")
		}
	}
}
