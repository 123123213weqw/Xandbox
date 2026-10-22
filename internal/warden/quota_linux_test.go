//go:build linux

package warden

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func evaluateQuotaProgram(t *testing.T, arch string, audit, nr, request uint32) uint32 {
	t.Helper()
	p, e := quotaMutationProgram(arch)
	if e != nil {
		t.Fatal(e)
	}
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data, nr)
	binary.LittleEndian.PutUint32(data[4:], audit)
	binary.LittleEndian.PutUint32(data[24:], request)
	var a uint32
	for pc := 0; pc < len(p); pc++ {
		i := p[pc]
		switch i.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			a = binary.LittleEndian.Uint32(data[i.K:])
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
	t.Fatal("unterminated filter")
	return 0
}
func TestQuotaFilterAllowsNormalIOButNoQuotaOrProjectMutation(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		audit := uint32(unix.AUDIT_ARCH_X86_64)
		if arch == "arm64" {
			audit = unix.AUDIT_ARCH_AARCH64
		}
		for _, nr := range []uint32{unix.SYS_QUOTACTL, unix.SYS_QUOTACTL_FD} {
			if evaluateQuotaProgram(t, arch, audit, nr, 0) != unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM) {
				t.Fatal("quota management escaped")
			}
		}
		for _, request := range []uint32{0x401c5820, 0x40086602, 0x40046602} {
			if evaluateQuotaProgram(t, arch, audit, unix.SYS_IOCTL, request) != unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM) {
				t.Fatal("project mutation escaped")
			}
		}
		for _, nr := range []uint32{unix.SYS_READ, unix.SYS_WRITE, unix.SYS_PRCTL, unix.SYS_CLONE} {
			if evaluateQuotaProgram(t, arch, audit, nr, 0) != unix.SECCOMP_RET_ALLOW {
				t.Fatal("ordinary lifecycle syscall denied")
			}
		}
		if evaluateQuotaProgram(t, arch, audit, unix.SYS_IOCTL, 0xae00) != unix.SECCOMP_RET_ALLOW {
			t.Fatal("KVM request denied")
		}
		if evaluateQuotaProgram(t, arch, 0, unix.SYS_WRITE, 0) != unix.SECCOMP_RET_KILL_PROCESS || evaluateQuotaProgram(t, arch, audit, 0x40000000|unix.SYS_IOCTL, 0) != unix.SECCOMP_RET_KILL_PROCESS {
			t.Fatal("compat architecture escaped")
		}
	}
	if _, e := quotaMutationProgram("386"); e == nil {
		t.Fatal("unsupported architecture accepted")
	}
}
func TestQuotaMutationFilterIsInheritedAcrossExec(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("64-bit filter only")
	}
	if mode := os.Getenv("XANDBOX_QUOTA_FILTER_TEST"); mode != "" {
		if mode == "install" {
			if e := installQuotaMutationFilter(); e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestQuotaMutationFilterIsInheritedAcrossExec$")
			cmd.Env = append(os.Environ(), "XANDBOX_QUOTA_FILTER_TEST=verify")
			if out, e := cmd.CombinedOutput(); e != nil {
				t.Fatalf("fixed filtered child failed: %v %s", e, out)
			}
			return
		}
		status, e := os.ReadFile("/proc/self/status")
		if e != nil || !strings.Contains(string(status), "NoNewPrivs:\t1\n") || !strings.Contains(string(status), "Seccomp:\t2\n") {
			t.Fatal("filter/no-new-privileges lost across exec")
		}
		for _, request := range []uintptr{0x401c5820, 0x40086602, 0x40046602} {
			_, _, e := unix.Syscall(unix.SYS_IOCTL, ^uintptr(0), request, 0)
			if e != unix.EPERM {
				t.Fatal("actual forbidden ioctl was not denied", e)
			}
		}
		for _, nr := range []uintptr{unix.SYS_QUOTACTL, unix.SYS_QUOTACTL_FD} {
			_, _, e := unix.Syscall6(nr, ^uintptr(0), 0, 0, 0, 0, 0)
			if e != unix.EPERM {
				t.Fatal("actual quota syscall was not denied", e)
			}
		}
		fmt.Println("fixed inherited quota filter syscall probes passed")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestQuotaMutationFilterIsInheritedAcrossExec$")
	cmd.Env = append(os.Environ(), "XANDBOX_QUOTA_FILTER_TEST=install")
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("isolated filter test failed: %v %s", e, out)
	}
}
