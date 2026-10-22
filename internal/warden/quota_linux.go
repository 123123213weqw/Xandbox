//go:build linux

package warden

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A file owner in the init user namespace can change ext4 project attributes.
// This additional inherited boundary protects quota even for owned files; it
// does not replace the pinned Firecracker allowlist or defend a malicious root
// operator. It is installed only after Run's cgroup/lease capability guards.
func quotaMutationProgram(arch string) ([]unix.SockFilter, error) {
	var audit uint32
	switch arch {
	case "amd64":
		audit = unix.AUDIT_ARCH_X86_64
	case "arm64":
		audit = unix.AUDIT_ARCH_AARCH64
	default:
		return nil, errors.New("quota filter requires a supported 64-bit architecture")
	}
	load := func(offset uint32) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offset}
	}
	ret := func(value uint32) unix.SockFilter { return unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: value} }
	eq := func(value uint32, yes, no uint8) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: value, Jt: yes, Jf: no}
	}
	deny := uint32(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM))
	p := []unix.SockFilter{load(4), eq(audit, 1, 0), ret(unix.SECCOMP_RET_KILL_PROCESS), load(0),
		// No x32/compat syscall-number escape from the 64-bit policy.
		{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, K: 0x40000000, Jf: 1}, ret(unix.SECCOMP_RET_KILL_PROCESS),
		eq(uint32(unix.SYS_QUOTACTL), 0, 1), ret(deny), eq(uint32(unix.SYS_QUOTACTL_FD), 0, 1), ret(deny),
		eq(uint32(unix.SYS_IOCTL), 0, 7), load(24)}
	// ioctl's request is an unsigned 32-bit command even on 64-bit Linux.
	// FSSETFLAGS can clear PROJINHERIT too; cover native and compat encodings.
	for _, request := range []uint32{0x401c5820, 0x40086602, 0x40046602} {
		p = append(p, eq(request, 0, 1), ret(deny))
	}
	return append(p, ret(unix.SECCOMP_RET_ALLOW)), nil
}
func installQuotaMutationFilter() error {
	p, e := quotaMutationProgram(runtime.GOARCH)
	if e != nil {
		return e
	}
	// A single-thread prctl is insufficient: os/exec can fork on another Go
	// thread. All existing threads and all future descendants must inherit NNP.
	if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return errors.New("cannot set all-thread quota no-new-privileges")
	}
	program := unix.SockFprog{Len: uint16(len(p)), Filter: &p[0]}
	tid, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(p)
	runtime.KeepAlive(program)
	if errno != 0 || tid != 0 {
		return errors.New("cannot synchronize inherited quota mutation filter")
	}
	return nil
}
