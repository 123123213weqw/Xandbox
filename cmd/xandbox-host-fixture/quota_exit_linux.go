//go:build linux && xandbox_host_fixture

package main

// TEST ONLY. A fixed raw sys_exit observer, installed solely by owned L1 PID1
// while its exact daemon thread is at a fixed verified entry notification.
// It records only the first matching return code, never arguments/data/stacks.
import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

type quotaBPFInstruction struct {
	Code, Registers uint8
	Offset          int16
	Immediate       int32
}
type quotaExitResult struct {
	Seen   uint64
	Return int64
}
type quotaExitTrace struct{ mapFD, programFD, linkFD int }

// Linux6.8 x86_64 pt_regs.orig_ax is the 16th u64. Raw sys_exit arguments
// are pt_regs* and signed long return. No runtime BTF/compiler is required.
func quotaExitProgram(mapFD, pid, tid int) ([]quotaBPFInstruction, error) {
	return quotaExitProgramOn(mapFD, pid, tid, false)
}
func quotaExitProgramOn(mapFD, pid, tid int, loss bool) ([]quotaBPFInstruction, error) {
	if runtime.GOARCH != "amd64" || mapFD < 0 || pid < 1 || tid < 1 || uint64(pid) > 1<<31-1 || uint64(tid) > 1<<31-1 {
		return nil, errors.New("fixed amd64 owned exit observer required")
	}
	p := []quotaBPFInstruction{}
	add := func(c, d, s uint8, off int16, imm int32) { p = append(p, quotaBPFInstruction{c, d | s<<4, off, imm}) }
	jumps := []int{}
	jump := func(c, d, s uint8, imm int32) { jumps = append(jumps, len(p)); add(c, d, s, 0, imm) }
	add(0xbf, 6, 1, 0, 0)  // saved raw context
	add(0x85, 0, 0, 0, 14) // bpf_get_current_pid_tgid
	add(0x18, 7, 0, 0, int32(tid))
	add(0, 0, 0, 0, int32(pid))
	jump(0x5d, 0, 7, 0) // full TGID:TID, not just recycled low TID
	add(0x79, 3, 6, 0, 0)
	add(0x07, 3, 0, 0, 120) // pt_regs.orig_ax
	add(0xbf, 1, 10, 0, 0)
	add(0x07, 1, 0, 0, -8)
	add(0xb7, 2, 0, 0, 8)
	add(0x85, 0, 0, 0, 113) // bpf_probe_read_kernel, no unsafe direct kernel dereference
	jump(0x55, 0, 0, 0)
	add(0x79, 7, 10, -8, 0)
	nr := int32(unix.SYS_SYNCFS)
	if loss {
		nr = int32(unix.SYS_QUOTACTL_FD)
	}
	jump(0x55, 7, 0, nr)
	add(0x18, 1, unix.BPF_PSEUDO_MAP_FD, 0, int32(mapFD))
	add(0, 0, 0, 0, 0)
	add(0x62, 10, 0, -4, 0)
	add(0xbf, 2, 10, 0, 0)
	add(0x07, 2, 0, 0, -4)
	add(0x85, 0, 0, 0, 1) // fixed array map lookup, key0
	jump(0x15, 0, 0, 0)
	add(0x79, 1, 0, 0, 0)
	jump(0x55, 1, 0, 0) // latch first return, never overwrite it
	add(0x79, 1, 6, 8, 0)
	add(0x7b, 0, 1, 8, 0)
	add(0xb7, 2, 0, 0, 1)
	add(0xdb, 0, 2, 0, 0) // publish seen last, atomic add
	end := len(p)
	add(0xb7, 0, 0, 0, 0)
	add(0x95, 0, 0, 0, 0)
	for _, i := range jumps {
		p[i].Offset = int16(end - i - 1)
	}
	return p, nil
}
func quotaBPF(command int, attribute []byte) (int, error) {
	if e := requireNode(); e != nil {
		return -1, e
	}
	if len(attribute) < 16 || len(attribute) > 128 {
		return -1, errors.New("fixed BPF attribute bounds")
	}
	if command != unix.BPF_MAP_CREATE && command != unix.BPF_PROG_LOAD && command != unix.BPF_RAW_TRACEPOINT_OPEN && command != unix.BPF_MAP_LOOKUP_ELEM {
		return -1, errors.New("non-allowlisted fixture BPF operation")
	}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(command), uintptr(unsafe.Pointer(&attribute[0])), uintptr(len(attribute)))
	runtime.KeepAlive(attribute)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}
func (t *quotaExitTrace) close() {
	for _, fd := range []int{t.linkFD, t.programFD, t.mapFD} {
		if fd >= 0 {
			unix.Close(fd)
		}
	}
	t.linkFD, t.programFD, t.mapFD = -1, -1, -1
}
func (o *quotaNotifier) startExitTrace(q quotaNotif) (_ *quotaExitTrace, err error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if o.barrier == nil || o.barrier.Mode != quotaReserveEIO || q.Data.NR != int32(unix.SYS_SYNCFS) {
		return nil, errors.New("only fixed owned syncfs EIO observation permitted")
	}
	if e := o.inspect(q); e != nil {
		return nil, e
	}
	return o.loadFixedExitTrace(q, false)
}
func (o *quotaNotifier) startListenerExitTrace(q quotaNotif) (*quotaExitTrace, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if o.loss == nil || o.loss.Mode.name() != o.state.name || q.Data.NR != int32(unix.SYS_QUOTACTL_FD) || q.Data.Args[1] != 0x80000802 {
		return nil, errors.New("only fixed owned SET listener loss observation permitted")
	}
	if e := o.inspect(q); e != nil {
		return nil, e
	}
	return o.loadFixedExitTrace(q, true)
}
func (o *quotaNotifier) loadFixedExitTrace(q quotaNotif, loss bool) (_ *quotaExitTrace, err error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	t := &quotaExitTrace{mapFD: -1, programFD: -1, linkFD: -1}
	defer func() {
		if err != nil {
			t.close()
		}
	}()
	a := make([]byte, 72)
	binary.LittleEndian.PutUint32(a[0:], unix.BPF_MAP_TYPE_ARRAY)
	binary.LittleEndian.PutUint32(a[4:], 4)
	binary.LittleEndian.PutUint32(a[8:], 16)
	binary.LittleEndian.PutUint32(a[12:], 1)
	copy(a[28:], "xb_quota_exit")
	var e error
	t.mapFD, e = quotaBPF(unix.BPF_MAP_CREATE, a)
	if e != nil {
		return nil, e
	}
	program, e := quotaExitProgramOn(t.mapFD, o.pid, int(q.PID), loss)
	if e != nil {
		return nil, e
	}
	license := []byte("GPL\x00")
	log := make([]byte, 4096)
	// Nested pointers are serialized in bpf_attr, not direct Syscall pointer
	// arguments. Pin them before taking addresses: KeepAlive alone cannot
	// prevent a stack relocation between encoding and the nested syscall.
	var pinned runtime.Pinner
	pinned.Pin(&program[0])
	pinned.Pin(&license[0])
	pinned.Pin(&log[0])
	defer pinned.Unpin()
	a = make([]byte, 72)
	binary.LittleEndian.PutUint32(a[0:], unix.BPF_PROG_TYPE_RAW_TRACEPOINT)
	binary.LittleEndian.PutUint32(a[4:], uint32(len(program)))
	binary.LittleEndian.PutUint64(a[8:], uint64(uintptr(unsafe.Pointer(&program[0]))))
	binary.LittleEndian.PutUint64(a[16:], uint64(uintptr(unsafe.Pointer(&license[0]))))
	binary.LittleEndian.PutUint32(a[24:], 1)
	binary.LittleEndian.PutUint32(a[28:], uint32(len(log)))
	binary.LittleEndian.PutUint64(a[32:], uint64(uintptr(unsafe.Pointer(&log[0]))))
	copy(a[48:], "xb_quota_exit")
	t.programFD, e = quotaBPF(unix.BPF_PROG_LOAD, a)
	runtime.KeepAlive(program)
	runtime.KeepAlive(license)
	runtime.KeepAlive(log)
	if e != nil {
		return nil, fmt.Errorf("fixed exit observer load: %w: %s", e, strings.TrimRight(string(log), "\x00"))
	}
	name := []byte("sys_exit\x00")
	pinned.Pin(&name[0])
	a = make([]byte, 16)
	binary.LittleEndian.PutUint64(a[0:], uint64(uintptr(unsafe.Pointer(&name[0]))))
	binary.LittleEndian.PutUint32(a[8:], uint32(t.programFD))
	t.linkFD, e = quotaBPF(unix.BPF_RAW_TRACEPOINT_OPEN, a)
	runtime.KeepAlive(name)
	if e != nil {
		return nil, e
	}
	return t, nil
}
func (t *quotaExitTrace) read() (quotaExitResult, error) {
	var out quotaExitResult
	if e := requireNode(); e != nil {
		return out, e
	}
	if t == nil || t.mapFD < 0 || t.linkFD < 0 {
		return out, errors.New("owned exit observer is absent")
	}
	key := uint32(0)
	var pinned runtime.Pinner
	pinned.Pin(&key)
	pinned.Pin(&out)
	defer pinned.Unpin()
	a := make([]byte, 32)
	binary.LittleEndian.PutUint32(a[0:], uint32(t.mapFD))
	binary.LittleEndian.PutUint64(a[8:], uint64(uintptr(unsafe.Pointer(&key))))
	binary.LittleEndian.PutUint64(a[16:], uint64(uintptr(unsafe.Pointer(&out))))
	_, e := quotaBPF(unix.BPF_MAP_LOOKUP_ELEM, a)
	runtime.KeepAlive(&key)
	runtime.KeepAlive(&out)
	return out, e
}
