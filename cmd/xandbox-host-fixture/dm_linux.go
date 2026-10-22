//go:build linux && xandbox_host_fixture

package main

// TEST ONLY. All device-mapper ioctls are reachable only behind the L1 marker,
// root and PID1 guard. Never load a module, map a host-selected device, issue
// DM_REMOVE_ALL, or accept a target/table/path from the control protocol.
import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	dmHeader     = 312
	dmTarget     = 40
	dmName       = "xandbox-l1-state-v1"
	stateDevice  = "/dev/xandbox-state"
	stateSectors = uint64(4194304)
	dmSuspended  = uint32(1 << 1)
	dmActive     = uint32(1 << 5)
	dmSkipLockFS = uint32(1 << 10)
	dmNoFlush    = uint32(1 << 11)
)

type stateMapper struct {
	control *os.File
	backing string
	device  uint64
}

func dmBuffer(flags uint32) []byte {
	b := make([]byte, 4096)
	binary.LittleEndian.PutUint32(b, 4)
	binary.LittleEndian.PutUint32(b[4:], 48)
	binary.LittleEndian.PutUint32(b[12:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[16:], dmHeader)
	binary.LittleEndian.PutUint32(b[28:], flags)
	copy(b[48:176], dmName)
	return b
}

func dmRequest(command uint32) (uintptr, error) {
	switch command {
	case 0, 3, 6, 7, 9, 12:
	default:
		return 0, errors.New("non-allowlisted fixture dm ioctl")
	}
	// Linux 6.8 UAPI: _IOWR(0xfd, command, struct dm_ioctl[312]).
	return uintptr(3<<30 | dmHeader<<16 | 0xfd<<8 | command), nil
}

func (m *stateMapper) call(command uint32, b []byte) error {
	if len(b) != 4096 {
		return errors.New("fixed dm buffer required")
	}
	request, e := dmRequest(command)
	if e != nil {
		return e
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, m.control.Fd(), request, uintptr(unsafe.Pointer(&b[0])))
	if errno != 0 {
		return fmt.Errorf("isolated L1 dm ioctl %d: %w", command, errno)
	}
	if binary.LittleEndian.Uint32(b) != 4 || binary.LittleEndian.Uint32(b[4:]) < 48 || binary.LittleEndian.Uint32(b[12:]) > uint32(len(b)) {
		return errors.New("unexpected pinned-kernel dm ABI")
	}
	return nil
}

func dmTable(target, backing string) ([]byte, error) {
	if target != "linear" && target != "error" {
		return nil, errors.New("fixed linear/error table only")
	}
	b := dmBuffer(0)
	binary.LittleEndian.PutUint32(b[20:], 1)
	s := b[dmHeader:]
	binary.LittleEndian.PutUint64(s[8:], stateSectors)
	copy(s[24:40], target)
	parameters := ""
	if target == "linear" {
		parts := strings.Split(backing, ":")
		if len(parts) != 2 {
			return nil, errors.New("fixed backing device number required")
		}
		for _, part := range parts {
			n, e := strconv.ParseUint(part, 10, 32)
			if e != nil || strconv.FormatUint(n, 10) != part {
				return nil, errors.New("noncanonical backing device")
			}
		}
		parameters = backing + " 0"
	}
	copy(s[dmTarget:], parameters)
	next := (dmTarget + len(parameters) + 1 + 7) &^ 7
	binary.LittleEndian.PutUint32(s[20:], uint32(next))
	return b, nil
}

func (m *stateMapper) table(target string) error {
	b, e := dmTable(target, m.backing)
	if e != nil {
		return e
	}
	return m.call(9, b)
}
func (m *stateMapper) status() (uint32, error) {
	b := dmBuffer(0)
	if e := m.call(7, b); e != nil {
		return 0, e
	}
	if strings.TrimRight(string(b[48:176]), "\x00") != dmName || binary.LittleEndian.Uint64(b[40:]) != m.device || binary.LittleEndian.Uint32(b[20:]) != 1 {
		return 0, errors.New("owned mapper status mismatch")
	}
	return binary.LittleEndian.Uint32(b[28:]), nil
}
func (m *stateMapper) verify(target string, suspended bool) error {
	flags, e := m.status()
	if e != nil {
		return e
	}
	if (flags&dmSuspended != 0) != suspended || flags&dmActive == 0 {
		return errors.New("mapper suspend/active state mismatch")
	}
	b := dmBuffer(1 << 4)
	if e = m.call(12, b); e != nil {
		return e
	}
	start := int(binary.LittleEndian.Uint32(b[16:]))
	if start < dmHeader || start+dmTarget > len(b) {
		return errors.New("invalid target offset")
	}
	s := b[start:]
	if binary.LittleEndian.Uint32(b[20:]) != 1 || binary.LittleEndian.Uint64(s) != 0 || binary.LittleEndian.Uint64(s[8:]) != stateSectors || strings.TrimRight(string(s[24:40]), "\x00") != target {
		return errors.New("owned full-disk target readback mismatch")
	}
	if target == "linear" && !strings.HasPrefix(string(s[dmTarget:]), m.backing+" 0\x00") {
		return errors.New("unexpected linear backing")
	}
	return nil
}
func (m *stateMapper) suspend() error {
	if e := m.call(6, dmBuffer(dmSuspended|dmSkipLockFS|dmNoFlush)); e != nil {
		return e
	}
	return m.verify("linear", true)
}
func (m *stateMapper) resume() error { return m.call(6, dmBuffer(0)) }
func (m *stateMapper) setError() error {
	if e := m.table("error"); e != nil {
		return e
	}
	if e := m.suspend(); e != nil {
		return e
	}
	if e := m.resume(); e != nil {
		return e
	}
	return m.verify("error", false)
}
func (m *stateMapper) linear() error {
	if e := m.table("linear"); e != nil {
		return e
	}
	// Suspend without filesystem freezing; never wait on an already failed FS.
	if e := m.call(6, dmBuffer(dmSuspended|dmSkipLockFS|dmNoFlush)); e != nil {
		return e
	}
	if e := m.resume(); e != nil {
		return e
	}
	return m.verify("linear", false)
}
func (m *stateMapper) close() { _ = m.control.Close() }

func setupStateMapper() (*stateMapper, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	var st unix.Stat_t
	if e := unix.Lstat("/dev/vda", &st); e != nil || st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return nil, errors.New("owned L1 virtio disk required")
	}
	backing := fmt.Sprintf("%d:%d", unix.Major(st.Rdev), unix.Minor(st.Rdev))
	sys := "/sys/dev/block/" + backing
	size, e := os.ReadFile(sys + "/size")
	if e != nil || strings.TrimSpace(string(size)) != "4194304" {
		return nil, errors.New("exact 2GiB L1 virtio disk required")
	}
	uevent, e := os.ReadFile(sys + "/uevent")
	if e != nil || !strings.Contains("\n"+string(uevent), "\nDEVNAME=vda\n") {
		return nil, errors.New("L1 backing identity mismatch")
	}
	if e = unix.Lstat("/dev/mapper/control", &st); e != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR || unix.Major(st.Rdev) != 10 || unix.Minor(st.Rdev) != 236 {
		return nil, errors.New("built-in L1 device mapper required")
	}
	fd, e := unix.Open("/dev/mapper/control", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	m := &stateMapper{control: os.NewFile(uintptr(fd), "owned-L1-dm-control"), backing: backing}
	fail := func(e error) (*stateMapper, error) { m.close(); return nil, e }
	if e = m.call(0, dmBuffer(0)); e != nil {
		return fail(e)
	}
	b := dmBuffer(0)
	copy(b[176:305], "Xandbox-L1-state-fixture-v1")
	if e = m.call(3, b); e != nil {
		return fail(e)
	} // Existing names are refused, never adopted.
	m.device = binary.LittleEndian.Uint64(b[40:])
	if m.device == 0 {
		return fail(errors.New("kernel did not allocate mapper device"))
	}
	if e = m.table("linear"); e != nil {
		return fail(e)
	}
	if e = m.resume(); e != nil {
		return fail(e)
	}
	if e = m.verify("linear", false); e != nil {
		return fail(e)
	}
	if e = unix.Mknod(stateDevice, unix.S_IFBLK|0600, int(m.device)); e != nil {
		return fail(e)
	}
	if e = unix.Lstat(stateDevice, &st); e != nil || st.Rdev != m.device || st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return fail(errors.New("owned mapper node mismatch"))
	}
	return m, nil
}
