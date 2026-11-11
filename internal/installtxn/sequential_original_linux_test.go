//go:build linux

package installtxn

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Pinned147 originals, not candidate aliases. Only function names and the
// directory's independent canonical/stat references are changed below.

func (f *filesystem) originalSequentialDirectory147(path string) (*os.File, error) {
	if !originalCanonicalPathE57(path) {
		return nil, ErrPolicy
	}
	fd, e := unix.Openat(int(f.root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	for _, name := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if e = originalSequentialTrustedStat147(fd, true, 0); e != nil {
			unix.Close(fd)
			return nil, e
		}
		next, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	if e = originalSequentialTrustedStat147(fd, true, 0); e != nil {
		unix.Close(fd)
		return nil, e
	}
	return os.NewFile(uintptr(fd), "install-directory"), nil
}

func originalSequentialParseObservation147(raw []byte) (observation, error) {
	var o observation
	values := map[string]string{}
	if len(raw) > 16384 {
		return o, ErrInventory
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		a, b, ok := strings.Cut(line, "=")
		if !ok || values[a] != "" || strings.ContainsAny(b, "\r\x00") {
			return o, ErrInventory
		}
		switch a {
		case "LoadState", "ActiveState", "FragmentPath", "DropInPaths", "UnitFileState", "MainPID":
		default:
			return o, ErrInventory
		}
		if _, ok := values[a]; ok {
			return o, ErrInventory
		}
		values[a] = b
	}
	if len(values) != 6 {
		return o, ErrInventory
	}
	pid, e := strconv.Atoi(values["MainPID"])
	if e != nil || pid < 0 || strconv.Itoa(pid) != values["MainPID"] {
		return o, ErrInventory
	}
	return observation{values["LoadState"], values["ActiveState"], values["FragmentPath"], values["DropInPaths"], values["UnitFileState"], pid}, nil
}

func originalSequentialParseIngressEmptyEvents147(raw []byte) error {
	if len(raw) == 0 || len(raw) > maxIngressEvents || raw[len(raw)-1] != '\n' || strings.ContainsAny(string(raw), "\r\x00") {
		return ErrInventory
	}
	fields := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 || (parts[0] != "populated" && parts[0] != "frozen") || fields[parts[0]] || parts[1] != "0" {
			return ErrInventory
		}
		fields[parts[0]] = true
	}
	if len(fields) != 2 {
		return ErrInventory
	}
	return nil
}

func originalSequentialStateKernelLockOwner147(raw []byte, id runtimeStateIdentity, pid int) error {
	if len(raw) == 0 || len(raw) > 4<<20 || raw[len(raw)-1] != '\n' {
		return runtimeProofFailure(proofStateLockRecordSyntax, ErrInventory)
	}
	found := 0
	var firstLine, firstOrdinal string
	sameText, sameOrdinal := true, true
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		v := strings.Fields(line)
		blocked := len(v) == 9 && v[1] == "->"
		if blocked {
			v = append(v[:1], v[2:]...)
		}
		if len(v) != 8 {
			return runtimeProofFailure(proofStateLockRecordSyntax, ErrInventory)
		}
		parts := strings.Split(v[5], ":")
		if len(parts) != 3 {
			return runtimeProofFailure(proofStateLockRecordSyntax, ErrInventory)
		}
		major, a := strconv.ParseUint(parts[0], 16, 32)
		minor, b := strconv.ParseUint(parts[1], 16, 32)
		inode, c := strconv.ParseUint(parts[2], 10, 64)
		if a != nil || b != nil || c != nil {
			return runtimeProofFailure(proofStateLockRecordSyntax, ErrInventory)
		}
		if major != uint64(unix.Major(id.LockDevice)) || minor != uint64(unix.Minor(id.LockDevice)) || inode != id.LockInode {
			continue
		}
		if blocked || v[1] != "FLOCK" || v[2] != "ADVISORY" || v[3] != "WRITE" || v[4] != strconv.Itoa(pid) || v[6] != "0" || v[7] != "EOF" {
			return runtimeProofFailure(proofStateLockOwnerMismatch, ErrConflict)
		}
		// Diagnostic comparisons only; retain the exact original rejection and
		// final found==1 authority requirement. The displayed ordinal is NOT a
		// stable kernel lock ID. No deduplication, extra read or retry is allowed.
		if found == 0 {
			firstLine, firstOrdinal = line, v[0]
		} else {
			sameText = sameText && line == firstLine
			sameOrdinal = sameOrdinal && v[0] == firstOrdinal
		}
		found++
	}
	if found == 0 {
		return runtimeProofFailure(proofStateLockOwnerMissing, ErrConflict)
	}
	if found != 1 {
		return runtimeLockAmbiguityFailure(found, sameText, sameOrdinal)
	}
	return nil
}

func originalSequentialStateKernelLockVeto147(raw []byte, id runtimeStateIdentity, pid int) error {
	if len(raw) == 0 || len(raw) > 4<<20 || raw[len(raw)-1] != '\n' {
		return runtimeProofFailure(proofStateLockRecordSyntax, ErrInventory)
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		v := strings.Fields(line)
		blocked := len(v) == 9 && v[1] == "->"
		if blocked {
			v = append(v[:1], v[2:]...)
		}
		if len(v) != 8 {
			return runtimeProofFailure(proofStateLockRecordSyntax, ErrInventory)
		}
		parts := strings.Split(v[5], ":")
		if len(parts) != 3 {
			return runtimeProofFailure(proofStateLockRecordSyntax, ErrInventory)
		}
		major, a := strconv.ParseUint(parts[0], 16, 32)
		minor, b := strconv.ParseUint(parts[1], 16, 32)
		inode, c := strconv.ParseUint(parts[2], 10, 64)
		if a != nil || b != nil || c != nil {
			return runtimeProofFailure(proofStateLockRecordSyntax, ErrInventory)
		}
		if major != uint64(unix.Major(id.LockDevice)) || minor != uint64(unix.Minor(id.LockDevice)) || inode != id.LockInode {
			continue
		}
		if blocked || v[1] != "FLOCK" || v[2] != "ADVISORY" || v[3] != "WRITE" || v[4] != strconv.Itoa(pid) || v[6] != "0" || v[7] != "EOF" {
			return runtimeProofFailure(proofStateLockOwnerMismatch, ErrConflict)
		}
	}
	return nil
}

func originalSequentialTrustedStat147(fd int, directory bool, mode uint32) error {
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil {
		return ErrInventory
	}
	kind := uint32(unix.S_IFREG)
	if directory {
		kind = unix.S_IFDIR
	}
	if s.Mode&unix.S_IFMT != kind || (s.Uid != 0 && s.Uid != uint32(os.Geteuid())) || s.Mode&0022 != 0 || s.Mode&07000 != 0 || !directory && (s.Uid != uint32(os.Geteuid()) || s.Nlink != 1) || mode != 0 && s.Mode&0777 != mode {
		return ErrInventory
	}
	return nil
}
