//go:build linux

package installtxn

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"golang.org/x/sys/unix"
)

func stateProcDirectory(parent int, name string) (*os.File, error) {
	fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	var fs unix.Statfs_t
	if e = unix.Fstatfs(fd, &fs); e != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
		return nil, ErrInventory
	}
	return os.NewFile(uintptr(fd), "original-state-proc-directory"), nil
}

func stateFDMatches(st unix.Stat_t, id runtimeStateIdentity) bool {
	return uint64(st.Dev) == id.LockDevice && st.Ino == id.LockInode && st.Mode == unix.S_IFREG|0600 && st.Nlink == 1 && st.Uid == uint32(os.Geteuid()) && st.Size == 0 && st.Ctim.Sec == id.LockChangeSeconds && st.Ctim.Nsec == id.LockChangeNanos
}

// Discover a single original descriptor, then read its kernel-associated lock.
// Discovery is bounded and is not cached. Multiple matching FDs (even aliases),
// permission/read/format uncertainty, disappearance or rebinding all refuse.
// Unrelated descriptor ENOENT is the sole tolerated enumeration race; it never
// supplies a witness. No target FD is opened, duplicated, flocked or signaled.
func stateOriginalFDLock(ctx context.Context, id runtimeStateIdentity, pid int) error {
	if e := ctx.Err(); e != nil {
		return runtimeProofFailure(proofStateFDOpen, e)
	}
	proc, e := stateProcDirectory(unix.AT_FDCWD, "/proc/"+strconv.Itoa(pid))
	if e != nil {
		return runtimeProofFailure(proofStateFDOpen, e)
	}
	defer proc.Close()
	fds, e := stateProcDirectory(int(proc.Fd()), "fd")
	if e != nil {
		return runtimeProofFailure(proofStateFDOpen, e)
	}
	defer fds.Close()
	names, e := fds.Readdirnames(stateOwnerFDLimit + 1)
	if e != nil && !errors.Is(e, io.EOF) {
		return runtimeProofFailure(proofStateFDList, e)
	}
	if e = stateFDNames(names); e != nil {
		return runtimeProofFailure(proofStateFDList, e)
	}
	var selected string
	for _, name := range names {
		if e := ctx.Err(); e != nil {
			return runtimeProofFailure(proofStateFDList, e)
		}
		var st unix.Stat_t
		if e = unix.Fstatat(int(fds.Fd()), name, &st, 0); errors.Is(e, unix.ENOENT) {
			continue
		} else if e != nil {
			return runtimeProofFailure(proofStateFDStat, e)
		}
		if uint64(st.Dev) != id.LockDevice || st.Ino != id.LockInode {
			continue
		}
		if !stateFDMatches(st, id) {
			return runtimeProofFailure(proofStateFDStat, ErrInventory)
		}
		if selected != "" {
			return runtimeProofFailure(proofStateFDMultiple, ErrConflict)
		}
		selected = name
	}
	if selected == "" {
		return runtimeProofFailure(proofStateLockOwnerMissing, ErrConflict)
	}
	if e := ctx.Err(); e != nil {
		return runtimeProofFailure(proofStateFDRead, e)
	}
	info, e := stateProcDirectory(int(proc.Fd()), "fdinfo")
	if e != nil {
		return runtimeProofFailure(proofStateFDOpen, e)
	}
	defer info.Close()
	fd, e := unix.Openat(int(info.Fd()), selected, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return runtimeProofFailure(proofStateFDRead, e)
	}
	in := os.NewFile(uintptr(fd), "original-state-fdinfo")
	defer in.Close()
	var fs unix.Statfs_t
	if e = unix.Fstatfs(fd, &fs); e != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		if e == nil {
			e = ErrInventory
		}
		return runtimeProofFailure(proofStateFDRead, e)
	}
	raw, e := io.ReadAll(io.LimitReader(in, stateFDInfoLimit+1))
	if e != nil {
		return runtimeProofFailure(proofStateFDRead, e)
	}
	row, e := stateFDInfoLockRecord(raw, id.LockInode)
	if e != nil {
		return runtimeProofFailure(proofStateFDRecord, e)
	}
	// SAME original per-row BSD/WRITE/PID/dev/inode/whole-file predicate and
	// exactly-one row requirement. No global-list row is selected/deduplicated.
	if e = stateKernelLockOwner(row, id, pid); e != nil {
		return e
	}
	var after unix.Stat_t
	if e = unix.Fstatat(int(fds.Fd()), selected, &after, 0); e != nil {
		return runtimeProofFailure(proofStateFDStat, e)
	}
	if !stateFDMatches(after, id) {
		return runtimeProofFailure(proofStateFDStat, ErrInventory)
	}
	return nil
}

// This is a NEGATIVE veto, never an ownership witness. Keep every original
// row/type/waiter/foreign-owner/malformed check, but do not infer global lock
// object cardinality from a changing whole-system seq_file iteration. Exactly
// one FD-local lock row AND original inode/path/incarnation are independently
// mandatory. This function alone, including a nil result, authorizes nothing.
func stateKernelLockVeto(raw []byte, id runtimeStateIdentity, pid int) error {
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

// Preserve the original live incarnation and original state path/ctime, and
// HOLD its inode across the FD-local kernel observation. A valid row is not a
// stopped/reclaimed/activation proof. Never fall back to a global /proc/locks
// scan as positive authority, another PID, a second FD or a retry on rejection.
func (f *filesystem) runtimeStateOwnedBy(ctx context.Context, id runtimeStateIdentity, process nodecontrol.ProcessIdentity) error {
	if e := ctx.Err(); e != nil {
		return runtimeProofFailure(proofStateOwnerState, e)
	}
	w, e := nodecontrol.NewProcessWatch(process.PID)
	if e != nil {
		return runtimeProofFailure(proofStateWatchOpen, e)
	}
	defer w.Close()
	if w.Identity() != process {
		return runtimeProofFailure(proofStateIncarnation, ErrConflict)
	}
	state, e := f.openRuntimeState()
	if e != nil {
		return runtimeProofFailure(proofStateOwnerState, e)
	}
	defer state.close()
	if state.id != id {
		return runtimeProofFailure(proofStateOwnerState, ErrConflict)
	}
	if e = stateOriginalFDLock(ctx, id, process.PID); e != nil {
		return e
	}
	// FD-local reporting omits blocked requests. Retain the original fresh
	// global per-row negative veto; malformed/foreign/waiter observations may
	// never be overridden by a valid FD witness. Global row count is NOT used
	// as positive authority and no negative result is retried or deduplicated.
	raw, e := boundedProcessFile("/proc/locks", 4<<20)
	if e != nil {
		return runtimeProofFailure(proofStateLocksRead, e)
	}
	if e = stateKernelLockVeto(raw, id, process.PID); e != nil {
		return e
	}
	// Existing private fault seam only; no public option or alternate source.
	if e = f.point("runtime-state-fd-after-observation"); e != nil {
		return runtimeProofFailure(proofStateOwnerRecheck, e)
	}
	if e = w.Alive(); e != nil {
		return runtimeProofFailure(proofStateWatchLive, e)
	}
	if e := ctx.Err(); e != nil {
		return runtimeProofFailure(proofStateOwnerRecheck, e)
	}
	return runtimeProofFailure(proofStateOwnerRecheck, state.verify(f))
}
