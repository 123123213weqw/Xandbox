//go:build linux

package installtxn

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"golang.org/x/sys/unix"
)

// A v2 Stop binds the EXISTING state root and controller.lock before effects.
// These inode identities are not a portable backup or a reboot certificate.

func (p runtimeStateIdentity) valid() bool {
	return p.RootInode != 0 && p.LockInode != 0 && p.LockChangeSeconds > 0 && p.LockChangeNanos >= 0 && p.LockChangeNanos < 1_000_000_000
}

type runtimeStateLease struct {
	root, lock *os.File
	id         runtimeStateIdentity
}

// The kernel describes active BSD locks as FLOCK ADVISORY WRITE PID
// major:minor:inode 0 EOF; blocked waiters have a separate -> marker.
// https://docs.kernel.org/filesystems/proc.html#proc-pid-fdinfo-fd-information-about-opened-file
func stateKernelLockOwner(raw []byte, id runtimeStateIdentity, pid int) error {
	if len(raw) == 0 || len(raw) > 4<<20 || raw[len(raw)-1] != '\n' {
		return runtimeProofFailure(proofStateLockRecordSyntax, ErrInventory)
	}
	found := 0
	var firstLine, firstOrdinal string
	sameText, sameOrdinal := true, true
	for line := range strings.SplitSeq(strings.TrimSuffix(string(raw), "\n"), "\n") {
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

func (p *runtimeStateLease) close() {
	if p == nil {
		return
	}
	if p.lock != nil {
		p.lock.Close()
		p.lock = nil
	}
	if p.root != nil {
		p.root.Close()
		p.root = nil
	}
}

func stateIdentity(root, lock *os.File) (runtimeStateIdentity, error) {
	var zero runtimeStateIdentity
	if root == nil || lock == nil {
		return zero, ErrConflict
	}
	if trustedStat(int(root.Fd()), true, 0700) != nil || trustedStat(int(lock.Fd()), false, 0600) != nil {
		return zero, ErrInventory
	}
	var a, b unix.Stat_t
	if e := unix.Fstat(int(root.Fd()), &a); e != nil {
		return zero, e
	}
	if e := unix.Fstat(int(lock.Fd()), &b); e != nil {
		return zero, e
	}
	if a.Uid != uint32(os.Geteuid()) || b.Size != 0 {
		return zero, ErrInventory
	}
	p := runtimeStateIdentity{uint64(a.Dev), a.Ino, uint64(b.Dev), b.Ino, b.Ctim.Sec, b.Ctim.Nsec}
	if !p.valid() {
		return zero, ErrInventory
	}
	return p, nil
}

// Open only: no creation, directory sync, lock removal, truncation or repair.
func (f *filesystem) openRuntimeState() (*runtimeStateLease, error) {
	dir, e := f.directory(stateDir)
	if e != nil {
		return nil, e
	}
	fd, e := unix.Openat(int(dir.Fd()), "controller.lock", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		dir.Close()
		return nil, e
	}
	p := &runtimeStateLease{root: dir, lock: os.NewFile(uintptr(fd), "runtime-original-controller-lock")}
	p.id, e = stateIdentity(p.root, p.lock)
	if e == nil {
		e = p.verify(f)
	}
	if e != nil {
		p.close()
		return nil, e
	}
	return p, nil
}

func (p *runtimeStateLease) verify(f *filesystem) error {
	if p == nil {
		return ErrConflict
	}
	id, e := stateIdentity(p.root, p.lock)
	if e != nil {
		return e
	}
	if id != p.id {
		return ErrInventory
	}
	dir, e := f.directory(stateDir)
	if e != nil {
		return e
	}
	defer dir.Close()
	var root, lock unix.Stat_t
	if e = unix.Fstat(int(dir.Fd()), &root); e != nil {
		return e
	}
	if e = unix.Fstatat(int(dir.Fd()), "controller.lock", &lock, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return e
	}
	if uint64(root.Dev) != id.RootDevice || root.Ino != id.RootInode || uint64(lock.Dev) != id.LockDevice || lock.Ino != id.LockInode || lock.Mode != unix.S_IFREG|0600 || lock.Nlink != 1 || lock.Uid != uint32(os.Geteuid()) || lock.Size != 0 || lock.Ctim.Sec != id.LockChangeSeconds || lock.Ctim.Nsec != id.LockChangeNanos {
		return ErrInventory
	}
	return nil
}

func (f *filesystem) runtimeStateMatches(id runtimeStateIdentity) error {
	p, e := f.openRuntimeState()
	if e != nil {
		return e
	}
	defer p.close()
	if p.id != id {
		return ErrConflict
	}
	return nil
}

// Original daemon lock semantics, not the installer's separate OFD lock.
// A foreign holder is a conflict, not permission to break/wait out a lock.
func acquireRuntimeState(p *runtimeStateLease) error {
	for n := 0; n < 4; n++ {
		e := unix.Flock(int(p.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if errors.Is(e, unix.EINTR) {
			continue
		}
		return e
	}
	return unix.EINTR
}

// Fresh kernel/manager observation even when a matching stop receipt exists.
// No stop job, process signal, backend constructor or resource deletion here.
func (s *runtimeScope) stoppedStateProof(ctx context.Context, base, request string, m systemManager, empty func(string) error) (runtimeStopIntent, error) {
	var p runtimeStopIntent
	if m.fs != s.fs || empty == nil {
		return p, ErrPolicy
	}
	e := s.fs.runtimeDrainLocked(ctx, func() error {
		_, _, e := s.fs.runtimeStopBase(ctx, base, request)
		if e != nil {
			return e
		}
		p, e = s.fs.readRuntimeStop()
		if e != nil {
			return e
		}
		drain, e := s.fs.runtimeDrainReadIntent()
		if e != nil {
			return e
		}
		if (p.Version != 2 && p.Version != 3 && p.Version != 4) || p.State == nil || p.Base != base || p.Request != request || p.Main != drain.Process || p.Drain != digest(encode(drain)) {
			return ErrConflict
		}
		if e = s.fs.stopInventory(&p); e != nil {
			return e
		}
		return s.fs.exact(runtimeStopRoot+"/stopped.json", encode(runtimeStopReceipt{Version: 1, Input: digest(encode(p))}), 0600)
	})
	if e != nil {
		return runtimeStopIntent{}, e
	}
	if e = m.enabledLinks(); e != nil {
		return runtimeStopIntent{}, e
	}
	for _, unit := range []string{IngressUnit, MainUnit} {
		o, e := m.observe(ctx, unit)
		if e != nil {
			return runtimeStopIntent{}, e
		}
		if !validManagedUnit(o, unit) || o.pid != 0 || o.active != "inactive" && o.active != "failed" {
			return runtimeStopIntent{}, ErrConflict
		}
		if e = empty(unit); e != nil {
			return runtimeStopIntent{}, e
		}
	}
	for _, id := range []*nodecontrol.ProcessIdentity{&p.Main, p.Ingress} {
		if id == nil {
			continue
		}
		watch, e := nodecontrol.NewProcessWatch(id.PID)
		if errors.Is(e, unix.ESRCH) {
			continue
		}
		if watch != nil {
			watch.Close()
		}
		if e != nil {
			return runtimeStopIntent{}, e
		}
		// Even an unrelated incarnation at the old numeric PID is not adopted.
		return runtimeStopIntent{}, ErrConflict
	}
	return p, nil
}

func (s *runtimeScope) ownStoppedState(ctx context.Context, base, request string, m systemManager) error {
	return s.ownStoppedStateWithProof(ctx, base, request, m, m.fs.unitExecutionEmpty)
}

// Private software-model seam; the production entry always uses real cgroup2.
func (s *runtimeScope) ownStoppedStateWithProof(ctx context.Context, base, request string, m systemManager, empty func(string) error) error {
	if !digestPattern.MatchString(base) || !requestPattern.MatchString(request) {
		return ErrPolicy
	}
	return s.run(ctx, func(f *filesystem) error {
		p, e := s.stoppedStateProof(ctx, base, request, m, empty)
		if e != nil {
			return e
		}
		if s.state != nil {
			if s.state.id != *p.State {
				return ErrConflict
			}
			return s.state.verify(f)
		}
		lease, e := f.openRuntimeState()
		if e != nil {
			return e
		}
		keep := false
		defer func() {
			if !keep {
				lease.close()
			}
		}()
		if lease.id != *p.State {
			return ErrConflict
		}
		if e = acquireRuntimeState(lease); e != nil {
			return e
		}
		if e = f.point("runtime-state-locked"); e != nil {
			return e
		}
		if e = lease.verify(f); e != nil {
			return e
		}
		if _, e = s.stoppedStateProof(ctx, base, request, m, empty); e != nil {
			return e
		}
		if e = lease.verify(f); e != nil {
			return e
		}
		s.state, keep = lease, true
		return nil
	})
}
