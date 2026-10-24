//go:build linux

package installtxn

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// operationLock spans file work AND manager/ACK reconciliation. Ordinary
// mutations share it; a future explicit ingress-maintenance transaction must
// hold it exclusively. Acquire it BEFORE any install flock, and never upgrade
// it while holding a flock. Read-only status and the cap0 startup gate do not
// acquire it, so starting ingress cannot deadlock its own verifier.
//
// This is an OFD byte-range lock on the ORIGINAL zero-byte .lock inode, not a
// new file, POSIX process lock, or replacement for the existing flock. Closing
// an unrelated descriptor must not release it. No create/truncate/fallback.
// Linux local-filesystem flock/fcntl independence is required; NFS/SMB differ:
// https://www.man7.org/linux/man-pages/man2/flock.2.html
func (f *filesystem) operationLock(ctx context.Context, exclusive bool) (func(), error) {
	in, e := f.acquireOperationLock(ctx, exclusive)
	if e != nil {
		return nil, e
	}
	return func() { _ = in.Close() }, nil
}

func (f *filesystem) acquireOperationLock(ctx context.Context, exclusive bool) (_ *os.File, err error) {
	in, e := f.open(Root+"/.lock", unix.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	defer func() {
		if err != nil {
			in.Close()
		}
	}()
	var fs unix.Statfs_t
	if e = unix.Fstatfs(int(in.Fd()), &fs); e != nil {
		return nil, e
	}
	// No remote-filesystem lock emulation. This list only defines the lock
	// primitive's local semantics; it is NOT runtime/storage qualification.
	switch fs.Type {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC:
	default:
		return nil, ErrPlatform
	}
	before, e := in.Stat()
	if e != nil {
		return nil, e
	}
	if before.Size() != 0 {
		return nil, ErrInventory
	}
	if e = f.point("operation-lock-opened"); e != nil {
		return nil, e
	}
	kind := int16(unix.F_RDLCK)
	if exclusive {
		kind = unix.F_WRLCK
	}
	lock := unix.Flock_t{Type: kind, Whence: int16(unix.SEEK_SET), Start: 0, Len: 1}
	for {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		e = unix.FcntlFlock(in.Fd(), unix.F_OFD_SETLK, &lock)
		if e == nil {
			break
		}
		if !errors.Is(e, unix.EAGAIN) && !errors.Is(e, unix.EACCES) && !errors.Is(e, unix.EINTR) {
			return nil, e // unsupported kernels fail closed, never POSIX fallback
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	if e = f.point("operation-lock-acquired"); e != nil {
		return nil, e
	}
	current, e := f.open(Root+"/.lock", unix.O_RDONLY, 0600)
	if e != nil {
		return nil, e
	}
	defer current.Close()
	after, e := current.Stat()
	if e != nil {
		return nil, e
	}
	if !os.SameFile(before, after) || after.Size() != 0 || trustedStat(int(in.Fd()), false, 0600) != nil {
		return nil, ErrInventory
	}
	return in, nil
}

// Initial installation may create only the original lock under its existing
// fresh-root rules. Drop that bootstrap flock before taking the operation lock;
// reacquire the ordinary EX file lock at the caller. This ordering lets every
// later operation (including a future exclusive maintenance caller) agree.
func (f *filesystem) initialOperationLock(ctx context.Context) (func(), error) {
	unlock, e := f.initialLock(ctx)
	if e != nil {
		return nil, e
	}
	unlock()
	return f.operationLock(ctx, false)
}
