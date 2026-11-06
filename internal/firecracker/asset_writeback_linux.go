//go:build linux

package firecracker

import (
	"errors"
	"math"
	"os"

	"golang.org/x/sys/unix"
)

// Capability selection uses this new owned file's filesystem, not an input,
// workload, tenant, fixture, path spelling or operator performance override.
// Other filesystems keep the plain dense writer; failed inspection is fatal.
func assetCopySink(file *os.File) (assetCopyDestination, error) {
	if file == nil {
		return nil, errors.New("owned asset file required")
	}
	var info unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &info); err != nil {
		return nil, err
	}
	if info.Type != unix.EXT4_SUPER_MAGIC {
		return file, nil
	}
	return &assetWritebackDestination{assetCopyDestination: file, submit: func(offset, length int64) error {
		return startAssetWriteback(file, offset, length)
	}}, nil
}
func startAssetWriteback(file *os.File, offset, length int64) error {
	if file == nil || offset < 0 || length <= 0 || offset > math.MaxInt64-length {
		return errors.New("invalid bounded asset writeback range")
	}
	// WRITE starts writeback only. No WAIT flags and no zero-length whole-file
	// selector. It may still block in the kernel and is NOT an fsync substitute.
	return unix.SyncFileRange(int(file.Fd()), offset, length, unix.SYNC_FILE_RANGE_WRITE)
}
