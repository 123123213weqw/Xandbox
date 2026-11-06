package firecracker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
)

const assetCopyBlockSize = 128 << 10

type assetCopyDestination interface {
	io.Writer
	io.Seeker
	Stat() (os.FileInfo, error)
	Truncate(int64) error
}

// copyAssetBytes hashes and WRITES every source byte, including zeros. The
// original dense allocation/write boundaries remain available to fault tests;
// final logical equality alone is not a substitute for that storage contract.
// The caller must use O_CREATE|O_EXCL: empty-file checks do not prove ownership.
// Failed partial copies remain owned by the ordinary fail-closed GC path.
func copyAssetBytes(ctx context.Context, source io.Reader, dest assetCopyDestination, digest string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := dest.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != 0 {
		return errors.New("asset copy requires a new empty regular destination")
	}
	offset, err := dest.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if offset != 0 {
		return errors.New("asset copy requires destination offset zero")
	}
	h := sha256.New()
	buf := make([]byte, assetCopyBlockSize)
	var logical int64
	emptyReads := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := source.Read(buf)
		if n < 0 || n > len(buf) {
			return errors.New("invalid asset read count")
		}
		if n > 0 {
			emptyReads = 0
			if logical > math.MaxInt64-int64(n) {
				return errors.New("asset logical size overflow")
			}
			logical += int64(n)
			wrote, err := dest.Write(buf[:n])
			if err != nil {
				return err
			}
			if wrote != n {
				return io.ErrShortWrite
			}
			_, _ = h.Write(buf[:n]) // SHA256's Write cannot fail.
		} else if readErr == nil {
			emptyReads++
		}
		// Preserve the original dense-copy IO error precedence: process bytes
		// returned with an error, then report that read error. Cancellation
		// cannot hide EIO/ENOSPC/EDQUOT/short writes, even with n>0 + EOF.
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if readErr == io.EOF {
			break
		}
		if emptyReads >= 100 {
			return io.ErrNoProgress
		}
	}
	if hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("staged image digest mismatch")
	}
	// Explicitly finalize the verified logical EOF. Any destination writeback
	// wrapper may submit a final partial range here, but not assert durability.
	if err := dest.Truncate(logical); err != nil {
		return err
	}
	return ctx.Err()
}
