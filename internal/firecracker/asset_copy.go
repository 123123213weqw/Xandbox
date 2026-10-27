package firecracker

import (
	"bytes"
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

// copyAssetBytes hashes every source byte, but represents all-zero buffers as
// holes in a NEW, exclusive private file. It never shares source extents or
// changes logical image bytes/size. The caller must use O_CREATE|O_EXCL: the
// empty-file checks alone are not a substitute for exclusive ownership.
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
			// Count handles short buffers too; a nonzero byte is never elided.
			if bytes.Count(buf[:n], []byte{0}) == n {
				position, err := dest.Seek(int64(n), io.SeekCurrent)
				if err != nil {
					return err
				}
				if position != logical {
					return errors.New("unexpected asset copy seek offset")
				}
			} else {
				wrote, err := dest.Write(buf[:n])
				if err != nil {
					return err
				}
				if wrote != n {
					return io.ErrShortWrite
				}
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
	// Seek alone does not establish EOF for trailing/wholly-zero images.
	// Only verified, uncanceled bytes reach this finalization syscall.
	if err := dest.Truncate(logical); err != nil {
		return err
	}
	return ctx.Err()
}
