//go:build linux

package installtxn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	"github.com/123123213weqw/Xandbox/internal/gateway"
	"golang.org/x/sys/unix"
)

const fileSequenceScratchBytes = 32 * 1024

// This is invocation-private STORAGE, not a hash/content/validation cache or
// pool. Only the serial file loop below owns it. Each file gets a NEW hash and
// an unchanged full size+1 read. It never survives into the next proof stage,
// filesystem callback, operation, service invocation or daemon.
type fileSequenceScratch struct{ buffer []byte }

func (s *fileSequenceScratch) release() {
	// Best-effort in-process cleanup, not physical media/forensic erasure.
	clear(s.buffer)
	s.buffer = nil
}

func (s *fileSequenceScratch) hash(ctx context.Context, in *os.File, size int64) (string, error) {
	// Preserve the original seek-before-context/read/error precedence, including
	// closed/nonseekable files and negative/overflowing size+1 behavior.
	if _, e := in.Seek(0, 0); e != nil {
		return "", e
	}
	if s.buffer == nil {
		s.buffer = make([]byte, fileSequenceScratchBytes)
	}
	h := sha256.New()
	n, e := io.CopyBuffer(h, contextReader{ctx, io.LimitReader(in, size+1)}, s.buffer[:hashScratchSize(size)])
	if e != nil {
		return "", e
	}
	if n != size {
		return "", ErrInventory
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Keep the original fresh anchored open, type/owner/mode/link checks, complete
// checksum and Sync for EACH target. No FD, data, hash or result is adopted from
// an earlier target. The standalone filesystem.verify/hashFile stay unchanged.
func (f *filesystem) verifyFileWithScratch(ctx context.Context, v File, scratch *fileSequenceScratch) error {
	in, e := f.open(v.Path, unix.O_RDONLY, v.Mode)
	if e != nil {
		return e
	}
	defer in.Close()
	sum, e := scratch.hash(ctx, in, v.Bytes)
	if e != nil {
		return e
	}
	if sum != v.SHA256 {
		return ErrInventory
	}
	return in.Sync()
}

// The SOLE production caller is verifyTargetsAfterPolicy, AFTER the original
// file-list, root inventory and managed-policy override guards. This private
// loop is not a new validator, caller-selected transaction or execution right.
// Release/zero its one bounded allocation on success AND every early error,
// before generated-file/inventory proofs or another stage can begin.
func (f *filesystem) verifyFileSequence(ctx context.Context, files []File, override *File) error {
	var scratch fileSequenceScratch
	defer scratch.release()
	for _, v := range files {
		if override != nil && v.Path == gateway.ManagedPolicyPath {
			v = *override
		}
		if e := f.verifyFileWithScratch(ctx, v, &scratch); e != nil {
			return e
		}
	}
	return nil
}
