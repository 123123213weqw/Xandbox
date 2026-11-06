package firecracker

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
)

type assetPartialBoundaryFile struct {
	*os.File
	seen      bool
	priorSize int64
}

func (f *assetPartialBoundaryFile) Write(b []byte) (int, error) {
	offset, e := f.File.Seek(0, io.SeekCurrent)
	if e != nil {
		return 0, e
	}
	if offset == 16<<20 && len(b) == 128<<10 {
		info, e := f.File.Stat()
		if e != nil {
			return 0, e
		}
		f.seen = true
		f.priorSize = info.Size()
	}
	return f.File.Write(b)
}

// The frozen runtime observer also validates real project charge/ownership.
// This software regression proves only the original WRITE offset/size and
// pre-write logical prefix, not ext4 quota, persistence,18s timing or KVM.
func TestAssetCopyPreservesFrozenPartialWriteBoundary(t *testing.T) {
	input := make([]byte, (16<<20)+assetCopyBlockSize)
	input[0] = 1
	for _, writeback := range []bool{false, true} {
		file := &assetPartialBoundaryFile{File: assetCopyFile(t)}
		var dest assetCopyDestination = file
		if writeback {
			dest = &assetWritebackDestination{assetCopyDestination: file, submit: func(o, n int64) error { return nil }}
		}
		if e := copyAssetBytes(context.Background(), bytes.NewReader(input), dest, assetCopyDigest(input)); e != nil {
			t.Fatal(e)
		}
		assetCopyCheck(t, file.File, input)
		if !file.seen || file.priorSize != 16<<20 {
			t.Fatal("frozen partial write boundary absent", writeback, file.seen, file.priorSize)
		}
	}
}
