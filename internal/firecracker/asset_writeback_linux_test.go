//go:build linux

package firecracker

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAssetWritebackLinuxFactoryUsesOwnedFilesystemFD(t *testing.T) {
	if _, err := assetCopySink(nil); err == nil {
		t.Fatal("nil descriptor accepted")
	}
	file := assetCopyFile(t)
	var fs unix.Statfs_t
	if e := unix.Fstatfs(int(file.Fd()), &fs); e != nil {
		t.Fatal(e)
	}
	sink, e := assetCopySink(file)
	if e != nil {
		t.Fatal(e)
	}
	_, wrapped := sink.(*assetWritebackDestination)
	if wrapped != (fs.Type == unix.EXT4_SUPER_MAGIC) {
		t.Fatal("filesystem capability selection changed")
	}
	if !wrapped && sink != file {
		t.Fatal("plain dense fallback is not the same owned file")
	}
	if e := file.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := assetCopySink(file); e == nil {
		t.Fatal("failed filesystem inspection became success")
	}
}

// Executes the real syscall on a private regular file, but does not claim
// ext4/project-quota/cold durability or KVM acceptance on an arbitrary TMPDIR.
func TestAssetWritebackLinuxRealSyscallAndClosedFD(t *testing.T) {
	input := make([]byte, assetWritebackWindow+17)
	input[7] = 9
	file := assetCopyFile(t)
	sink := &assetWritebackDestination{assetCopyDestination: file, submit: func(o, n int64) error { return startAssetWriteback(file, o, n) }}
	if e := copyAssetBytes(context.Background(), bytes.NewReader(input), sink, assetCopyDigest(input)); e != nil {
		t.Fatal(e)
	}
	assetCopyCheck(t, file, input)
	if sink.submitted != int64(len(input)) {
		t.Fatal("missing kernel range request")
	}
	if e := file.Close(); e != nil {
		t.Fatal(e)
	}
	if e := startAssetWriteback(file, 0, 1); !errors.Is(e, unix.EBADF) {
		t.Fatal("closed descriptor accepted", e)
	}
	for _, r := range [][2]int64{{-1, 1}, {0, 0}, {0, -1}, {math.MaxInt64, 1}} {
		if e := startAssetWriteback(file, r[0], r[1]); e == nil || e.Error() != "invalid bounded asset writeback range" {
			t.Fatal("invalid range reached the closed descriptor syscall", e)
		}
	}
	if e := startAssetWriteback((*os.File)(nil), 0, 1); e == nil {
		t.Fatal("nil writeback descriptor accepted")
	}
}
