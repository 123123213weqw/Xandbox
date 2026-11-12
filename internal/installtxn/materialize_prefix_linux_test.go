//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

// Exact independent 63c2ab5 materialize body; ONLY the method name changed.
// Do not route its prefix allocation/loop through the candidate selector.
func (f *filesystem) originalMaterialize63c2(ctx context.Context, v target) error {
	if e := f.verify(ctx, v.file); e == nil {
		return nil
	} else if !errors.Is(e, unix.ENOENT) {
		partial, err := f.open(v.file.Path, unix.O_RDONLY, 0600)
		if err != nil {
			return err
		}
		partial.Close()
	}
	var input io.ReadSeeker = bytes.NewReader(v.data)
	if v.source != nil {
		input = v.source
	}
	if _, e := input.Seek(0, 0); e != nil {
		return e
	}
	out, e := f.open(v.file.Path, unix.O_RDWR|unix.O_CREAT, 0600)
	if e != nil {
		return e
	}
	defer out.Close()
	st, e := out.Stat()
	if e != nil || st.Size() > v.file.Bytes {
		return ErrInventory
	}
	left := make([]byte, 65536)
	right := make([]byte, 65536)
	remain := st.Size()
	for remain > 0 {
		if e = ctx.Err(); e != nil {
			return e
		}
		size := int64(len(left))
		if remain < size {
			size = remain
		}
		if _, e = io.ReadFull(out, left[:size]); e != nil {
			return e
		}
		if _, e = io.ReadFull(input, right[:size]); e != nil {
			return e
		}
		if !bytes.Equal(left[:size], right[:size]) {
			return ErrInventory
		}
		remain -= size
	}
	if _, e = io.Copy(out, contextReader{ctx, io.LimitReader(input, v.file.Bytes-st.Size()+1)}); e != nil {
		return e
	}
	stage := "file-" + filepath.Base(v.file.Path)
	if e = f.point(stage + "-written"); e != nil {
		return e
	}
	sum, e := hashFile(ctx, out, v.file.Bytes)
	if e != nil {
		return e
	}
	if sum != v.file.SHA256 {
		return ErrInventory
	}
	if e = out.Sync(); e != nil {
		return e
	}
	if e = f.point(stage + "-synced"); e != nil {
		return e
	}
	if e = out.Chmod(os.FileMode(v.file.Mode)); e != nil {
		return e
	}
	if e = out.Sync(); e != nil {
		return e
	}
	if e = f.syncDir(filepath.Dir(v.file.Path)); e != nil {
		return e
	}
	return f.point(stage + "-sealed")
}

func TestMaterializePrefixScratchBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix int64
		want   int
	}{
		{"min-int", math.MinInt64, 0}, {"negative", -1, 0}, {"zero", 0, 0},
		{"one", 1, 1}, {"two", 2, 2}, {"small", 255, 255},
		{"page-minus", 4095, 4095}, {"page", 4096, 4096},
		{"half-minus", 32767, 32767}, {"half", 32768, 32768},
		{"cap-minus", 65535, 65535}, {"cap", 65536, 65536},
		{"cap-plus", 65537, 65536}, {"two-cap", 131072, 65536},
		{"max-minus", math.MaxInt64 - 1, 65536}, {"max", math.MaxInt64, 65536},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := materializePrefixScratchSize(tc.prefix); got != tc.want || got < 0 || got > 65536 {
				t.Fatal("bounded exact original-prefix scratch", got, tc.want)
			}
		})
	}
}

type materializePrefixCase struct {
	name                                               string
	size, prefix                                       int
	sealed, mismatch, wrongHash, shortInput, longInput bool
	point                                              string
	cancelAt, closedSource                             bool
}
type materializePrefixFile struct {
	Mode     uint32
	UID, GID uint32
	Links    uint64
	Data     string
}
type materializePrefixObservation struct {
	Err             error
	Stages          []string
	Files           map[string]materializePrefixFile
	SourcePosition  int64
	SourceSeekError error
	SourceStatError error
	SourceFlags     int
	RootPosition    int64
}

var materializePrefixCut = errors.New("materialize-prefix-test-cut")

// Only owned regular-file shadows; no installer/daemon/systemd/runtime roots,
// subprocess, real quota, VM or original-node operation is constructed here.
func observeMaterializePrefix(t *testing.T, tc materializePrefixCase, source, original bool) materializePrefixObservation {
	t.Helper()
	root := t.TempDir()
	if e := os.MkdirAll(root+"/a/b", 0700); e != nil {
		t.Fatal(e)
	}
	fd, e := os.Open(root)
	if e != nil {
		t.Fatal(e)
	}
	defer fd.Close()
	f := &filesystem{root: fd}
	data := make([]byte, tc.size+1)
	for i := range data {
		data[i] = byte(i % 251)
	}
	v := target{file: File{Path: "/a/b/target", Bytes: int64(tc.size), Mode: 0444, SHA256: digest(data[:tc.size])}, data: data[:tc.size]}
	if tc.wrongHash {
		v.file.SHA256 = digest([]byte("deliberately-wrong-pin"))
	}
	if tc.prefix >= 0 {
		prefix := append([]byte(nil), data[:tc.prefix]...)
		if tc.mismatch {
			prefix[0] ^= 1
		}
		mode := os.FileMode(0600)
		if tc.sealed {
			mode = 0444
		}
		if e = os.WriteFile(root+v.file.Path, prefix, mode); e != nil {
			t.Fatal(e)
		}
	}
	input := data[:tc.size]
	if tc.shortInput {
		input = data[:tc.size-1]
	}
	if tc.longInput {
		input = data
	}
	v.data = input
	var before unix.Stat_t
	if source {
		if e = os.WriteFile(root+"/a/b/source", input, 0600); e != nil {
			t.Fatal(e)
		}
		v.source, e = f.open("/a/b/source", unix.O_RDONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		defer v.source.Close()
		if _, e = v.source.Seek(7, io.SeekStart); e != nil {
			t.Fatal(e)
		}
		if e = unix.Fstat(int(v.source.Fd()), &before); e != nil {
			t.Fatal(e)
		}
		if tc.closedSource {
			if e = v.source.Close(); e != nil {
				t.Fatal(e)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var got materializePrefixObservation
	f.hook = func(stage string) error {
		got.Stages = append(got.Stages, stage)
		if stage == tc.point {
			if tc.cancelAt {
				cancel()
			} else {
				return materializePrefixCut
			}
		}
		return nil
	}
	if tc.point == "before" {
		cancel()
	}
	if original {
		got.Err = f.originalMaterialize63c2(ctx, v)
	} else {
		got.Err = f.materialize(ctx, v)
	}
	if source {
		got.SourcePosition, got.SourceSeekError = v.source.Seek(0, io.SeekCurrent)
		var after unix.Stat_t
		got.SourceStatError = unix.Fstat(int(v.source.Fd()), &after)
		if !tc.closedSource {
			if got.SourceStatError != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid || before.Gid != after.Gid || before.Nlink != after.Nlink || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
				t.Fatal("source FD/bytes metadata changed")
			}
			got.SourceFlags, e = unix.FcntlInt(v.source.Fd(), unix.F_GETFD, 0)
			if e != nil || got.SourceFlags&unix.FD_CLOEXEC == 0 {
				t.Fatal("source descriptor flags", e)
			}
		}
	}
	got.RootPosition, e = fd.Seek(0, io.SeekCurrent)
	if e != nil || got.RootPosition != 0 {
		t.Fatal("original root description offset changed", e)
	}
	got.Files = map[string]materializePrefixFile{}
	if e = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		var st unix.Stat_t
		if err = unix.Lstat(path, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			t.Fatal("nonregular owned test file")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		got.Files[name] = materializePrefixFile{Mode: st.Mode, UID: st.Uid, GID: st.Gid, Links: uint64(st.Nlink), Data: string(raw)}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	return got
}
func compareMaterializePrefix(t *testing.T, tc materializePrefixCase, source bool, positive bool) {
	t.Helper()
	want := observeMaterializePrefix(t, tc, source, true)
	got := observeMaterializePrefix(t, tc, source, false)
	if !reflect.DeepEqual(want, got) {
		t.Fatal("independent original errors/stages/bytes/modes/FDs differ", want.Err, got.Err)
	}
	if positive && got.Err != nil {
		t.Fatal("positive original fixture rejected", got.Err)
	}
	if tc.mismatch || tc.wrongHash || tc.shortInput || tc.longInput || tc.prefix > tc.size {
		if !errors.Is(got.Err, ErrInventory) {
			t.Fatal("original invalid file admitted", got.Err)
		}
	}
	if tc.closedSource && !errors.Is(got.Err, os.ErrClosed) {
		t.Fatal("closed input admitted", got.Err)
	}
	if tc.point != "" && tc.point != "before" && !tc.cancelAt && !errors.Is(got.Err, materializePrefixCut) {
		t.Fatal("original cut not reached", tc.point, got.Err)
	}
}
func TestMaterializePrefixIndependentOriginalFiles(t *testing.T) {
	for _, tc := range []materializePrefixCase{
		{name: "new-empty", size: 0, prefix: -1},
		{name: "new-small", size: 257, prefix: -1},
		{name: "empty-prefix", size: 257, prefix: 0},
		{name: "short-prefix", size: 257, prefix: 1},
		{name: "cap-minus-prefix", size: 65537, prefix: 65535},
		{name: "cap-prefix", size: 65537, prefix: 65536},
		{name: "cap-plus-prefix", size: 65538, prefix: 65537},
		{name: "full-unsealed", size: 257, prefix: 257},
		{name: "full-sealed", size: 257, prefix: 257, sealed: true},
		{name: "prefix-mismatch", size: 257, prefix: 1, mismatch: true},
		{name: "oversized", size: 257, prefix: 258},
		{name: "wrong-hash", size: 257, prefix: -1, wrongHash: true},
		{name: "short-input", size: 257, prefix: 0, shortInput: true},
		{name: "long-input", size: 257, prefix: 0, longInput: true},
	} {
		for _, source := range []bool{false, true} {
			name := tc.name + "/memory"
			if source {
				name = tc.name + "/original-source-fd"
			}
			t.Run(name, func(t *testing.T) {
				compareMaterializePrefix(t, tc, source, !tc.mismatch && !tc.wrongHash && !tc.shortInput && !tc.longInput && tc.prefix <= tc.size)
			})
		}
	}
}
func TestMaterializePrefixIndependentOriginalCutsAndCancellation(t *testing.T) {
	for _, tc := range []materializePrefixCase{
		{name: "written", point: "file-target-written"},
		{name: "synced", point: "file-target-synced"},
		{name: "sealed", point: "file-target-sealed"},
		{name: "cancel-before", point: "before", cancelAt: true},
		{name: "cancel-written", point: "file-target-written", cancelAt: true},
		{name: "cancel-synced", point: "file-target-synced", cancelAt: true},
		{name: "cancel-sealed", point: "file-target-sealed", cancelAt: true},
	} {
		tc.size, tc.prefix = 257, 0
		for _, source := range []bool{false, true} {
			name := tc.name + "/memory"
			if source {
				name = tc.name + "/original-source-fd"
			}
			t.Run(name, func(t *testing.T) { compareMaterializePrefix(t, tc, source, false) })
		}
	}
	t.Run("closed-original-source-fd", func(t *testing.T) {
		compareMaterializePrefix(t, materializePrefixCase{name: "closed-source", size: 257, prefix: 0, closedSource: true}, true, false)
	})
}
