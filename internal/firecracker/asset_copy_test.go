package firecracker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"testing/iotest"
)

func assetCopyDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func assetCopyFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(t.TempDir(), "private"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func assetCopyCheck(t *testing.T, f *os.File, want []byte) {
	t.Helper()
	info, err := f.Stat()
	if err != nil || info.Size() != int64(len(want)) {
		t.Fatalf("wrong logical EOF: %v, %v", info, err)
	}
	got := make([]byte, len(want)+1)
	n, err := f.ReadAt(got, 0)
	if err != io.EOF || n != len(want) || !bytes.Equal(got[:n], want) || assetCopyDigest(got[:n]) != assetCopyDigest(want) {
		t.Fatalf("logical bytes/digest changed: %d, %v", n, err)
	}
}

// No assumptions about physical allocation on the test filesystem. Logical
// equality, distinct inodes, and write isolation are the portable contract.
func TestAssetCopyLogicalBytesEOFAndIndependentFiles(t *testing.T) {
	rng := rand.New(rand.NewSource(52183))
	for _, size := range []int{0, 1, 17, assetCopyBlockSize - 1, assetCopyBlockSize, assetCopyBlockSize + 1, 3*assetCopyBlockSize + 19} {
		for mode := 0; mode < 3; mode++ {
			input := make([]byte, size)
			if mode == 1 {
				_, _ = rng.Read(input)
			} else if mode == 2 && size > 0 {
				input[size/2] = 1
			}
			a, b := assetCopyFile(t), assetCopyFile(t)
			for _, f := range []*os.File{a, b} {
				if err := copyAssetBytes(context.Background(), bytes.NewReader(input), f, assetCopyDigest(input)); err != nil {
					t.Fatal(size, mode, err)
				}
				assetCopyCheck(t, f, input)
			}
			sa, _ := a.Stat()
			sb, _ := b.Stat()
			if os.SameFile(sa, sb) {
				t.Fatal("private copies share an inode")
			}
			if size > 0 {
				if _, err := a.WriteAt([]byte{input[0] ^ 0xff}, 0); err != nil {
					t.Fatal(err)
				}
				assetCopyCheck(t, b, input)
			}
		}
	}
}

type assetCopyFaults struct {
	*os.File
	statErr, initialSeekErr, holeSeekErr, writeErr, truncateErr error
	badOffset, short, truncated                                 bool
	writes, written, holes, skipped                             int
	truncateHook                                                func()
}

func (f *assetCopyFaults) Stat() (os.FileInfo, error) {
	if f.statErr != nil {
		return nil, f.statErr
	}
	return f.File.Stat()
}

func (f *assetCopyFaults) Seek(offset int64, whence int) (int64, error) {
	if offset == 0 && f.initialSeekErr != nil {
		return 0, f.initialSeekErr
	}
	if offset != 0 {
		f.holes++
		f.skipped += int(offset)
		if f.holeSeekErr != nil {
			return 0, f.holeSeekErr
		}
		if f.badOffset {
			return 0, nil
		}
	}
	return f.File.Seek(offset, whence)
}

func (f *assetCopyFaults) Write(b []byte) (int, error) {
	f.writes++
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.short {
		return len(b) - 1, nil
	}
	n, err := f.File.Write(b)
	f.written += n
	return n, err
}

func (f *assetCopyFaults) Truncate(n int64) error {
	f.truncated = true
	if f.truncateHook != nil {
		f.truncateHook()
	}
	if f.truncateErr != nil {
		return f.truncateErr
	}
	return f.File.Truncate(n)
}

func TestAssetCopyWritesDenseZerosWithoutSeekElision(t *testing.T) {
	input := make([]byte, 16*assetCopyBlockSize+7)
	for _, start := range []int{0, 8 * assetCopyBlockSize} {
		for i := start; i < start+assetCopyBlockSize; i++ {
			input[i] = byte(i%251 + 1)
		}
	}
	f := &assetCopyFaults{File: assetCopyFile(t)}
	if err := copyAssetBytes(context.Background(), bytes.NewReader(input), f, assetCopyDigest(input)); err != nil {
		t.Fatal(err)
	}
	assetCopyCheck(t, f.File, input)
	if f.writes != 17 || f.written != len(input) || f.holes != 0 || f.skipped != 0 || !f.truncated {
		t.Fatalf("wrong write work: %+v", f)
	}
	// This is write-call/byte evidence, not a latency, quota, or KVM benchmark.
}

func TestAssetCopyHashesZeroBuffersAndShortReads(t *testing.T) {
	input := make([]byte, 257)
	input[63], input[128], input[256] = 1, 2, 3
	readers := []io.Reader{
		iotest.OneByteReader(bytes.NewReader(input)),
		iotest.HalfReader(bytes.NewReader(input)),
		iotest.DataErrReader(bytes.NewReader(input)),
	}
	for _, reader := range readers {
		f := assetCopyFile(t)
		if err := copyAssetBytes(context.Background(), reader, f, assetCopyDigest(input)); err != nil {
			t.Fatal(err)
		}
		assetCopyCheck(t, f, input)
	}
	for _, input := range [][]byte{make([]byte, 2*assetCopyBlockSize+3), append([]byte{1}, make([]byte, assetCopyBlockSize)...)} {
		f := &assetCopyFaults{File: assetCopyFile(t)}
		if err := copyAssetBytes(context.Background(), bytes.NewReader(input), f, assetCopyDigest([]byte("wrong"))); err == nil || err.Error() != "staged image digest mismatch" || f.truncated {
			t.Fatal("unverified zero/tail bytes reached successful EOF", err)
		}
	}
}

type assetCopyReadResult struct {
	data   []byte
	err    error
	hook   func()
	reads  int
	noData bool
}

func (r *assetCopyReadResult) Read(b []byte) (int, error) {
	r.reads++
	if r.hook != nil {
		r.hook()
	}
	if r.noData {
		return 0, r.err
	}
	return copy(b, r.data), r.err
}

func TestAssetCopyRejectsReusedAdvancedOrNonregularDestination(t *testing.T) {
	for _, mode := range []string{"nonempty", "advanced", "directory", "stat-error", "initial-seek-error"} {
		t.Run(mode, func(t *testing.T) {
			f := &assetCopyFaults{File: assetCopyFile(t)}
			switch mode {
			case "nonempty":
				if _, err := f.File.Write([]byte("prior-private-data")); err != nil {
					t.Fatal(err)
				}
				if _, err := f.File.Seek(0, 0); err != nil {
					t.Fatal(err)
				}
			case "advanced":
				if _, err := f.File.Seek(1, 0); err != nil {
					t.Fatal(err)
				}
			case "directory":
				d, err := os.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				defer d.Close()
				f.File = d
			case "stat-error":
				f.statErr = syscall.EIO
			case "initial-seek-error":
				f.initialSeekErr = syscall.EIO
			}
			src := &assetCopyReadResult{err: io.EOF}
			if err := copyAssetBytes(context.Background(), src, f, assetCopyDigest(nil)); err == nil || src.reads != 0 || f.writes != 0 || f.holes != 0 || f.truncated {
				t.Fatal("unsafe destination reached source/copy/finalize", err)
			}
			if mode == "nonempty" {
				assetCopyCheck(t, f.File, []byte("prior-private-data"))
			}
		})
	}
}

func TestAssetCopyIOFailuresNeverBecomeVerifiedEOF(t *testing.T) {
	for _, mode := range []string{"write-eio", "write-enospc", "write-edquot", "short-write", "zero-write-eio", "zero-read-data-eio", "truncate-eio", "truncate-enospc", "truncate-edquot", "read-eio", "read-data-eio", "no-progress"} {
		t.Run(mode, func(t *testing.T) {
			input := []byte{1, 2, 3}
			f := &assetCopyFaults{File: assetCopyFile(t)}
			var reader io.Reader = bytes.NewReader(input)
			var want error
			switch mode {
			case "write-eio":
				f.writeErr, want = syscall.EIO, syscall.EIO
			case "write-enospc":
				f.writeErr, want = syscall.ENOSPC, syscall.ENOSPC
			case "write-edquot":
				f.writeErr, want = syscall.EDQUOT, syscall.EDQUOT
			case "short-write":
				f.short, want = true, io.ErrShortWrite
			case "zero-write-eio":
				input = make([]byte, 3)
				reader = bytes.NewReader(input)
				f.writeErr, want = syscall.EIO, syscall.EIO
			case "zero-read-data-eio":
				input = make([]byte, 3)
				reader, want = &assetCopyReadResult{data: input, err: syscall.EIO}, syscall.EIO
			case "truncate-eio":
				f.truncateErr, want = syscall.EIO, syscall.EIO
			case "truncate-enospc":
				f.truncateErr, want = syscall.ENOSPC, syscall.ENOSPC
			case "truncate-edquot":
				f.truncateErr, want = syscall.EDQUOT, syscall.EDQUOT
			case "read-eio":
				reader, want = &assetCopyReadResult{err: syscall.EIO}, syscall.EIO
			case "read-data-eio":
				reader, want = &assetCopyReadResult{data: input, err: syscall.EIO}, syscall.EIO
			case "no-progress":
				reader, want = &assetCopyReadResult{noData: true}, io.ErrNoProgress
			}
			err := copyAssetBytes(context.Background(), reader, f, assetCopyDigest(input))
			if err == nil || (want != nil && !errors.Is(err, want)) {
				t.Fatal("original IO failure hidden", err, want)
			}
			if f.truncated != (f.truncateErr != nil) {
				t.Fatal("invalid data reached final EOF")
			}
			if mode == "read-data-eio" && f.written != len(input) {
				t.Fatal("bytes returned with read error not processed")
			}
			if mode == "no-progress" && reader.(*assetCopyReadResult).reads != 100 {
				t.Fatal("unbounded no-progress reader")
			}
		})
	}
}

func TestAssetCopyCancellationCannotHideIOErrorsOrSucceedAtEOF(t *testing.T) {
	for _, mode := range []string{"pre-cancel", "data-eof", "zero-eof", "empty-eof", "data-eio", "empty-eio", "data-eio-write-enospc", "data-eof-short-write", "zero-eof-write-eio", "truncate", "truncate-error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			input := []byte{1, 2, 3}
			f := &assetCopyFaults{File: assetCopyFile(t)}
			src := &assetCopyReadResult{data: input, err: io.EOF, hook: cancel}
			var want error = context.Canceled
			switch mode {
			case "pre-cancel":
				cancel()
			case "zero-eof":
				input = make([]byte, 3)
				src.data = input
			case "empty-eof":
				input, src.data = nil, nil
			case "data-eio":
				src.err, want = syscall.EIO, syscall.EIO
			case "empty-eio":
				src.data, src.err, want = nil, syscall.EIO, syscall.EIO
			case "data-eio-write-enospc":
				src.err, f.writeErr, want = syscall.EIO, syscall.ENOSPC, syscall.ENOSPC
			case "data-eof-short-write":
				f.short, want = true, io.ErrShortWrite
			case "zero-eof-write-eio":
				input = make([]byte, 3)
				src.data, f.writeErr, want = input, syscall.EIO, syscall.EIO
			case "truncate":
				src.hook, f.truncateHook = nil, cancel
			case "truncate-error":
				src.hook, f.truncateHook, f.truncateErr, want = nil, cancel, syscall.ENOSPC, syscall.ENOSPC
			}
			err := copyAssetBytes(ctx, src, f, assetCopyDigest(input))
			if !errors.Is(err, want) {
				t.Fatal("cancellation/IO precedence changed", err, want)
			}
			if f.truncated != (mode == "truncate" || mode == "truncate-error") {
				t.Fatal("canceled or invalid data reached verified EOF")
			}
			if mode == "pre-cancel" && src.reads != 0 {
				t.Fatal("pre-canceled copy consumed source")
			}
		})
	}
}

func TestAssetCopyConcurrentCopiesOwnTheirBuffersAndInodes(t *testing.T) {
	input := make([]byte, assetCopyBlockSize+17)
	input[9], input[len(input)-1] = 71, 52
	digest := assetCopyDigest(input)
	files := make([]*os.File, 8)
	for i := range files {
		files[i] = assetCopyFile(t)
	}
	errs := make([]error, len(files))
	var wg sync.WaitGroup
	for i := range files {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = copyAssetBytes(context.Background(), bytes.NewReader(input), files[i], digest)
		}(i)
	}
	wg.Wait()
	for i, f := range files {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		assetCopyCheck(t, f, input)
		for j := 0; j < i; j++ {
			a, _ := f.Stat()
			b, _ := files[j].Stat()
			if os.SameFile(a, b) {
				t.Fatal("concurrent copies share an inode")
			}
		}
	}
}

func TestAssetCopyProductionWiringUsesExclusiveVerifiedCopy(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "driver_linux.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, declaration := range file.Decls {
		if f, ok := declaration.(*ast.FuncDecl); ok && f.Name.Name == "copyAsset" {
			body = f.Body
		}
	}
	if body == nil {
		t.Fatal("ordinary copyAsset absent")
	}
	calls, sinkCalls, exclusive := 0, 0, false
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if f, ok := call.Fun.(*ast.Ident); ok && f.Name == "copyAssetBytes" {
			calls++
			if len(call.Args) != 4 {
				t.Fatal("ordinary helper inputs changed")
			}
			for i, want := range []string{"ctx", "source", "copyDest"} {
				arg, ok := call.Args[i].(*ast.Ident)
				if !ok || arg.Name != want {
					t.Fatal("ordinary helper input disconnected")
				}
			}
			arg, ok := call.Args[3].(*ast.SelectorExpr)
			if !ok || arg.Sel.Name != "SHA256" {
				t.Fatal("trusted digest disconnected")
			}
			owner, ok := arg.X.(*ast.Ident)
			if !ok || owner.Name != "asset" {
				t.Fatal("trusted digest source disconnected")
			}
		}
		if f, ok := call.Fun.(*ast.Ident); ok && f.Name == "assetCopySink" {
			sinkCalls++
			if len(call.Args) != 1 {
				t.Fatal("owned sink input changed")
			}
			arg, ok := call.Args[0].(*ast.Ident)
			if !ok || arg.Name != "dest" {
				t.Fatal("writeback sink is not bound to the owned descriptor")
			}
		}
		if f, ok := call.Fun.(*ast.SelectorExpr); ok && f.Sel.Name == "OpenFile" && len(call.Args) == 3 {
			flags := make(map[string]bool)
			ast.Inspect(call.Args[1], func(n ast.Node) bool {
				if flag, ok := n.(*ast.SelectorExpr); ok {
					flags[flag.Sel.Name] = true
				}
				return true
			})
			exclusive = flags["O_WRONLY"] && flags["O_CREATE"] && flags["O_EXCL"]
		}
		return true
	})
	if calls != 1 || sinkCalls != 1 || !exclusive {
		t.Fatal("ordinary copy does not use exclusive verified dense writeback", calls, sinkCalls, exclusive)
	}
}
