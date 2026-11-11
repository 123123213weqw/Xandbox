//go:build linux

package installtxn

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"testing"
)

// Exact pinned8d59 hash algorithm. Do not route through the candidate buffer
// selector or CopyBuffer. The unchanged contextReader is source-bound separately.
func originalHashFile8d59(ctx context.Context, in *os.File, size int64) (string, error) {
	if _, e := in.Seek(0, 0); e != nil {
		return "", e
	}
	h := sha256.New()
	n, e := io.Copy(h, contextReader{ctx, io.LimitReader(in, size+1)})
	if e != nil {
		return "", e
	}
	if n != size {
		return "", ErrInventory
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
func scratchData(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}
func sameScratchError(a, b error) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Error() == b.Error() && errors.Is(a, ErrInventory) == errors.Is(b, ErrInventory) && errors.Is(a, context.Canceled) == errors.Is(b, context.Canceled) && errors.Is(a, context.DeadlineExceeded) == errors.Is(b, context.DeadlineExceeded)
}

func TestRuntimeFileHashScratchAllocationBoundEdges(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int64
		want int
	}{
		{"min-int", math.MinInt64, 32768}, {"negative-two", -2, 32768}, {"negative-one", -1, 32768}, {"zero", 0, 1}, {"one", 1, 2}, {"thirty-one", 31, 32}, {"thirty-two", 32, 33}, {"tiny", 255, 256}, {"page-minus-one", 4095, 4096}, {"page", 4096, 4097}, {"half-minus-one", 16383, 16384}, {"cap-minus-two", 32766, 32767}, {"cap-minus-one", 32767, 32768}, {"cap", 32768, 32768}, {"cap-plus-one", 32769, 32768}, {"two-cap", 65536, 32768}, {"max-minus-one", math.MaxInt64 - 1, 32768}, {"max-int", math.MaxInt64, 32768},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := hashScratchSize(tc.size)
			if n != tc.want || n < 1 || n > 32768 {
				t.Fatal("nonzero bounded scratch contract", tc, n)
			}
		})
	}
}

func compareScratchFile(t *testing.T, size int64, actual int) {
	t.Helper()
	path := t.TempDir() + "/owned.bin"
	data := scratchData(actual)
	if e := os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = f.Seek(3, 0); e != nil {
		t.Fatal(e)
	}
	want, old := originalHashFile8d59(context.Background(), f, size)
	oldPos, e := f.Seek(0, 1)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Seek(7, 0); e != nil {
		t.Fatal(e)
	}
	got, err := hashFile(context.Background(), f, size)
	pos, e := f.Seek(0, 1)
	if e != nil {
		t.Fatal(e)
	}
	if got != want || !sameScratchError(old, err) || pos != oldPos {
		t.Fatal("SHA/error/seek/consumed-size differs from original", size, actual, oldPos, pos, want, got, old, err)
	}
	if size >= 0 && size == int64(actual) {
		h := sha256.Sum256(data)
		if err != nil || got != fmt.Sprintf("%x", h) {
			t.Fatal("exact file SHA control failed", size, err)
		}
	} else if !errors.Is(err, ErrInventory) || got != "" {
		t.Fatal("short/extra/negative/overflow did not retain original refusal", size, actual, got, err)
	}
}
func TestRuntimeFileHashScratchRealFilesKeepFullFreshHashAndSizePlusOne(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
	}{{"zero", 0}, {"one", 1}, {"seven", 7}, {"tiny", 255}, {"page-minus-one", 4095}, {"page", 4096}, {"cap-minus-one", 32767}, {"cap", 32768}, {"cap-plus-one", 32769}, {"two-cap-minus-one", 65535}, {"two-cap", 65536}, {"two-cap-plus-one", 65537}, {"three-cap", 98304}} {
		t.Run(tc.name, func(t *testing.T) {
			for _, rel := range []string{"equal", "short", "extra"} {
				if tc.size == 0 && rel == "short" {
					continue
				}
				t.Run(rel, func(t *testing.T) {
					n := tc.size
					if rel == "short" {
						n--
					}
					if rel == "extra" {
						n++
					}
					compareScratchFile(t, int64(tc.size), n)
				})
			}
		})
	}
	for _, tc := range []struct {
		name string
		size int64
	}{{"min-int", math.MinInt64}, {"negative-two", -2}, {"negative-one", -1}, {"max-minus-one", math.MaxInt64 - 1}, {"max-int", math.MaxInt64}} {
		t.Run(tc.name, func(t *testing.T) { compareScratchFile(t, tc.size, 31) })
	}
}

type scratchTraceContext struct {
	context.Context
	checks, failAt int
	failure        error
}

func (c *scratchTraceContext) Err() error {
	c.checks++
	if c.failAt > 0 && c.checks >= c.failAt {
		return c.failure
	}
	return nil
}

type scratchTraceReader struct {
	data               []byte
	offset             int
	mode               string
	requests, returned []int
	errors             []string
}

func (r *scratchTraceReader) Read(p []byte) (int, error) {
	r.requests = append(r.requests, len(p))
	call := len(r.requests)
	n := 0
	var e error
	switch {
	case r.mode == "zero-once" && call == 1:
	case r.mode == "read-error":
		e = interrupted
	case r.offset == len(r.data):
		e = io.EOF
	default:
		n = len(p)
		if n > len(r.data)-r.offset {
			n = len(r.data) - r.offset
		}
		if r.mode == "fragment-seven" && n > 7 {
			n = 7
		}
		if r.mode == "partial-error" && n > 7 {
			n = 7
		}
		copy(p, r.data[r.offset:r.offset+n])
		r.offset += n
		if r.mode == "partial-error" {
			e = interrupted
		}
	}
	r.returned = append(r.returned, n)
	kind := "nil"
	if e == io.EOF {
		kind = "EOF"
	} else if e != nil {
		kind = "interrupted"
	}
	r.errors = append(r.errors, kind)
	return n, e
}

type scratchTraceResult struct {
	sum                string
	count              int64
	err                error
	requests, returned []int
	errors             []string
	checks, offset     int
}

func scratchCopyTrace(original bool, size int64, mode string) scratchTraceResult {
	length := 31
	if size >= 0 && size <= 65536 {
		length = int(size) + 1
	}
	reader := &scratchTraceReader{data: scratchData(length), mode: mode}
	ctx := &scratchTraceContext{Context: context.Background(), failure: context.Canceled}
	switch mode {
	case "cancel-first":
		ctx.failAt = 1
	case "cancel-second":
		ctx.failAt = 2
	case "deadline-third":
		ctx.failAt = 3
		ctx.failure = context.DeadlineExceeded
	}
	h := sha256.New()
	wrapped := contextReader{ctx, io.LimitReader(reader, size+1)}
	if _, ok := any(wrapped).(io.WriterTo); ok {
		panic("review contextReader WriterTo growth")
	}
	if _, ok := h.(io.ReaderFrom); ok {
		panic("review SHA ReaderFrom growth")
	}
	var n int64
	var e error
	if original {
		n, e = io.Copy(h, wrapped)
	} else {
		n, e = io.CopyBuffer(h, wrapped, make([]byte, hashScratchSize(size)))
	}
	sum := ""
	if e == nil {
		if n != size {
			e = ErrInventory
		} else {
			sum = fmt.Sprintf("%x", h.Sum(nil))
		}
	}
	return scratchTraceResult{sum, n, e, reader.requests, reader.returned, reader.errors, ctx.checks, reader.offset}
}
func TestRuntimeFileHashScratchSameUnderlyingReadsAndCancellationBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int64
	}{{"zero", 0}, {"one", 1}, {"seven", 7}, {"tiny", 255}, {"page", 4096}, {"cap-minus-one", 32767}, {"cap", 32768}, {"cap-plus-one", 32769}, {"two-cap", 65536}, {"negative-one", -1}, {"negative-two", -2}, {"min-int", math.MinInt64}, {"max-int", math.MaxInt64}} {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []string{"full", "fragment-seven", "zero-once", "read-error", "partial-error", "cancel-first", "cancel-second", "deadline-third"} {
				t.Run(mode, func(t *testing.T) {
					old := scratchCopyTrace(true, tc.size, mode)
					got := scratchCopyTrace(false, tc.size, mode)
					if old.sum != got.sum || old.count != got.count || !sameScratchError(old.err, got.err) || !reflect.DeepEqual(old.requests, got.requests) || !reflect.DeepEqual(old.returned, got.returned) || !reflect.DeepEqual(old.errors, got.errors) || old.checks != got.checks || old.offset != got.offset {
						t.Fatal("original Read args/counts/partial-error/ctx boundary changed", tc, mode, old, got)
					}
				})
			}
		})
	}
}

func TestRuntimeFileHashScratchPreservesSeekReadAndContextErrorPrecedence(t *testing.T) {
	for _, kind := range []string{"closed", "closed-cancelled", "pipe", "pipe-cancelled", "directory", "write-only", "cancelled-file", "cancelled-overflow"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir() + "/input"
			if e := os.WriteFile(path, []byte("OWNED_TEST_INPUT"), 0600); e != nil {
				t.Fatal(e)
			}
			var f *os.File
			var e error
			switch kind {
			case "pipe", "pipe-cancelled":
				var writer *os.File
				f, writer, e = os.Pipe()
				if e == nil {
					writer.Close()
				}
			case "directory":
				f, e = os.Open(t.TempDir())
			case "write-only":
				f, e = os.OpenFile(path, os.O_WRONLY, 0)
			default:
				f, e = os.Open(path)
			}
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			if kind == "closed" || kind == "closed-cancelled" {
				f.Close()
			}
			cancelled := kind == "closed-cancelled" || kind == "pipe-cancelled" || kind == "cancelled-file" || kind == "cancelled-overflow"
			oldCtx := &scratchTraceContext{Context: context.Background(), failure: context.Canceled}
			newCtx := &scratchTraceContext{Context: context.Background(), failure: context.Canceled}
			if cancelled {
				oldCtx.failAt = 1
				newCtx.failAt = 1
			}
			size := int64(16)
			if kind == "cancelled-overflow" {
				size = math.MaxInt64
			}
			want, old := originalHashFile8d59(oldCtx, f, size)
			got, err := hashFile(newCtx, f, size)
			if want != got || !sameScratchError(old, err) || oldCtx.checks != newCtx.checks {
				t.Fatal("Seek/read error or cancellation precedence changed", kind, want, got, old, err, oldCtx.checks, newCtx.checks)
			}
			if (kind == "closed-cancelled" || kind == "pipe-cancelled") && (errors.Is(err, context.Canceled) || newCtx.checks != 0) {
				t.Fatal("Seek error no longer precedes context", err, newCtx.checks)
			}
			if (kind == "cancelled-file" || kind == "cancelled-overflow") && !errors.Is(err, context.Canceled) {
				t.Fatal("context no longer precedes limit EOF/size", err)
			}
		})
	}
}

func TestRuntimeFileHashScratchVerifierNeverCachesContentOrRelaxesPathPolicy(t *testing.T) {
	root := t.TempDir()
	fd, e := os.Open(root)
	if e != nil {
		t.Fatal(e)
	}
	defer fd.Close()
	f := &filesystem{root: fd}
	if e = os.Mkdir(root+"/owned", 0700); e != nil {
		t.Fatal(e)
	}
	path := root + "/owned/asset"
	original := []byte("FRESH_OWNED_TEST_DATA")
	if e = os.WriteFile(path, original, 0600); e != nil {
		t.Fatal(e)
	}
	file := File{Path: "/owned/asset", SHA256: digest(original), Bytes: int64(len(original)), Mode: 0600}
	for _, kind := range []string{"first-valid", "modified-same-length", "restored", "mode-reject", "symlink-reject"} {
		t.Run(kind, func(t *testing.T) {
			switch kind {
			case "modified-same-length":
				b := append([]byte(nil), original...)
				b[0] ^= 1
				if e := os.WriteFile(path, b, 0600); e != nil {
					t.Fatal(e)
				}
			case "restored":
				if e := os.WriteFile(path, original, 0600); e != nil {
					t.Fatal(e)
				}
			case "mode-reject":
				if e := os.Chmod(path, 0644); e != nil {
					t.Fatal(e)
				}
				defer os.Chmod(path, 0600)
			case "symlink-reject":
				if e := os.Rename(path, path+".owned"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(path+".owned", path); e != nil {
					t.Fatal(e)
				}
			}
			before := coreTree(t, root)
			err := f.verify(context.Background(), file)
			if (err == nil) != (kind == "first-valid" || kind == "restored") || !reflect.DeepEqual(before, coreTree(t, root)) {
				t.Fatal("fresh checksum/type/mode/path verification relaxed or mutated input", kind, err)
			}
		})
	}
}
