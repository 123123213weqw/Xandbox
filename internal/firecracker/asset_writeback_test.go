package firecracker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"syscall"
	"testing"
)

// A counting destination is only a state-machine double, not disk evidence.
type assetWritebackCountDest struct {
	*os.File
	writes, truncated     int
	total                 int64
	short                 bool
	writeErr, truncateErr error
}

func (d *assetWritebackCountDest) Write(b []byte) (int, error) {
	d.writes++
	if d.writeErr != nil {
		return 0, d.writeErr
	}
	if d.short {
		return len(b) - 1, nil
	}
	d.total += int64(len(b))
	return len(b), nil
}
func (d *assetWritebackCountDest) Truncate(n int64) error {
	d.truncated++
	if d.truncateErr != nil {
		return d.truncateErr
	}
	if n != d.total {
		return errors.New("counting destination size mismatch")
	}
	return nil
}
func TestAssetWritebackContiguousBoundedSubmissionsAndTails(t *testing.T) {
	// Source files used by the real copier are bounded, and it writes128KiB.
	// Exercise cadence without writing gigabytes in a unit/state-machine test.
	for _, size := range []int{0, 1, assetWritebackWindow - 1, assetWritebackWindow, assetWritebackWindow + 1, 2*assetWritebackWindow + 19} {
		base := &assetWritebackCountDest{File: assetCopyFile(t)}
		var ranges [][2]int64
		sink := &assetWritebackDestination{assetCopyDestination: base, submit: func(o, n int64) error {
			if n <= 0 || n > assetWritebackWindow || o < 0 || o+n > base.total {
				t.Fatal("unwritten/unbounded range", o, n, base.total)
			}
			ranges = append(ranges, [2]int64{o, n})
			return nil
		}}
		b := make([]byte, assetCopyBlockSize)
		left := size
		for left > 0 {
			n := min(left, len(b))
			if _, e := sink.Write(b[:n]); e != nil {
				t.Fatal(e)
			}
			left -= n
		}
		if e := sink.Truncate(int64(size)); e != nil {
			t.Fatal(e)
		}
		var total int64
		for _, r := range ranges {
			if r[0] != total {
				t.Fatal("gap/overlap", ranges)
			}
			total += r[1]
		}
		if total != int64(size) || base.total != int64(size) || sink.submitted != int64(size) || base.truncated != 1 {
			t.Fatal("missing written range", size, total)
		}
		before := len(ranges)
		if e := sink.Truncate(int64(size)); e != nil || len(ranges) != before {
			t.Fatal("duplicate submission", e)
		}
	}
}

func TestAssetWritebackPartialWritesKeepEachRangeBounded(t *testing.T) {
	base := &assetWritebackCountDest{File: assetCopyFile(t)}
	var submitted int64
	sink := &assetWritebackDestination{assetCopyDestination: base, submit: func(offset, length int64) error {
		if offset != submitted || length <= 0 || length > assetWritebackWindow || offset+length > base.total {
			t.Fatalf("partial writes produced invalid range: offset=%d length=%d submitted=%d written=%d", offset, length, submitted, base.total)
		}
		submitted += length
		return nil
	}}
	buffer := make([]byte, assetCopyBlockSize)
	steps := []int{assetCopyBlockSize - 3, 7, 65537}
	left := 2*assetWritebackWindow + 19
	for i := 0; left > 0; i++ {
		n := min(left, steps[i%len(steps)])
		if _, err := sink.Write(buffer[:n]); err != nil {
			t.Fatal(err)
		}
		left -= n
	}
	if err := sink.Truncate(base.total); err != nil || submitted != base.total {
		t.Fatal("partial final range missing", err, submitted, base.total)
	}
}

func TestAssetWritebackPartialSubmissionFailureRetainsConfirmedCursor(t *testing.T) {
	base := &assetWritebackCountDest{File: assetCopyFile(t)}
	calls := 0
	sink := &assetWritebackDestination{assetCopyDestination: base, submit: func(offset, length int64) error {
		calls++
		if calls == 1 && offset == 0 && length == assetWritebackWindow {
			return nil
		}
		return syscall.EIO
	}}
	if _, err := sink.Write(make([]byte, assetWritebackWindow+19)); !errors.Is(err, syscall.EIO) {
		t.Fatal("partial submission error lost", err)
	}
	if calls != 2 || sink.submitted != assetWritebackWindow || sink.written != assetWritebackWindow+19 {
		t.Fatal("failed range advanced the confirmed cursor", calls, sink.submitted, sink.written)
	}
	if _, err := sink.Write([]byte{1}); !errors.Is(err, syscall.EIO) {
		t.Fatal("partial submission failure not sealed", err)
	}
	if err := sink.Truncate(sink.written); !errors.Is(err, syscall.EIO) || calls != 2 || base.writes != 1 || base.truncated != 0 {
		t.Fatal("partially successful submission retried IO", err, calls, base.writes, base.truncated)
	}
}
func TestAssetWritebackWrappedCopiesKeepBytesEOFAndIsolation(t *testing.T) {
	input := make([]byte, assetWritebackWindow+17)
	input[9] = 1
	input[len(input)-1] = 7
	a, b := assetCopyFile(t), assetCopyFile(t)
	for _, f := range []*os.File{a, b} {
		var total int64
		sink := &assetWritebackDestination{assetCopyDestination: f, submit: func(o, n int64) error {
			if o != total || n <= 0 {
				t.Fatal("bad callback range", o, n)
			}
			total += n
			return nil
		}}
		if e := copyAssetBytes(context.Background(), bytes.NewReader(input), sink, assetCopyDigest(input)); e != nil {
			t.Fatal(e)
		}
		assetCopyCheck(t, f, input)
		if total != int64(len(input)) {
			t.Fatal("missing tail")
		}
	}
	if _, e := a.WriteAt([]byte{99}, 0); e != nil {
		t.Fatal(e)
	}
	assetCopyCheck(t, b, input)
}
func TestAssetWritebackErrorsAreStickyWithoutRetryOrMoreIO(t *testing.T) {
	for _, mode := range []string{"write-eio", "write-enospc", "write-edquot", "short", "submit-eio", "submit-enospc", "truncate-eio", "bad-eof", "nil-submit", "invalid-state"} {
		t.Run(mode, func(t *testing.T) {
			base := &assetWritebackCountDest{File: assetCopyFile(t)}
			calls := 0
			sink := &assetWritebackDestination{assetCopyDestination: base, submit: func(o, n int64) error { calls++; return nil }}
			var want error
			switch mode {
			case "write-eio":
				base.writeErr, want = syscall.EIO, syscall.EIO
			case "write-enospc":
				base.writeErr, want = syscall.ENOSPC, syscall.ENOSPC
			case "write-edquot":
				base.writeErr, want = syscall.EDQUOT, syscall.EDQUOT
			case "short":
				base.short, want = true, io.ErrShortWrite
			case "submit-eio":
				sink.submit = func(o, n int64) error { calls++; return syscall.EIO }
				want = syscall.EIO
			case "submit-enospc":
				sink.submit = func(o, n int64) error { calls++; return syscall.ENOSPC }
				want = syscall.ENOSPC
			case "truncate-eio":
				base.truncateErr, want = syscall.EIO, syscall.EIO
			case "nil-submit":
				sink.submit = nil
			case "invalid-state":
				sink.submitted = 1
			}
			var e error
			if mode == "bad-eof" {
				e = sink.Truncate(1)
			} else if mode == "truncate-eio" {
				_, e = sink.Write([]byte{1})
				if e == nil {
					e = sink.Truncate(1)
				}
			} else {
				_, e = sink.Write(make([]byte, assetWritebackWindow))
			}
			if e == nil || (want != nil && !errors.Is(e, want)) {
				t.Fatal("failure lost", e, want)
			}
			oldCalls, oldWrites, oldTrunc := calls, base.writes, base.truncated
			if _, again := sink.Write([]byte{1}); again != e {
				t.Fatal("write error changed", again, e)
			}
			if again := sink.Truncate(sink.written); again != e {
				t.Fatal("truncate error changed", again, e)
			}
			if calls != oldCalls || base.writes != oldWrites || base.truncated != oldTrunc {
				t.Fatal("retried failed operation")
			}
		})
	}
}
func TestAssetWritebackDigestAndCancellationNeverBecomeSuccess(t *testing.T) {
	for _, mode := range []string{"bad-digest", "cancel-eof", "cancel-truncate"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			input := []byte{1, 2, 3}
			digest := assetCopyDigest(input)
			file := &assetCopyFaults{File: assetCopyFile(t)}
			calls := 0
			sink := &assetWritebackDestination{assetCopyDestination: file, submit: func(o, n int64) error { calls++; return nil }}
			var reader io.Reader = bytes.NewReader(input)
			if mode == "bad-digest" {
				digest = assetCopyDigest(nil)
			}
			if mode == "cancel-eof" {
				reader = &assetCopyReadResult{data: input, err: io.EOF, hook: cancel}
			}
			if mode == "cancel-truncate" {
				file.truncateHook = cancel
			}
			e := copyAssetBytes(ctx, reader, sink, digest)
			if e == nil || (mode != "bad-digest" && !errors.Is(e, context.Canceled)) {
				t.Fatal("false copy success", e)
			}
			want := 0
			if mode == "cancel-truncate" {
				want = 1
			}
			if calls != want || file.truncated != (mode == "cancel-truncate") {
				t.Fatal("unverified tail submitted", calls, file.truncated)
			}
		})
	}
}

func TestAssetWritebackReadAndCancelCannotHideSubmissionError(t *testing.T) {
	input := make([]byte, assetWritebackWindow)
	for _, mode := range []string{"read-eio", "cancel-eof", "cancel-read-eio"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reader := &assetWritebackLastRead{input: input}
			if mode != "cancel-eof" {
				reader.err = syscall.EIO
			}
			if mode != "read-eio" {
				reader.cancel = cancel
			}
			base := &assetWritebackCountDest{File: assetCopyFile(t)}
			sink := &assetWritebackDestination{assetCopyDestination: base, submit: func(o, n int64) error { return syscall.ENOSPC }}
			e := copyAssetBytes(ctx, reader, sink, assetCopyDigest(input))
			if !errors.Is(e, syscall.ENOSPC) || base.truncated != 0 {
				t.Fatal("submission failure hidden by read/cancel", e)
			}
		})
	}
}

type assetWritebackLastRead struct {
	input  []byte
	offset int
	err    error
	cancel context.CancelFunc
}

func (r *assetWritebackLastRead) Read(b []byte) (int, error) {
	n := copy(b, r.input[r.offset:])
	r.offset += n
	if r.offset == len(r.input) {
		if r.cancel != nil {
			r.cancel()
		}
		if r.err != nil {
			return n, r.err
		}
		return n, io.EOF
	}
	return n, nil
}
