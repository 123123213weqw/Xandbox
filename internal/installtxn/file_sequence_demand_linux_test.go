//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/gateway"
)

// Independent scalar oracle: do NOT call the candidate constructor or selector.
func originalSequenceDemand5efd(files []File, override *File) int {
	maximum := 0
	for _, file := range files {
		if override != nil && file.Path == gateway.ManagedPolicyPath {
			file = *override
		}
		n := 32768
		if file.Bytes >= 0 && file.Bytes < 32768 {
			n = int(file.Bytes) + 1
		}
		if n > maximum {
			maximum = n
		}
	}
	return maximum
}

func TestRuntimeFileSequenceDemandSizingMatchesIndependentOracle(t *testing.T) {
	policy := func(size int64) File { return File{Path: gateway.ManagedPolicyPath, Bytes: size} }
	for _, tc := range []struct {
		name     string
		files    []File
		override *File
		want     int
	}{
		{"empty", nil, nil, 0},
		{"zero", []File{{Bytes: 0}}, nil, 1},
		{"one", []File{{Bytes: 1}}, nil, 2},
		{"tiny", []File{{Bytes: 31}}, nil, 32},
		{"page", []File{{Bytes: 4096}}, nil, 4097},
		{"cap-minus-two", []File{{Bytes: 32766}}, nil, 32767},
		{"cap-minus-one", []File{{Bytes: 32767}}, nil, 32768},
		{"cap", []File{{Bytes: 32768}}, nil, 32768},
		{"cap-plus", []File{{Bytes: 32769}}, nil, 32768},
		{"negative", []File{{Bytes: -1}}, nil, 32768},
		{"min-int", []File{{Bytes: math.MinInt64}}, nil, 32768},
		{"max-int", []File{{Bytes: math.MaxInt64}}, nil, 32768},
		{"mixed", []File{{Bytes: 31}, {Bytes: 255}, {Bytes: 1}}, nil, 256},
		{"override-smaller", []File{policy(65537), {Bytes: 31}}, ptrSequenceFile(policy(1)), 32},
		{"override-larger", []File{policy(1), {Bytes: 31}}, ptrSequenceFile(policy(4096)), 4097},
		{"override-absent", []File{{Path: "/owned", Bytes: 31}}, ptrSequenceFile(policy(65537)), 32},
		{"nil-override", []File{policy(1), {Bytes: 31}}, nil, 32},
		{"unrelated-largest", []File{policy(65537), {Path: "/other", Bytes: 98305}}, ptrSequenceFile(policy(1)), 32768},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]File(nil), tc.files...)
			var oldOverride File
			if tc.override != nil {
				oldOverride = *tc.override
			}
			scratch := newFileSequenceScratch(tc.files, tc.override)
			if scratch.buffer != nil || scratch.reserved != tc.want || scratch.reserved != originalSequenceDemand5efd(tc.files, tc.override) || scratch.reserved < 0 || scratch.reserved > 32768 {
				t.Fatal("incorrect bounded metadata maximum or eager allocation")
			}
			if !reflect.DeepEqual(before, tc.files) || tc.override != nil && *tc.override != oldOverride {
				t.Fatal("sizing mutated private inputs")
			}
			scratch.release()
			if scratch.buffer != nil || scratch.reserved != 0 {
				t.Fatal("released stage retained a size reservation")
			}
		})
	}
}

func ptrSequenceFile(v File) *File { return &v }

func TestRuntimeFileSequenceDemandStagesFreshSingleAllocation(t *testing.T) {
	for _, tc := range []struct {
		name         string
		sizes        []int
		policyChange int // -1 means no override; otherwise the final target is policy.
	}{
		{"small-ascending", []int{0, 1, 31, 255}, -1},
		{"small-descending", []int{4096, 31, 0}, -1},
		{"mixed-large", []int{31, 65537, 1}, -1},
		{"all-large", []int{32768, 98305}, -1},
		{"override-larger", []int{31, 7}, 4096},
		{"override-smaller", []int{31, 65537}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			fd, e := os.Open(root)
			if e != nil {
				t.Fatal(e)
			}
			defer fd.Close()
			f := &filesystem{root: fd}
			var files []File
			var override *File
			for i, size := range tc.sizes {
				path := "/owned/" + string(rune('a'+i))
				if tc.policyChange >= 0 && i == len(tc.sizes)-1 {
					path = gateway.ManagedPolicyPath
				}
				data := scratchData(size)
				files = append(files, File{Path: path, SHA256: digest(data), Bytes: int64(len(data)), Mode: 0600})
				if tc.policyChange >= 0 && i == len(tc.sizes)-1 {
					data = scratchData(tc.policyChange)
					override = ptrSequenceFile(File{Path: path, SHA256: digest(data), Bytes: int64(len(data)), Mode: 0600})
				}
				if e = os.MkdirAll(root+filepath.Dir(path), 0700); e == nil {
					e = os.WriteFile(root+path, data, 0600)
				}
				if e != nil {
					t.Fatal(e)
				}
			}
			before := coreTree(t, root)
			scratch := newFileSequenceScratch(files, override)
			defer scratch.release()
			want := originalSequenceDemand5efd(files, override)
			var pointer *byte
			for _, file := range files {
				if override != nil && file.Path == gateway.ManagedPolicyPath {
					file = *override
				}
				for i := range scratch.buffer {
					scratch.buffer[i] = 0x6d
				}
				if e = f.verifyFileWithScratch(context.Background(), file, &scratch); e != nil {
					t.Fatal("fresh full-byte owned verifier", e)
				}
				if len(scratch.buffer) != want || cap(scratch.buffer) != want || want > 32768 {
					t.Fatal("stage did not allocate the exact bounded demand")
				}
				if pointer == nil {
					pointer = &scratch.buffer[0]
				} else if pointer != &scratch.buffer[0] {
					t.Fatal("production-sized sequence grew storage between targets")
				}
			}
			if e = originalFileSequenceF12(context.Background(), f, files, override); e != nil {
				t.Fatal("unchanged original serial verifier", e)
			}
			if e = f.verifyFileSequence(context.Background(), files, override); e != nil || !reflect.DeepEqual(before, coreTree(t, root)) {
				t.Fatal("actual sequence changed proof or disk bytes", e)
			}
			borrowed := scratch.buffer
			scratch.release()
			if scratch.buffer != nil || scratch.reserved != 0 || !bytes.Equal(borrowed, make([]byte, want)) {
				t.Fatal("stage storage/reservation did not release")
			}
		})
	}
}

func TestRuntimeFileSequenceDemandGrowthBoundsAndClearsOldBytes(t *testing.T) {
	path := t.TempDir() + "/owned"
	if e := os.WriteFile(path, scratchData(65537), 0600); e != nil {
		t.Fatal(e)
	}
	fd, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer fd.Close()
	for _, tc := range []struct {
		name     string
		reserved int
		want     int
	}{{"zero-reserve", 0, 2}, {"negative-reserve", -1, 2}, {"forged-large-reserve", int(^uint(0) >> 1), 32768}} {
		t.Run(tc.name, func(t *testing.T) {
			scratch := fileSequenceScratch{reserved: tc.reserved}
			defer scratch.release()
			// Declaring one byte against a larger file MUST preserve the original
			// extra-byte refusal; the reservation is never a read/size bypass.
			if _, e := scratch.hash(context.Background(), fd, 1); !errors.Is(e, ErrInventory) || len(scratch.buffer) != tc.want || cap(scratch.buffer) != tc.want {
				t.Fatal("untrusted private size hint changed bounded actual read")
			}
		})
	}
	var scratch fileSequenceScratch
	defer scratch.release()
	if _, e = scratch.hash(context.Background(), fd, 1); !errors.Is(e, ErrInventory) || len(scratch.buffer) != 2 {
		t.Fatal("initial small extra-byte control")
	}
	borrowed := scratch.buffer
	for i := range borrowed {
		borrowed[i] = 0x5c
	}
	want, old := originalHashFile8d59(context.Background(), fd, 65537)
	got, err := scratch.hash(context.Background(), fd, 65537)
	if old != nil || err != nil || got != want || len(scratch.buffer) != 32768 || !bytes.Equal(borrowed, []byte{0, 0}) {
		t.Fatal("growth reused stale authority/data or failed to clear prior storage")
	}
	planned := newFileSequenceScratch([]File{{Bytes: 0}}, nil)
	defer planned.release()
	if planned.reserved != 1 {
		t.Fatal("small plan control")
	}
	got, err = planned.hash(context.Background(), fd, 65537)
	if err != nil || got != want || len(planned.buffer) != 32768 {
		t.Fatal("stale private size reservation truncated the actual fresh hash")
	}
}

func TestRuntimeFileSequenceDemandKeepsOriginalEarlyErrors(t *testing.T) {
	for _, kind := range []string{"empty-cancelled", "directory-first", "missing-first", "wrong-mode-first", "checksum-first", "cancel-first", "cancel-after-first", "override-cancelled"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			fd, e := os.Open(root)
			if e != nil {
				t.Fatal(e)
			}
			defer fd.Close()
			f := &filesystem{root: fd}
			var files []File
			var override *File
			for i, size := range []int{31, 65537} {
				path := "/owned/" + string(rune('a'+i))
				if kind == "override-cancelled" && i == 0 {
					path = gateway.ManagedPolicyPath
				}
				data := scratchData(size)
				files = append(files, File{Path: path, SHA256: digest(data), Bytes: int64(len(data)), Mode: 0600})
				if kind == "override-cancelled" && i == 0 {
					data = scratchData(1)
					override = ptrSequenceFile(File{Path: path, SHA256: digest(data), Bytes: 1, Mode: 0600})
				}
				if e = os.MkdirAll(root+filepath.Dir(path), 0700); e == nil {
					e = os.WriteFile(root+path, data, 0600)
				}
				if e != nil {
					t.Fatal(e)
				}
			}
			first := root + files[0].Path
			switch kind {
			case "empty-cancelled":
				files = nil
			case "directory-first":
				e = os.Remove(first)
				if e == nil {
					e = os.Mkdir(first, 0700)
				}
			case "missing-first":
				e = os.Remove(first)
			case "wrong-mode-first":
				e = os.Chmod(first, 0644)
			case "checksum-first":
				data := scratchData(31)
				data[0] ^= 1
				e = os.WriteFile(first, data, 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			oldCtx := &scratchTraceContext{Context: context.Background(), failure: context.Canceled}
			newCtx := &scratchTraceContext{Context: context.Background(), failure: context.Canceled}
			switch kind {
			case "empty-cancelled", "cancel-first", "override-cancelled":
				oldCtx.failAt, newCtx.failAt = 1, 1
			case "cancel-after-first":
				oldCtx.failAt, newCtx.failAt = 3, 3
			}
			before := coreTree(t, root)
			old := originalFileSequenceF12(oldCtx, f, files, override)
			err := f.verifyFileSequence(newCtx, files, override)
			if !sameScratchError(old, err) || oldCtx.checks != newCtx.checks || (err == nil) != (kind == "empty-cancelled") || !reflect.DeepEqual(before, coreTree(t, root)) {
				t.Fatal("metadata maximum changed original early error/order/reads or disk state")
			}
		})
	}
}
