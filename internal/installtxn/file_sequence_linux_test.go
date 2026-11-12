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

func TestRuntimeFileSequenceFullFreshHashesAndNoTaint(t *testing.T) {
	var scratch fileSequenceScratch
	defer scratch.release()
	for _, tc := range []struct {
		name string
		size int
	}{{"zero", 0}, {"one", 1}, {"tiny", 31}, {"page", 4096}, {"cap-minus", 32767}, {"cap", 32768}, {"cap-plus", 32769}, {"large", 98305}} {
		t.Run(tc.name, func(t *testing.T) {
			path := t.TempDir() + "/owned"
			data := scratchData(tc.size)
			if e := os.WriteFile(path, data, 0600); e != nil {
				t.Fatal(e)
			}
			in, e := os.Open(path)
			if e != nil {
				t.Fatal(e)
			}
			defer in.Close()
			for i := range scratch.buffer {
				scratch.buffer[i] = 0x7f // Old storage must never become hashed input.
			}
			want, old := originalHashFile8d59(context.Background(), in, int64(tc.size))
			oldPos, oldPosErr := in.Seek(0, 1)
			got, err := scratch.hash(context.Background(), in, int64(tc.size))
			pos, posErr := in.Seek(0, 1)
			if old != nil || err != nil || got != want || got != digest(data) || oldPosErr != nil || posErr != nil || pos != oldPos {
				t.Fatal("full fresh hash/offset differs from pinned original")
			}
			if len(data) > 0 {
				data[0] ^= 1
				if e = os.WriteFile(path, data, 0600); e != nil {
					t.Fatal(e)
				}
				changed, e := scratch.hash(context.Background(), in, int64(tc.size))
				if e != nil || changed == want || changed != digest(data) {
					t.Fatal("same-inode same-length content was cached")
				}
			}
		})
	}
}

func TestRuntimeFileSequenceHashErrorsCancellationAndOverflowMatchOriginal(t *testing.T) {
	for _, kind := range []string{"ordinary", "closed", "closed-cancelled", "pipe", "pipe-cancelled", "directory", "write-only", "cancelled-file", "cancelled-overflow", "min-int", "negative-two", "negative-one", "max-minus-one", "max-int"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir() + "/owned"
			if e := os.WriteFile(path, scratchData(65537), 0600); e != nil {
				t.Fatal(e)
			}
			var in *os.File
			var e error
			switch kind {
			case "pipe", "pipe-cancelled":
				var writer *os.File
				in, writer, e = os.Pipe()
				if e == nil {
					writer.Close()
				}
			case "directory":
				in, e = os.Open(t.TempDir())
			case "write-only":
				in, e = os.OpenFile(path, os.O_WRONLY, 0)
			default:
				in, e = os.Open(path)
			}
			if e != nil {
				t.Fatal(e)
			}
			defer in.Close()
			if kind == "closed" || kind == "closed-cancelled" {
				in.Close()
			}
			size := int64(65537)
			switch kind {
			case "min-int":
				size = math.MinInt64
			case "negative-two":
				size = -2
			case "negative-one":
				size = -1
			case "max-minus-one":
				size = math.MaxInt64 - 1
			case "max-int", "cancelled-overflow":
				size = math.MaxInt64
			}
			oldCtx := &scratchTraceContext{Context: context.Background(), failure: context.Canceled}
			newCtx := &scratchTraceContext{Context: context.Background(), failure: context.Canceled}
			switch kind {
			case "closed-cancelled", "pipe-cancelled", "cancelled-file", "cancelled-overflow":
				oldCtx.failAt, newCtx.failAt = 1, 1
			}
			want, old := originalHashFile8d59(oldCtx, in, size)
			oldPos, oldPosErr := in.Seek(0, 1)
			var scratch fileSequenceScratch
			defer scratch.release()
			got, err := scratch.hash(newCtx, in, size)
			pos, posErr := in.Seek(0, 1)
			if want != got || !sameScratchError(old, err) || oldCtx.checks != newCtx.checks || oldPos != pos || !sameScratchError(oldPosErr, posErr) {
				t.Fatal("seek/read/size/context error or consumed-offset order changed")
			}
			if (kind == "closed-cancelled" || kind == "pipe-cancelled") && (newCtx.checks != 0 || scratch.buffer != nil || errors.Is(err, context.Canceled)) {
				t.Fatal("seek failure no longer precedes allocation/context")
			}
		})
	}
}

func TestRuntimeFileSequenceOnePrivateBufferAndZeroedRelease(t *testing.T) {
	var scratch fileSequenceScratch
	if scratch.buffer != nil {
		t.Fatal("empty sequence allocated storage")
	}
	path := t.TempDir() + "/owned"
	if e := os.WriteFile(path, scratchData(65537), 0600); e != nil {
		t.Fatal(e)
	}
	in, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer in.Close()
	for i := 0; i < 3; i++ {
		if _, e = scratch.hash(context.Background(), in, 65537); e != nil {
			t.Fatal(e)
		}
		if len(scratch.buffer) != 32768 || cap(scratch.buffer) != 32768 {
			t.Fatal("buffer grew beyond the original per-read ceiling")
		}
	}
	borrowed := scratch.buffer // TEST ONLY: no production method exports this.
	pointer := &borrowed[0]
	if _, e = scratch.hash(context.Background(), in, 65537); e != nil || &scratch.buffer[0] != pointer {
		t.Fatal("serial hashes did not reuse only their private storage")
	}
	for i := range borrowed {
		borrowed[i] = 0x5a
	}
	scratch.release()
	if scratch.buffer != nil || !bytes.Equal(borrowed, make([]byte, 32768)) {
		t.Fatal("released storage retained prior target bytes")
	}
	scratch.release()
	var next fileSequenceScratch
	defer next.release()
	if _, e = next.hash(context.Background(), in, 65537); e != nil || &next.buffer[0] == pointer || !bytes.Equal(borrowed, make([]byte, 32768)) {
		t.Fatal("next stage adopted or wrote the previous stage's storage")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var failed fileSequenceScratch
	if _, e = failed.hash(ctx, in, 65537); !errors.Is(e, context.Canceled) || len(failed.buffer) != 32768 {
		t.Fatal("owned storage/error precedence on early failure")
	}
	failedBytes := failed.buffer
	for i := range failedBytes {
		failedBytes[i] = 0x3c
	}
	failed.release()
	if failed.buffer != nil || !bytes.Equal(failedBytes, make([]byte, 32768)) {
		t.Fatal("early-failure storage was not cleared/released")
	}
}

// Exact original serial loop, using the UNCHANGED standalone verifier. This is
// not routed through the candidate hash, storage selector or batch helper.
func originalFileSequenceF12(ctx context.Context, f *filesystem, files []File, override *File) error {
	for _, v := range files {
		if override != nil && v.Path == gateway.ManagedPolicyPath {
			v = *override
		}
		if e := f.verify(ctx, v); e != nil {
			return e
		}
	}
	return nil
}

func TestRuntimeFileSequenceOrderOverrideAndFailuresMatchOriginal(t *testing.T) {
	for _, kind := range []string{"exact", "changed-second", "missing-second", "mode-second", "link-second", "extra-second", "short-second", "bad-path-first", "cancel-first", "cancel-second", "override-policy"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			in, e := os.Open(root)
			if e != nil {
				t.Fatal(e)
			}
			defer in.Close()
			f := &filesystem{root: in}
			paths := []string{"/owned/first", "/owned/second", gateway.ManagedPolicyPath}
			payloads := [][]byte{scratchData(31), scratchData(65537), []byte("OWNED_TEST_POLICY_OLD")}
			var files []File
			for i, path := range paths {
				if e = os.MkdirAll(root+filepath.Dir(path), 0700); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(root+path, payloads[i], 0600); e != nil {
					t.Fatal(e)
				}
				files = append(files, File{Path: path, SHA256: digest(payloads[i]), Bytes: int64(len(payloads[i])), Mode: 0600})
			}
			var override *File
			second := root + paths[1]
			switch kind {
			case "changed-second":
				payloads[1][0] ^= 1
				e = os.WriteFile(second, payloads[1], 0600)
			case "missing-second":
				e = os.Remove(second)
			case "mode-second":
				e = os.Chmod(second, 0644)
			case "link-second":
				e = os.Rename(second, second+".owned")
				if e == nil {
					e = os.Symlink(second+".owned", second)
				}
			case "extra-second":
				e = os.WriteFile(second, append(payloads[1], 1), 0600)
			case "short-second":
				e = os.WriteFile(second, payloads[1][:len(payloads[1])-1], 0600)
			case "bad-path-first":
				files[0].Path = "/owned/../owned/first"
			case "override-policy":
				data := []byte("OWNED_TEST_POLICY_NEW")
				e = os.WriteFile(root+gateway.ManagedPolicyPath, data, 0600)
				v := File{Path: gateway.ManagedPolicyPath, SHA256: digest(data), Bytes: int64(len(data)), Mode: 0600}
				override = &v
			}
			if e != nil {
				t.Fatal(e)
			}
			oldCtx := &scratchTraceContext{Context: context.Background(), failure: context.Canceled}
			newCtx := &scratchTraceContext{Context: context.Background(), failure: context.Canceled}
			if kind == "cancel-first" {
				oldCtx.failAt, newCtx.failAt = 1, 1
			} else if kind == "cancel-second" {
				oldCtx.failAt, newCtx.failAt = 3, 3
			}
			before := coreTree(t, root)
			old := originalFileSequenceF12(oldCtx, f, files, override)
			err := f.verifyFileSequence(newCtx, files, override)
			if !sameScratchError(old, err) || oldCtx.checks != newCtx.checks || (err == nil) != (kind == "exact" || kind == "override-policy") || !reflect.DeepEqual(before, coreTree(t, root)) {
				t.Fatal("original order/path/override/fresh bytes/context/error or read-only behavior changed")
			}
		})
	}
}

// Real test-owned shadow roots and immutable file proofs, but MODEL programs /
// manager, not a native install, real daemon, service transition or KVM gate.
func TestRuntimeFileSequenceOriginalV1V2CommittedGuardsStayClosed(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		t.Run(version, func(t *testing.T) {
			makeFixture := fixture
			if version == "v2" {
				makeFixture = managedFixture
			}
			f, p, m := makeFixture(t)
			tx, e := applyModel(context.Background(), f, p, request(), m)
			if e != nil || f.verifyTransaction(context.Background(), tx) != nil {
				t.Fatal("existing committed fixture proof", e)
			}
			before := coreTree(t, f.root.Name())
			if e = f.verifyTransaction(context.Background(), tx); e != nil || !reflect.DeepEqual(before, coreTree(t, f.root.Name())) {
				t.Fatal("whole existing verifier changed bytes", e)
			}
			var guarded File
			for _, v := range tx.Files {
				if v.Path == rolePath("daemon") {
					guarded = v
				}
			}
			if guarded.Path == "" {
				t.Fatal("model fixture has no daemon target")
			}
			path := f.root.Name() + guarded.Path
			data, e := os.ReadFile(path)
			if e != nil || len(data) == 0 {
				t.Fatal(e)
			}
			if e = os.Chmod(path, 0755); e != nil {
				t.Fatal(e)
			}
			data[0] ^= 1
			if e = os.WriteFile(path, data, 0755); e != nil {
				t.Fatal(e)
			}
			if e = os.Chmod(path, 0555); e != nil {
				t.Fatal(e)
			}
			if f.verifyTransaction(context.Background(), tx) == nil {
				t.Fatal("same-size changed target was cached")
			}
			data[0] ^= 1
			if e = os.Chmod(path, 0755); e == nil {
				e = os.WriteFile(path, data, 0755)
			}
			if e == nil {
				e = os.Chmod(path, 0555)
			}
			if e != nil || f.verifyTransaction(context.Background(), tx) != nil {
				t.Fatal("exact restoration was not freshly verified", e)
			}
			if e = os.WriteFile(f.root.Name()+Root+"/unknown", []byte("OWNED_TEST_UNKNOWN"), 0600); e != nil {
				t.Fatal(e)
			}
			ctx := &scratchTraceContext{Context: context.Background()}
			if f.verifyTransaction(ctx, tx) == nil || ctx.checks != 0 {
				t.Fatal("root inventory no longer refuses before target hashes")
			}
			if e = os.Remove(f.root.Name() + Root + "/unknown"); e != nil {
				t.Fatal(e)
			}
			ctx = &scratchTraceContext{Context: context.Background()}
			if !errors.Is(f.verifyTargetsAfterPolicy(ctx, tx, true, &File{Path: "/wrong"}), ErrPolicy) || ctx.checks != 0 {
				t.Fatal("managed override guard no longer precedes target hashes")
			}
		})
	}
}
