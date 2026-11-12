//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

// Actual ordinary-format files in an owned directory, not a running daemon,
// process-pinned closure, backend/VM, installation or activation certificate.
func framingFixture(t *testing.T, sizes []int, separateTenants, pending bool) (*os.File, map[sandbox.Ref]retainedResultOwner) {
	t.Helper()
	path := t.TempDir()
	store, e := sandbox.OpenResultStore(filepath.Join(path, "results"), sandbox.ResultLimits{Bytes: 4 << 20, TenantBytes: 4 << 20, Records: 10})
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	owners := map[sandbox.Ref]retainedResultOwner{}
	// Reverse creation order independently of the required sorted read order.
	for i := len(sizes) - 1; i >= 0; i-- {
		tenant := "tenant-a"
		if separateTenants && i != 0 {
			tenant = "tenant-b"
		}
		h := sandbox.ResultReservation{JobID: fmt.Sprintf("%032x", i+1), Ref: sandbox.Ref{ID: fmt.Sprintf("%032x", i+20), Generation: strings.Repeat("e", 32)}, TenantID: tenant, MaxOutputBytes: max(1, sizes[i]), StartedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)}
		owners[h.Ref] = retainedResultOwner{tenant: tenant, maxOutput: h.MaxOutputBytes}
		if e = store.Reserve(h); e != nil {
			t.Fatal(e)
		}
		if pending {
			continue
		}
		payload := make([]byte, sizes[i])
		for j := range payload {
			payload[j] = byte(j*131 + i) // Includes NUL and non-UTF-8 bytes.
		}
		job := sandbox.Job{ID: h.JobID, Ref: h.Ref, Status: "EXITED", StartedAt: h.StartedAt, FinishedAt: h.StartedAt.Add(time.Second), Output: sandbox.Output{Stdout: string(payload), ExitCode: 0}}
		if e = store.Complete(job); e != nil {
			t.Fatal(e)
		}
	}
	root, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { root.Close() })
	return root, owners
}

func framingReader(t *testing.T, ctx context.Context, root *os.File) *stateInventoryReader {
	t.Helper()
	var st unix.Stat_t
	if e := unix.Fstat(int(root.Fd()), &st); e != nil {
		t.Fatal(e)
	}
	h := sha256.New()
	h.Write([]byte("independent original result framing test\x00"))
	return &stateInventoryReader{ctx: ctx, device: uint64(st.Dev), hash: h}
}

func framingSameError(a, b error) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Error() == b.Error() && errors.Is(a, b) == errors.Is(b, a)
}

func compareFraming(t *testing.T, ctx context.Context, root *os.File, owners map[sandbox.Ref]retainedResultOwner, success bool) {
	t.Helper()
	before := coreTree(t, root.Name())
	old, candidate := framingReader(t, ctx, root), framingReader(t, ctx, root)
	a, b := &retainedRootPolicy{owners: owners}, &retainedRootPolicy{owners: owners}
	oldErr := old.framingOriginalRetainedC4(root, a)
	gotErr := candidate.retainedResults(root, b)
	if !framingSameError(oldErr, gotErr) || (gotErr == nil) != success || old.view != candidate.view || !bytes.Equal(old.hash.Sum(nil), candidate.hash.Sum(nil)) || a.results != b.results {
		t.Fatal("changed raw/stat frame, count, result projection or refusal", oldErr, gotErr, old.view, candidate.view, a.results, b.results)
	}
	if !reflect.DeepEqual(before, coreTree(t, root.Name())) {
		t.Fatal("framing inspection modified an owned file or namespace")
	}
}

func TestRuntimeRetainedFramingFullRawDomainMatchesOriginal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sizes   []int
		tenants bool
	}{
		{"empty", nil, false}, {"zero-output", []int{0}, false},
		{"one-byte", []int{1}, false}, {"page-minus-one", []int{4095}, false},
		{"page", []int{4096}, false}, {"maximum-binary-output", []int{65536}, false},
		{"same-tenant-reverse-created", []int{1, 4096}, false}, {"two-tenants", []int{4096, 65536}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, owners := framingFixture(t, tc.sizes, tc.tenants, false)
			compareFraming(t, context.Background(), root, owners, true)
			// Every invocation gets a fresh reader/projection; no prior digest is
			// available to the second complete scan.
			compareFraming(t, context.Background(), root, owners, true)
		})
	}
}

func TestRuntimeRetainedFramingRefusalsKeepOriginalPrefix(t *testing.T) {
	for _, name := range []string{"checksum", "pending", "empty-file", "unknown-name", "subdirectory", "symlink", "hardlink", "mode", "orphan-owner", "tenant", "output-limit", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			root, owners := framingFixture(t, []int{32}, false, name == "pending")
			path := filepath.Join(root.Name(), "results", fmt.Sprintf("%032x.json", 1))
			ctx := context.Background()
			var e error
			switch name {
			case "checksum":
				var raw []byte
				raw, e = os.ReadFile(path)
				if e == nil {
					key := []byte(`"sha256":"`)
					at := bytes.LastIndex(raw, key)
					if at < 0 {
						t.Fatal("ordinary V2 checksum missing")
					}
					at += len(key)
					if raw[at] == 'a' {
						raw[at] = 'b'
					} else {
						raw[at] = 'a'
					}
					e = os.WriteFile(path, raw, 0600)
				}
			case "empty-file":
				e = os.WriteFile(path, nil, 0600)
			case "unknown-name":
				e = os.WriteFile(filepath.Join(root.Name(), "results", "unknown"), []byte("x"), 0600)
			case "subdirectory":
				e = os.Remove(path)
				if e == nil {
					e = os.Mkdir(path, 0700)
				}
			case "symlink":
				e = os.Rename(path, filepath.Join(root.Name(), "original-row"))
				if e == nil {
					e = os.Symlink(filepath.Join(root.Name(), "original-row"), path)
				}
			case "hardlink":
				e = os.Link(path, filepath.Join(root.Name(), "alias-row"))
			case "mode":
				e = os.Chmod(path, 0644)
			case "orphan-owner":
				clear(owners)
			case "tenant", "output-limit":
				for ref, owner := range owners {
					if name == "tenant" {
						owner.tenant = "different"
					} else {
						owner.maxOutput++
					}
					owners[ref] = owner
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if e != nil {
				t.Fatal(e)
			}
			compareFraming(t, ctx, root, owners, false)
		})
	}
}

func TestRuntimeRetainedFramingOrdinaryFileReaderUnchanged(t *testing.T) {
	for _, name := range []string{"regular", "empty-lock", "limit", "empty-nonlock", "nonempty-lock", "mode", "missing", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			root, _ := framingFixture(t, nil, false, false)
			data, limit, empty := []byte("complete bytes\x00\xff"), 128, false
			if name == "empty-lock" || name == "empty-nonlock" {
				data = nil
			}
			if name == "empty-lock" || name == "nonempty-lock" {
				empty = true
			}
			if name == "limit" {
				limit = 1
			}
			path := filepath.Join(root.Name(), "ordinary")
			if e := os.WriteFile(path, data, 0600); e != nil {
				t.Fatal(e)
			}
			if name == "mode" {
				if e := os.Chmod(path, 0644); e != nil {
					t.Fatal(e)
				}
			}
			if name == "missing" {
				if e := os.Remove(path); e != nil {
					t.Fatal(e)
				}
			}
			ctx := context.Background()
			if name == "cancelled" {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			before := coreTree(t, root.Name())
			a, b := framingReader(t, ctx, root), framingReader(t, ctx, root)
			old, oldErr := a.framingOriginalFileC4(root, "ordinary", "ordinary", limit, empty)
			got, gotErr := b.file(root, "ordinary", "ordinary", limit, empty)
			if !framingSameError(oldErr, gotErr) || !bytes.Equal(old, got) || a.view != b.view || !bytes.Equal(a.hash.Sum(nil), b.hash.Sum(nil)) || !reflect.DeepEqual(before, coreTree(t, root.Name())) {
				t.Fatal("ordinary file read/frame/error changed", oldErr, gotErr)
			}
		})
	}
}

func TestRuntimeRetainedFramingWholeRootStillReadsFreshBytes(t *testing.T) {
	// Existing explicit legacy Stop MODEL plus actual ordinary result files.
	// This is not an authentic V2 actor, real installation/KVM or activation.
	x := newRetainedRootTest(t)
	ctx, cancel := workStopContext(t)
	defer cancel()
	before := coreTree(t, x.x.f.root.Name())
	first, e := x.read(ctx)
	if e != nil || first.Results != x.expected.Results || !first.DiskResultBytesMatched || first.ResourcesReclaimed || first.ActivationAllowed || !reflect.DeepEqual(before, coreTree(t, x.x.f.root.Name())) {
		t.Fatal(first, e)
	}
	changed := append([]byte(nil), x.raw...)
	changed[len(changed)-2] ^= 1
	if e = os.WriteFile(x.file, changed, 0600); e != nil {
		t.Fatal(e)
	}
	retainedRootRefuses(t, x, ctx)
	if e = os.WriteFile(x.file, x.raw, 0600); e != nil {
		t.Fatal(e)
	}
	after, e := x.read(ctx)
	if e != nil || after.Results != first.Results || !after.DiskResultBytesMatched || after.ResourcesReclaimed || after.ActivationAllowed {
		t.Fatal(after, e)
	}
}

// Exact c4aa858 original reader bodies below, with ONLY reference function
// renames. They never call fileBytes or retainedResult, so the original raw
// hash and the ordinary decoder independently recompute their own SHA-256.
func (r *stateInventoryReader) framingOriginalFileC4(dir *os.File, name, path string, limit int, empty bool) ([]byte, error) {
	before, e := r.entry(dir, name)
	if e != nil {
		return nil, e
	}
	var raw []byte
	if empty {
		if before.Mode != unix.S_IFREG|0600 || before.Nlink != 1 || before.Size != 0 {
			return nil, ErrInventory
		}
	} else {
		raw, e = readCoreRecord(r.ctx, dir, name, limit)
		if e != nil {
			return nil, e
		}
	}
	after, e := r.entry(dir, name)
	if e != nil || stateEntry(before) != stateEntry(after) {
		return nil, ErrInventory
	}
	r.bind(path, after, raw)
	r.view.Files++
	return raw, nil
}

func (r *stateInventoryReader) framingOriginalRetainedC4(root *os.File, policy *retainedRootPolicy) error {
	p := sandbox.NewResultInspectionProjection()
	e := r.directory(root, "results", "results", sandbox.MaxResultRecords, func(dir *os.File, names []string) error {
		// Reject the entire bounded namespace BEFORE opening any result payload.
		last := ""
		for _, name := range names {
			if len(name) != 37 || name[32:] != ".json" || !requestPattern.MatchString(name[:32]) || name <= last {
				return ErrInventory
			}
			last = name
		}
		for _, name := range names {
			raw, e := r.framingOriginalFileC4(dir, name, "results/"+name, sandbox.MaxResultRecordBytes, false)
			if e != nil {
				return e
			}
			row, e := p.Add(name[:32], raw)
			if e != nil {
				return e
			}
			h := row.Reservation
			owner, ok := policy.owners[h.Ref]
			if !ok || owner.tenant != h.TenantID || owner.maxOutput != h.MaxOutputBytes {
				return ErrConflict
			}
		}
		return r.ctx.Err()
	})
	if e != nil {
		return e
	}
	policy.results, e = p.Observation()
	return e
}
