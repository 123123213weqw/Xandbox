//go:build linux

package installtxn

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func sequentialErrorEqual(a, b error) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	// Include the full private stage/ambiguity payload and underlying errno,
	// not merely whether both calls rejected an input.
	return reflect.DeepEqual(a, b) && a.Error() == b.Error()
}

func sequentialOwnedFS(t *testing.T) (*filesystem, string) {
	t.Helper()
	root := t.TempDir()
	if e := os.MkdirAll(filepath.Join(root, "a", "b"), 0700); e != nil {
		t.Fatal(e)
	}
	in, e := os.Open(root)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { in.Close() })
	return &filesystem{root: in}, root
}

func sequentialCompareDirectory(t *testing.T, f *filesystem, path string, success bool) {
	t.Helper()
	before, e := f.root.Seek(0, 1)
	if e != nil {
		t.Fatal(e)
	}
	want, old := f.originalSequentialDirectory147(path)
	got, err := f.directory(path)
	if !sequentialErrorEqual(old, err) || (got != nil) != (want != nil) || (err == nil) != success {
		if want != nil {
			want.Close()
		}
		if got != nil {
			got.Close()
		}
		t.Fatalf("original directory result/error differs: %q: %v / %v", path, old, err)
	}
	if got != nil {
		var a, b unix.Stat_t
		if unix.Fstat(int(want.Fd()), &a) != nil || unix.Fstat(int(got.Fd()), &b) != nil || stateEntry(a) != stateEntry(b) {
			t.Fatal("different original directory inode or metadata")
		}
		for _, in := range []*os.File{want, got} {
			fd := int(in.Fd())
			flags, e := unix.FcntlInt(in.Fd(), unix.F_GETFD, 0)
			if e != nil || flags&unix.FD_CLOEXEC == 0 || in.Name() != "install-directory" {
				t.Fatal("descriptor flags/name changed", e)
			}
			if e = in.Close(); e != nil || !errors.Is(unix.Fstat(fd, &a), unix.EBADF) {
				t.Fatal("returned descriptor did not close independently", e)
			}
		}
	}
	after, e := f.root.Seek(0, 1)
	if e != nil || before != after {
		t.Fatal("retained root description offset changed", e)
	}
}

func TestRuntimeFileSequentialDirectoryOriginalAnchoring(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		success    bool
	}{
		{"one", "/a", true}, {"nested", "/a/b", true}, {"missing", "/absent", false},
		{"missing-middle", "/absent/b", false}, {"file-leaf", "/regular", false}, {"file-middle", "/regular/b", false},
		{"link-leaf", "/link", false}, {"link-middle", "/link/b", false}, {"link-escape", "/escape", false},
		{"writable-leaf", "/writable", false}, {"writable-middle", "/writable/b", false}, {"sticky", "/sticky", false},
		{"empty", "", false}, {"root", "/", false}, {"relative", "a/b", false}, {"dot", "/a/./b", false},
		{"parent", "/a/../a", false}, {"double-slash", "/a//b", false}, {"trailing-slash", "/a/b/", false},
		{"nul", "/a\x00", false}, {"unicode", "/a/é", false}, {"newline", "/a\n", false}, {"invalid-utf8", "/a\xff", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, root := sequentialOwnedFS(t)
			if e := os.WriteFile(root+"/regular", []byte("owned"), 0600); e != nil {
				t.Fatal(e)
			}
			for _, link := range []struct{ name, target string }{{"link", "a"}, {"escape", root}} {
				if e := os.Symlink(link.target, root+"/"+link.name); e != nil {
					t.Fatal(e)
				}
			}
			for _, name := range []string{"writable", "sticky"} {
				if e := os.MkdirAll(root+"/"+name+"/b", 0700); e != nil {
					t.Fatal(e)
				}
				mode := os.FileMode(0777)
				if name == "sticky" {
					mode = 0700 | os.ModeSticky
				}
				if e := os.Chmod(root+"/"+name, mode); e != nil {
					t.Fatal(e)
				}
			}
			sequentialCompareDirectory(t, f, tc.path, tc.success)
		})
	}
}

func TestRuntimeFileSequentialDirectoryFreshRebind(t *testing.T) {
	f, root := sequentialOwnedFS(t)
	first, e := f.directory("/a/b")
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close() // Keep old inode alive to exclude inode-number reuse.
	var before unix.Stat_t
	if e = unix.Fstat(int(first.Fd()), &before); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(root+"/a/b", root+"/a/old"); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(root+"/a/b", 0700); e != nil {
		t.Fatal(e)
	}
	sequentialCompareDirectory(t, f, "/a/b", true)
	second, e := f.directory("/a/b")
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	var after unix.Stat_t
	if e = unix.Fstat(int(second.Fd()), &after); e != nil || before.Ino == after.Ino && before.Dev == after.Dev {
		t.Fatal("path component was cached across calls", e)
	}
	// Detaching/replacing the physical root path must not re-anchor either
	// implementation away from its original retained directory description.
	detached := root + "-detached"
	if e = os.Rename(root, detached); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(detached) })
	if e = os.MkdirAll(root+"/replacement", 0700); e != nil {
		t.Fatal(e)
	}
	sequentialCompareDirectory(t, f, "/a/b", true)
	sequentialCompareDirectory(t, f, "/replacement", false)
	if e = f.root.Close(); e != nil {
		t.Fatal(e)
	}
	if e = unix.Fstat(int(second.Fd()), &after); e != nil {
		t.Fatal("returned directory borrowed original root descriptor", e)
	}
	oldFile, old := f.originalSequentialDirectory147("/a/b")
	newFile, err := f.directory("/a/b")
	if oldFile != nil || newFile != nil || !sequentialErrorEqual(old, err) || err == nil {
		t.Fatal("closed original root error differs", old, err)
	}
}

// Compare mutations without repairing, normalizing or sharing a decoded view.
// Raw bytes (including NUL and invalid UTF-8) reach both actual caller parsers.
func sequentialEveryByte(t *testing.T, seed []byte, compare func([]byte) bool) {
	t.Helper()
	for _, pos := range []int{0, len(seed) / 2, len(seed) - 1} {
		for b := 0; b < 256; b++ {
			raw := append([]byte(nil), seed...)
			raw[pos] = byte(b)
			if !compare(raw) {
				t.Fatalf("caller diverged at position %d byte %d", pos, b)
			}
		}
	}
}

func sequentialObservationEqual(raw []byte) bool {
	a, x := originalSequentialParseObservation147(raw)
	b, y := parseObservation(raw)
	return a == b && sequentialErrorEqual(x, y)
}

func TestRuntimeFileSequentialObservationMatchesOriginal(t *testing.T) {
	seed := "LoadState=loaded\nActiveState=active\nFragmentPath=/owned/main.service\nDropInPaths=\nUnitFileState=enabled\nMainPID=42\n"
	for _, tc := range []struct{ name, raw string }{
		{"valid", seed}, {"no-final-newline", strings.TrimSuffix(seed, "\n")}, {"empty", ""}, {"extra-newline", seed + "\n"},
		{"duplicate", seed + "MainPID=42\n"}, {"empty-duplicate", seed + "DropInPaths=\n"}, {"unknown", seed + "Other=0\n"},
		{"missing", strings.Replace(seed, "MainPID=42\n", "", 1)}, {"leading-zero", strings.Replace(seed, "MainPID=42", "MainPID=042", 1)},
		{"negative", strings.Replace(seed, "MainPID=42", "MainPID=-1", 1)}, {"overflow", strings.Replace(seed, "MainPID=42", "MainPID=18446744073709551616", 1)},
		{"crlf", strings.ReplaceAll(seed, "\n", "\r\n")}, {"nul", strings.Replace(seed, "loaded", "lo\x00aded", 1)},
		{"equal-value", strings.Replace(seed, "loaded", "load=ed", 1)}, {"limit", strings.Replace(seed, "loaded", strings.Repeat("a", 16384-len(seed)+6), 1)},
		{"over-limit", strings.Repeat("a", 16385)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !sequentialObservationEqual([]byte(tc.raw)) {
				t.Fatal("original observation value/partial-value/error differs")
			}
			if tc.name == "valid" || tc.name == "limit" {
				if _, e := parseObservation([]byte(tc.raw)); e != nil || tc.name == "limit" && len(tc.raw) != 16384 {
					t.Fatal("valid/exact-limit positive control refused", e)
				}
			}
		})
	}
	sequentialEveryByte(t, []byte(seed), sequentialObservationEqual)
}

func sequentialIngressEqual(raw []byte) bool {
	return sequentialErrorEqual(originalSequentialParseIngressEmptyEvents147(raw), parseIngressEmptyEvents(raw))
}

func TestRuntimeFileSequentialIngressMatchesOriginal(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"valid", "populated 0\nfrozen 0\n"}, {"reordered", "frozen 0\npopulated 0\n"}, {"empty", ""},
		{"no-final-newline", "populated 0\nfrozen 0"}, {"blank", "populated 0\n\nfrozen 0\n"}, {"populated", "populated 1\nfrozen 0\n"},
		{"frozen", "populated 0\nfrozen 1\n"}, {"duplicate", "populated 0\npopulated 0\nfrozen 0\n"}, {"unknown", "populated 0\nother 0\n"},
		{"missing", "populated 0\n"}, {"extra-column", "populated 0 0\nfrozen 0\n"}, {"crlf", "populated 0\r\nfrozen 0\r\n"},
		{"nul", "populated 0\x00\nfrozen 0\n"}, {"unicode-space", "populated\u20030\nfrozen\t0\n"},
		{"limit", "populated" + strings.Repeat(" ", 4076) + "0\nfrozen 0\n"}, {"over-limit", strings.Repeat(" ", 4097)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !sequentialIngressEqual([]byte(tc.raw)) {
				t.Fatal("original empty-events error differs")
			}
			if tc.name == "valid" || tc.name == "limit" {
				if e := parseIngressEmptyEvents([]byte(tc.raw)); e != nil || tc.name == "limit" && len(tc.raw) != 4096 {
					t.Fatal("valid/exact-limit events control refused", e)
				}
			}
		})
	}
	sequentialEveryByte(t, []byte("populated 0\nfrozen 0\n"), sequentialIngressEqual)
}

func sequentialLockEqual(raw []byte) bool {
	id := runtimeStateIdentity{LockDevice: unix.Mkdev(8, 1), LockInode: 123}
	return sequentialErrorEqual(originalSequentialStateKernelLockOwner147(raw, id, 42), stateKernelLockOwner(raw, id, 42)) &&
		sequentialErrorEqual(originalSequentialStateKernelLockVeto147(raw, id, 42), stateKernelLockVeto(raw, id, 42))
}

func TestRuntimeFileSequentialLockMatchesOriginal(t *testing.T) {
	row := "1: FLOCK ADVISORY WRITE 42 08:01:123 0 EOF\n"
	for _, tc := range []struct{ name, raw string }{
		{"original", row}, {"empty", ""}, {"no-final-newline", strings.TrimSuffix(row, "\n")}, {"blank", row + "\n"},
		{"same-text", row + row}, {"same-ordinal", row + strings.Replace(row, "08:01", "8:1", 1)},
		{"different-ordinal", row + strings.Replace(row, "1:", "2:", 1)}, {"three", row + row + row}, {"many", strings.Repeat(row, 5)},
		{"unrelated", strings.Replace(row, ":123", ":124", 1)}, {"unrelated-then-original", strings.Replace(row, ":123", ":124", 1) + row},
		{"foreign-pid", strings.Replace(row, " 42 ", " 43 ", 1)}, {"waiter", strings.Replace(row, "FLOCK", "-> FLOCK", 1)},
		{"posix", strings.Replace(row, "FLOCK", "POSIX", 1)}, {"read", strings.Replace(row, "WRITE", "READ", 1)},
		{"range-start", strings.Replace(row, " 0 EOF", " 1 EOF", 1)}, {"range-end", strings.Replace(row, " EOF", " 10", 1)},
		{"bad-device", strings.Replace(row, "08:01:123", "bad", 1)}, {"inode-overflow", strings.Replace(row, ":123", ":18446744073709551616", 1)},
		{"major-overflow", strings.Replace(row, "08:", "100000000:", 1)}, {"nul", strings.Replace(row, "FLOCK", "FLO\x00CK", 1)},
		{"crlf", strings.ReplaceAll(row, "\n", "\r\n")}, {"tab", strings.ReplaceAll(row, " ", "\t")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !sequentialLockEqual([]byte(tc.raw)) {
				t.Fatal("original lock stage/ambiguity/errno differs")
			}
			if tc.name == "original" {
				id := runtimeStateIdentity{LockDevice: unix.Mkdev(8, 1), LockInode: 123}
				if stateKernelLockOwner([]byte(tc.raw), id, 42) != nil || stateKernelLockVeto([]byte(tc.raw), id, 42) != nil {
					t.Fatal("original owner/negative-veto positive controls refused")
				}
			}
		})
	}
	sequentialEveryByte(t, []byte(row), sequentialLockEqual)
	corpus := rand.New(rand.NewSource(1472112))
	for n := 0; n < 512; n++ {
		b := make([]byte, corpus.Intn(256))
		for i := range b {
			b[i] = byte(corpus.Intn(256))
		}
		if !sequentialLockEqual(b) || !sequentialIngressEqual(b) || !sequentialObservationEqual(b) {
			t.Fatal("original deterministic raw-byte parsers differ", n)
		}
	}
}

func TestRuntimeFileSequentialFreshConcurrentParsers(t *testing.T) {
	var wg sync.WaitGroup
	failures := make(chan error, 4)
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for repeat := 0; repeat < 64; repeat++ {
				// Every invocation gets fresh input, not a shared mutable fixture.
				obs := []byte(fmt.Sprintf("LoadState=loaded\nActiveState=active\nFragmentPath=\nDropInPaths=\nUnitFileState=enabled\nMainPID=%d\n", repeat))
				if !sequentialObservationEqual(obs) || !sequentialIngressEqual([]byte("populated 0\nfrozen 0\n")) || !sequentialLockEqual([]byte("1: FLOCK ADVISORY WRITE 42 08:01:123 0 EOF\n")) {
					failures <- errors.New("fresh concurrent caller differs")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
}
