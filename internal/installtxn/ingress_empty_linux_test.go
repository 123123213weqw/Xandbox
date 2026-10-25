//go:build linux

package installtxn

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRecoveryIngressEmptyEventsWholeSubtreeNotManagerPID(t *testing.T) {
	for _, raw := range []string{"populated 0\nfrozen 0\n", "frozen 0\npopulated 0\n"} {
		if e := parseIngressEmptyEvents([]byte(raw)); e != nil {
			t.Fatal("empty complete kernel report refused", e)
		}
	}
	for _, raw := range []string{"", "populated 0\n", "frozen 0\n", "populated 1\nfrozen 0\n", "populated 0\nfrozen 1\n", "populated 0\nfrozen 0", "populated 0\nfrozen 0\npopulated 0\n", "populated 0\nfrozen 0\nunknown 0\n", "populated 00\nfrozen 0\n", "populated 0\nfrozen 0\n\n", "populated 0\r\nfrozen 0\n", "populated 0\nfrozen 0\x00\n", strings.Repeat("x", maxIngressEvents+1)} {
		if parseIngressEmptyEvents([]byte(raw)) == nil {
			t.Fatal("nonempty/frozen/incomplete/unrecognized report accepted")
		}
	}
}

// Ordinary-filesystem MODELS exercise the walker, not kernel cgroup semantics.
// The production caller's mandatory real-cgroup2 check is tested separately.
func modelIngressGroup(t *testing.T, path string, events string) {
	t.Helper()
	if e := os.MkdirAll(path, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(path, "cgroup.events"), []byte(events), 0444); e != nil {
		t.Fatal(e)
	}
	// Match the kernel file mode even under the required private umask 077.
	if e := os.Chmod(filepath.Join(path, "cgroup.events"), 0444); e != nil {
		t.Fatal(e)
	}
}

func modelIngressProof(t *testing.T, path string, check func(int) error) error {
	t.Helper()
	g, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	return proveIngressSubtree(g, check)
}

func TestIngressSubtreeModelChecksEveryDescendant(t *testing.T) {
	for _, tc := range []struct {
		name, events string
		depth        int
		accept       bool
	}{
		{"empty-root", "populated 0\nfrozen 0\n", 0, true},
		{"empty-child", "populated 0\nfrozen 0\n", 1, true},
		{"empty-grandchild", "populated 0\nfrozen 0\n", 2, true},
		{"populated-child", "populated 1\nfrozen 0\n", 1, false},
		{"frozen-child-unfrozen-parent", "populated 0\nfrozen 1\n", 1, false},
		{"frozen-grandchild", "populated 0\nfrozen 1\n", 2, false},
		{"malformed-child", "populated 0\n", 1, false},
		{"oversized-child", strings.Repeat("x", maxIngressEvents+1), 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			modelIngressGroup(t, root, "populated 0\nfrozen 0\n")
			path := root
			for i := 0; i < tc.depth; i++ {
				path = filepath.Join(path, "child")
				modelIngressGroup(t, path, "populated 0\nfrozen 0\n")
			}
			if e := os.Chmod(filepath.Join(path, "cgroup.events"), 0600); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(filepath.Join(path, "cgroup.events"), []byte(tc.events), 0444); e != nil {
				t.Fatal(e)
			}
			if e := os.Chmod(filepath.Join(path, "cgroup.events"), 0444); e != nil {
				t.Fatal(e)
			}
			e := modelIngressProof(t, root, func(int) error { return nil })
			if (e == nil) != tc.accept {
				t.Fatal("subtree model result disagrees with contract", e)
			}
		})
	}
}

func TestIngressSubtreeModelRejectsUntrustedInventory(t *testing.T) {
	for _, kind := range []string{"missing-events", "event-symlink", "child-symlink", "fifo", "writable-directory", "writable-events", "wrong-filesystem"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			modelIngressGroup(t, root, "populated 0\nfrozen 0\n")
			child := filepath.Join(root, "child")
			modelIngressGroup(t, child, "populated 0\nfrozen 0\n")
			events := filepath.Join(child, "cgroup.events")
			check := func(int) error { return nil }
			var e error
			switch kind {
			case "missing-events":
				e = os.Remove(events)
			case "event-symlink":
				if e = os.Remove(events); e == nil {
					e = os.Symlink(filepath.Join(root, "cgroup.events"), events)
				}
			case "child-symlink":
				e = os.Symlink(child, filepath.Join(root, "link"))
			case "fifo":
				e = unix.Mkfifo(filepath.Join(child, "fifo"), 0600)
			case "writable-directory":
				e = os.Chmod(child, 0777)
			case "writable-events":
				e = os.Chmod(events, 0666)
			case "wrong-filesystem":
				check = cgroup2FD
			}
			if e != nil {
				t.Fatal(e)
			}
			if modelIngressProof(t, root, check) == nil {
				t.Fatal("untrusted subtree accepted")
			}
		})
	}
}

func TestIngressSubtreeModelBoundedTraversal(t *testing.T) {
	for _, kind := range []string{"nodes", "depth", "entries"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			modelIngressGroup(t, root, "populated 0\nfrozen 0\n")
			switch kind {
			case "nodes":
				for i := 0; i < maxIngressGroups; i++ {
					modelIngressGroup(t, filepath.Join(root, strconv.Itoa(i)), "populated 0\nfrozen 0\n")
				}
			case "depth":
				path := root
				for i := 0; i <= maxIngressDepth; i++ {
					path = filepath.Join(path, "child")
					modelIngressGroup(t, path, "populated 0\nfrozen 0\n")
				}
			case "entries":
				for i := 0; i < maxIngressEntries; i++ {
					if e := os.WriteFile(filepath.Join(root, "control"+strconv.Itoa(i)), nil, 0600); e != nil {
						t.Fatal(e)
					}
				}
			}
			if !errors.Is(modelIngressProof(t, root, func(int) error { return nil }), ErrInventory) {
				t.Fatal("unbounded subtree accepted")
			}
		})
	}
}

func TestIngressSubtreeModelDetectsInventoryAndInodeChanges(t *testing.T) {
	for _, kind := range []string{"new-child", "replaced-child", "replaced-events"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			modelIngressGroup(t, root, "populated 0\nfrozen 0\n")
			child := filepath.Join(root, "child")
			modelIngressGroup(t, child, "populated 0\nfrozen 0\n")
			target := child
			if kind == "replaced-events" {
				target = filepath.Join(child, "cgroup.events")
			}
			var pin unix.Stat_t
			if e := unix.Stat(target, &pin); e != nil {
				t.Fatal(e)
			}
			changed := false
			check := func(fd int) error {
				var current unix.Stat_t
				if e := unix.Fstat(fd, &current); e != nil {
					return e
				}
				if !changed && current.Dev == pin.Dev && current.Ino == pin.Ino {
					changed = true
					switch kind {
					case "new-child":
						modelIngressGroup(t, filepath.Join(root, "new-child"), "populated 0\nfrozen 0\n")
					case "replaced-child":
						if e := os.Rename(child, filepath.Join(root, "retired")); e != nil {
							return e
						}
						modelIngressGroup(t, child, "populated 0\nfrozen 0\n")
					case "replaced-events":
						if e := os.Rename(target, filepath.Join(child, "retired")); e != nil {
							return e
						}
						modelIngressGroup(t, child, "populated 0\nfrozen 0\n")
					}
				}
				return nil
			}
			if modelIngressProof(t, root, check) == nil || !changed {
				t.Fatal("inventory/inode change went undetected")
			}
		})
	}
}
func TestRecoveryIngressEmptyRequiresRealCgroup2EvenWhenUnitAbsent(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "unit-absent", true: "fake-events"}[present], func(t *testing.T) {
			f, _, _ := fixture(t)
			if present {
				dir := f.root.Name() + ingressCgroupParent + "/" + IngressUnit
				if e := os.MkdirAll(dir, 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(dir+"/cgroup.events", []byte("populated 0\nfrozen 0\n"), 0444); e != nil {
					t.Fatal(e)
				}
			}
			if e := f.ingressEmpty(); !errors.Is(e, ErrPlatform) {
				t.Fatal("ordinary shadow filesystem accepted as cgroup absence/emptiness", e)
			}
		})
	}
}
