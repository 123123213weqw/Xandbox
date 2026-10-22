//go:build linux || darwin

package privatefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureDirectoryRejectsWritableAncestorsBeforeCreatingAnything(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(parent, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "new", "state")
	if _, err := EnsureDirectory(target); err == nil {
		t.Fatal("writable ancestor accepted")
	}
	if _, err := os.Lstat(filepath.Join(parent, "new")); !os.IsNotExist(err) {
		t.Fatal("created child before validating ancestor", err)
	}
}

func TestEnsureDirectoryRejectsLeafAndUserSymlinksBeforeWrites(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureDirectory(link); err == nil {
		t.Fatal("leaf symlink accepted")
	}
	if os.Geteuid() != 0 { // Non-root user symlinks must not impersonate OS aliases.
		if _, err := EnsureDirectory(filepath.Join(link, "new")); err == nil {
			t.Fatal("user-owned ancestor symlink accepted")
		}
		if _, err := os.Stat(filepath.Join(target, "new")); !os.IsNotExist(err) {
			t.Fatal("symlink traversed during creation", err)
		}
	}
}

func TestEnsureDirectoryAllowsOwnedPrivateChildrenUnderTrustedStickyParent(t *testing.T) {
	root := t.TempDir()
	sticky := filepath.Join(root, "sticky")
	if err := os.Mkdir(sticky, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sticky, os.ModeSticky|0777); err != nil {
		t.Fatal(err)
	}
	path, err := EnsureDirectory(filepath.Join(sticky, "private", "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0700 || !ownedByCaller(info) {
		t.Fatal(info, err)
	}
	if _, err := EnsureDirectory(path); err != nil {
		t.Fatal("not idempotent", err)
	}
}

func TestRootRejectsForeignDirectoriesAndFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root; normal CI also covers non-root policy")
	}
	root := t.TempDir()
	foreign := filepath.Join(root, "foreign")
	if err := os.Mkdir(foreign, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(foreign, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureDirectory(filepath.Join(foreign, "new")); err == nil {
		t.Fatal("root trusted another UID's directory")
	}
	if _, err := os.Stat(filepath.Join(foreign, "new")); !os.IsNotExist(err) {
		t.Fatal("wrote under foreign directory", err)
	}
	file := filepath.Join(root, "foreign.json")
	if err := os.WriteFile(file, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(file, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(file, 1024); err == nil {
		t.Fatal("root accepted foreign-owned configuration")
	}
}
