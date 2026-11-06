//go:build linux

package firecracker

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Root-only software test of the ordinary wrapper, NOT KVM/project-quota
// evidence. /run avoids weakening securePath for a world-writable /tmp.
func TestAssetCopyProductionWrapperRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ordinary trusted-path wrapper requires root-owned non-writable ancestors")
	}
	root, err := os.MkdirTemp("/run", "xandbox-asset-copy-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error("owned wrapper test directory removal failed", err)
		} else if _, err := os.Lstat(root); !os.IsNotExist(err) {
			t.Error("owned wrapper test directory still exists", err)
		}
	})
	input := make([]byte, 3*assetCopyBlockSize+7)
	input[9], input[2*assetCopyBlockSize+3] = 3, 8
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, input, 0600); err != nil {
		t.Fatal(err)
	}
	asset := Asset{Path: source, SHA256: assetCopyDigest(input)}
	before, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"first", "second"} {
		path := filepath.Join(root, name)
		if err := copyAsset(context.Background(), asset, path); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0444 || os.SameFile(before, info) {
			t.Fatal("private staged inode/mode changed", info, err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		assetCopyCheck(t, f, input)
		f.Close()
		if err := copyAsset(context.Background(), asset, path); !os.IsExist(err) {
			t.Fatal("existing private file overwritten", err)
		}
	}
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	a, _ := os.Stat(first)
	b, _ := os.Stat(second)
	if os.SameFile(a, b) {
		t.Fatal("copies share an inode")
	}
	if err := os.Chmod(first, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{source, second} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, input) {
			t.Fatal("source/neighbor changed", err)
		}
	}
	after, err := os.Stat(source)
	if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() || before.Mode() != after.Mode() {
		t.Fatal("source metadata mutated", err)
	}
	link := filepath.Join(root, "destination-link")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if err := copyAsset(context.Background(), asset, link); !os.IsExist(err) {
		t.Fatal("destination symlink followed", err)
	}
	asset.SHA256 = assetCopyDigest([]byte("wrong"))
	failed := filepath.Join(root, "failed")
	if err := copyAsset(context.Background(), asset, failed); err == nil || err.Error() != "staged image digest mismatch" {
		t.Fatal("incorrect digest accepted", err)
	}
	info, err := os.Stat(failed)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("failed copy published or removed outside GC", info, err)
	}
}
