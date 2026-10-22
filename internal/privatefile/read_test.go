package privatefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateFile(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "secret")
	if err := os.WriteFile(path, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if data, err := Read(path, 7); err != nil || string(data) != "private" {
		t.Fatalf("read: %q %v", data, err)
	}
	if _, err := Read(path, 6); err == nil {
		t.Fatal("oversized file accepted")
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(link, 100); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err := Read(base, 100); err == nil {
		t.Fatal("directory accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 100); err == nil {
		t.Fatal("public file accepted")
	}
	if _, err := Read(filepath.Join(base, "missing"), 100); err == nil {
		t.Fatal("missing file accepted")
	}
}
