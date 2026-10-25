//go:build linux

package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNodeInterfaceReaderCannotTraverseFollowSymlinkOrExceedBounds(t *testing.T) {
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "memory.max"), []byte("12345\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "large"), []byte(strings.Repeat("x", 4097)), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Join(dir, "memory.max"), filepath.Join(dir, "alias")); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	a := nodeAnchor{file: f, path: dir}
	if got, e := a.read("memory.max"); e != nil || got != "12345" {
		t.Fatal(got, e)
	}
	for _, name := range []string{"", ".", "..", "../memory.max", "/etc/passwd", "alias", "large"} {
		if _, e = a.read(name); e == nil {
			t.Fatal("unbounded node interface", name)
		}
	}
	if _, e = openNodeAnchor(dir, true); e == nil {
		t.Fatal("regular filesystem impersonated cgroup2")
	}
}
func TestNodeCanceledPreparationNeverTouchesFilesystemAndReturnsPermit(t *testing.T) {
	n := &nodeEnvelope{preparing: newPrepareGate(1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 100; i++ {
		if e := n.acquirePrepare(ctx); !errors.Is(e, context.Canceled) {
			t.Fatal("canceled prepare attempted inventory", e)
		}
	}
	if len(n.preparing.tokens) != 0 {
		t.Fatal("canceled preparation leaked node permit")
	}
	if e := (*nodeEnvelope)(nil).check(true); e != nil {
		t.Fatal("legacy nil policy altered")
	}
}
