//go:build linux && xandbox_host_fixture

package main

import (
	"crypto/sha256"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// This opt-in test only reads a caller-supplied ELF. It does not register
// probes, mount tracefs, run the ELF, or bypass any live owned-L1 guards.
func TestPrepareProbePinnedOrdinaryELF(t *testing.T) {
	path := os.Getenv("XANDBOX_PREPARE_PROBE_ELF")
	if path == "" {
		t.Skip("explicit pinned ordinary ELF required for offline calibration")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "sandboxd" {
		t.Fatal("canonical ordinary ELF path required")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal("ordinary ELF open refused")
	}
	file := os.NewFile(uintptr(fd), "offline-probe-elf")
	defer file.Close()
	st, err := file.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 64<<20 {
		t.Fatal("bounded regular ordinary ELF required")
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.LimitReader(file, (64<<20)+1)); err != nil {
		t.Fatal("ordinary ELF hash read refused")
	}
	if fmt.Sprintf("%x", h.Sum(nil)) != prepareTraceELFSHA {
		t.Fatal("ordinary ELF does not match fixed probe target")
	}
	binary, err := elf.NewFile(file)
	if err != nil {
		t.Fatal("ordinary ELF parse refused")
	}
	offsets, err := prepareProbeOffsets(binary, file)
	if err != nil || len(offsets) != 9 {
		t.Fatal("nine exact native ELF symbols and instruction fingerprints required")
	}
	seen := make(map[uint64]bool)
	for _, offset := range offsets {
		if seen[offset] || offset >= uint64(st.Size()) {
			t.Fatal("duplicate or out-of-range probe instruction")
		}
		seen[offset] = true
	}
	t.Log("whole ELF SHA, nine symbol-contained offsets and exact instruction bytes verified; no live trace claim")
}
