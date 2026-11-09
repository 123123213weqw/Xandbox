//go:build linux && xandbox_host_fixture

package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These controls read a fixed ELF as DATA. No target execution, tracefs mount,
// probe registration or live owned-L1 guard bypass occurs.
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
		t.Fatal("ordinary ELF open refused", err)
	}
	file := os.NewFile(uintptr(fd), "offline-probe-elf")
	defer file.Close()
	offsets, identity, err := prepareProbeFile(file)
	if err != nil || len(offsets) != 9 || identity == nil {
		t.Fatal("whole image, descriptor identity and nine exact instructions required", err)
	}
	current, err := file.Stat()
	if err != nil || !samePrepareExecutable(identity, current) {
		t.Fatal("verified descriptor identity lost", err)
	}
	raw := make([]byte, prepareTraceELFBytes)
	if _, err = io.ReadFull(io.NewSectionReader(file, 0, prepareTraceELFBytes), raw); err != nil {
		t.Fatal(err)
	}
	seen := make(map[uint64]bool)
	for i, offset := range offsets {
		p := prepareProbes()[i]
		expected, err := hex.DecodeString(p.opcode)
		if err != nil || seen[offset] || offset > uint64(len(raw))-uint64(len(expected)) || !bytes.Equal(raw[offset:offset+uint64(len(expected))], expected) {
			t.Fatal("duplicate, unbounded or incorrect instruction")
		}
		seen[offset] = true
	}
	// Deliberately isolate the structural layer from the WHOLE-image gate. A
	// change outside the selected code must still fail the gate used by tracing.
	t.Run("non-probe-byte-still-requires-whole-image-pin", func(t *testing.T) {
		changed := append([]byte(nil), raw...)
		f, err := elf.NewFile(bytes.NewReader(changed))
		if err != nil {
			t.Fatal(err)
		}
		section := f.Section(".go.buildinfo")
		if section == nil || section.Size < 33 {
			t.Fatal("expected bounded build info")
		}
		changed[section.Offset+32] ^= 1
		f.Close()
		if _, err = prepareProbeCore(changed); err != nil {
			t.Fatal("control unexpectedly broke selected code/symbols", err)
		}
		if _, err = prepareProbeImage(changed); err == nil {
			t.Fatal("non-probe image mutation accepted")
		}
	})
	for _, kind := range []string{"truncated", "appended", "instruction"} {
		t.Run("whole-image-"+kind, func(t *testing.T) {
			changed := append([]byte(nil), raw...)
			switch kind {
			case "truncated":
				changed = changed[:len(changed)-1]
			case "appended":
				changed = append(changed, 0)
			case "instruction":
				changed[offsets[0]] ^= 1
			}
			if bytes.Equal(changed, raw) {
				t.Fatal("negative did not mutate image")
			}
			if _, err := prepareProbeImage(changed); err == nil {
				t.Fatal("changed fixed image accepted")
			}
		})
	}
	for _, kind := range []string{"zero-size", "straddling-instruction", "object-not-function", "undefined", "overflow-size", "duplicate-symbol"} {
		t.Run("structural-symbol-"+kind, func(t *testing.T) {
			changed := append([]byte(nil), raw...)
			p := prepareProbes()[0]
			entry, other := prepareSymbolEntries(t, changed, p.symbol)
			switch kind {
			case "zero-size":
				binary.LittleEndian.PutUint64(changed[entry+16:], 0)
			case "straddling-instruction":
				value := binary.LittleEndian.Uint64(changed[entry+8:])
				binary.LittleEndian.PutUint64(changed[entry+16:], p.address-value+1)
			case "object-not-function":
				changed[entry+4] = changed[entry+4]&0xf0 | byte(elf.STT_OBJECT)
			case "undefined":
				binary.LittleEndian.PutUint16(changed[entry+6:], uint16(elf.SHN_UNDEF))
			case "overflow-size":
				binary.LittleEndian.PutUint64(changed[entry+16:], ^uint64(0))
			case "duplicate-symbol":
				copy(changed[other:other+24], changed[entry:entry+24])
			}
			if bytes.Equal(changed, raw) {
				t.Fatal("symbol negative did not mutate data")
			}
			if _, err := prepareProbeCore(changed); err == nil {
				t.Fatal("unsafe symbol metadata accepted", kind)
			}
		})
	}
	for _, kind := range []string{"wrong-machine", "dynamic-type", "interpreter", "dynamic-loader", "missing-execute", "writable-execute", "bss-only", "offset-overflow", "ambiguous-segment", "non-executable-section", "short-reader", "wrong-instruction"} {
		t.Run("structural-"+kind, func(t *testing.T) {
			f, err := elf.NewFile(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var text *elf.Prog
			for _, p := range f.Progs {
				if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 {
					text = p
					break
				}
			}
			if text == nil {
				t.Fatal("expected executable segment")
			}
			var reader io.ReaderAt = bytes.NewReader(raw)
			switch kind {
			case "wrong-machine":
				f.Machine = elf.EM_AARCH64
			case "dynamic-type":
				f.Type = elf.ET_DYN
			case "interpreter":
				f.Progs = append(f.Progs, &elf.Prog{ProgHeader: elf.ProgHeader{Type: elf.PT_INTERP}})
			case "dynamic-loader":
				f.Progs = append(f.Progs, &elf.Prog{ProgHeader: elf.ProgHeader{Type: elf.PT_DYNAMIC}})
			case "missing-execute":
				text.Flags &^= elf.PF_X
			case "writable-execute":
				text.Flags |= elf.PF_W
			case "bss-only":
				text.Filesz = 0
			case "offset-overflow":
				text.Off = ^uint64(0) - 1
			case "ambiguous-segment":
				duplicate := *text
				f.Progs = append(f.Progs, &duplicate)
			case "non-executable-section":
				f.Section(".text").Flags &^= elf.SHF_EXECINSTR
			case "short-reader":
				reader = shortPrepareReader{reader}
			case "wrong-instruction":
				changed := append([]byte(nil), raw...)
				changed[offsets[0]] ^= 1
				reader = bytes.NewReader(changed)
			}
			if _, err = prepareProbeOffsets(f, reader); err == nil {
				t.Fatal("unsafe structural control accepted", kind)
			}
		})
	}
	t.Log("fixed whole image and immutable descriptor identity, nine instructions and adversarial parser controls verified as DATA; no live trace claim")
}

func prepareProbeCore(raw []byte) ([]uint64, error) {
	f, e := elf.NewFile(bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return prepareProbeOffsets(f, bytes.NewReader(raw))
}
func prepareSymbolEntries(t *testing.T, raw []byte, name string) (int, int) {
	t.Helper()
	f, e := elf.NewFile(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	syms, e := f.Symbols()
	if e != nil {
		t.Fatal(e)
	}
	section := f.Section(".symtab")
	if section == nil || section.Entsize != 24 {
		t.Fatal("expected ELF64 symbol layout")
	}
	found, other := -1, -1
	for i, s := range syms {
		offset := int(section.Offset) + 24*(i+1) // debug/elf omits the mandatory NULL symbol.
		if offset < 0 || offset+24 > len(raw) {
			t.Fatal("unbounded symbol control")
		}
		if s.Name == name {
			if binary.LittleEndian.Uint64(raw[offset+8:]) != s.Value || binary.LittleEndian.Uint64(raw[offset+16:]) != s.Size {
				t.Fatal("wrong symbol entry control")
			}
			found = offset
		} else if other < 0 {
			other = offset
		}
	}
	if found < 0 || other < 0 {
		t.Fatal("missing symbol mutation control")
	}
	return found, other
}

type shortPrepareReader struct{ io.ReaderAt }

func (r shortPrepareReader) ReadAt(b []byte, offset int64) (int, error) {
	n, e := r.ReaderAt.ReadAt(b, offset)
	if e == nil && n > 0 {
		return n - 1, nil
	}
	return n, e
}

func TestPrepareProbeFileAndExecutableIdentityRefuseDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandboxd")
	if e := os.WriteFile(path, []byte("model"), 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if off, id, e := prepareProbeFile(f); e == nil || off != nil || id != nil {
		t.Fatal("wrong-sized file accepted")
	}
	before, e := f.Stat()
	if e != nil {
		t.Fatal(e)
	}
	after, e := f.Stat()
	if e != nil || !samePrepareExecutable(before, after) {
		t.Fatal("unchanged descriptor lost", e)
	}
	if samePrepareExecutable(nil, before) || samePrepareExecutable(before, nil) {
		t.Fatal("missing identity accepted")
	}
	for _, kind := range []string{"uid", "gid", "links", "ctime"} {
		copyStat := *before.Sys().(*syscall.Stat_t)
		switch kind {
		case "uid":
			copyStat.Uid++
		case "gid":
			copyStat.Gid++
		case "links":
			copyStat.Nlink++
		case "ctime":
			copyStat.Ctim.Nsec ^= 1
		}
		if samePrepareExecutable(before, prepareStatInfo{before, &copyStat}) {
			t.Fatal("changed executable identity accepted", kind)
		}
	}
	if e = os.Chmod(path, 0700); e != nil {
		t.Fatal(e)
	}
	after, e = f.Stat()
	if e != nil || samePrepareExecutable(before, after) {
		t.Fatal("mode drift accepted", e)
	}
	if e = os.Chtimes(path, time.Unix(1, 0), time.Unix(1, 0)); e != nil {
		t.Fatal(e)
	}
	after, e = f.Stat()
	if e != nil || samePrepareExecutable(before, after) {
		t.Fatal("timestamp drift accepted", e)
	}
	replacement := path + "-replacement"
	if e = os.WriteFile(replacement, []byte("model"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(replacement, path); e != nil {
		t.Fatal(e)
	}
	after, e = os.Stat(path)
	if e != nil || samePrepareExecutable(before, after) {
		t.Fatal("different inode accepted", e)
	}
	directory, e := os.Open(filepath.Dir(path))
	if e != nil {
		t.Fatal(e)
	}
	defer directory.Close()
	if off, id, e := prepareProbeFile(directory); e == nil || off != nil || id != nil {
		t.Fatal("directory accepted")
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	if off, id, e := prepareProbeFile(f); e == nil || off != nil || id != nil {
		t.Fatal("closed descriptor accepted")
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if e = unix.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	fd, e := unix.Open(fifo, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	pipe := os.NewFile(uintptr(fd), "nonblocking-data-fifo")
	defer pipe.Close()
	if off, id, e := prepareProbeFile(pipe); e == nil || off != nil || id != nil {
		t.Fatal("FIFO accepted")
	}
}

type prepareStatInfo struct {
	os.FileInfo
	stat *syscall.Stat_t
}

func (v prepareStatInfo) Sys() any { return v.stat }

func TestPrepareProbePinDoesNotRetargetFrozenObservers(t *testing.T) {
	if prepareTraceELFSHA != "64883c528ba1d574aaa082c24b136e4938717c13c6abc122afcbddbb3b6c2abe" || prepareTraceELFBytes != 12622263 {
		t.Fatal("fixed reviewed image drift")
	}
	if observerOrdinaryELFSHA != "5bfb2394f95a1b1c2f887b6e301357b92140586bde07448e3e09f2aa0ee3c11c" || observerOrdinaryELFSHA == prepareTraceELFSHA {
		t.Fatal("unqualified notification observer retargeted")
	}
}
