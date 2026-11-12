//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// Structural bytes ONLY. Never executed, not a Go build/ABI or usable program.
func imageSectionsFixture() []byte {
	b := append(elfFixture(), make([]byte, 129)...)
	w := binary.LittleEndian
	w.PutUint64(b[40:], 152)
	w.PutUint16(b[58:], 64)
	w.PutUint16(b[60:], 2)
	w.PutUint16(b[62:], 1)
	w.PutUint32(b[220:], uint32(elf.SHT_STRTAB))
	w.PutUint64(b[240:], 280)
	w.PutUint64(b[248:], 1)
	return b
}

func TestRuntimeFileProgramImagesBoundedSharedNativePolicy(t *testing.T) {
	for _, kind := range []string{"native", "sections", "script", "truncated", "class", "byte-order", "ident-version", "header-version", "header-width", "machine", "PIE", "interpreter", "no-load", "nonexecuting-entry", "entry-in-bss", "beyond-file", "address-overflow", "alignment", "ph-count-zero", "ph-count-over", "ph-width", "ph-offset-overflow", "ph-table-truncated", "sh-count-over", "sh-extended", "sh-width", "sh-table-truncated", "sh-offset-zero", "sh-index-over", "section-name-compressed", "section-name-type", "section-name-size-over", "section-name-beyond", "malformed-section-name", "hidden-needed", "hidden-audit"} {
		t.Run(kind, func(t *testing.T) {
			b := elfFixture()
			w := binary.LittleEndian
			if kind == "sections" || strings.HasPrefix(kind, "sh-") || strings.HasPrefix(kind, "section-name") || kind == "malformed-section-name" {
				b = imageSectionsFixture()
			}
			switch kind {
			case "script":
				b = []byte("#!/bin/sh\nexit 0\n")
			case "truncated":
				b = b[:80]
			case "class":
				b[4] = 1
			case "byte-order":
				b[5] = 2
			case "ident-version":
				b[6] = 2
			case "header-version":
				w.PutUint32(b[20:], 2)
			case "header-width":
				w.PutUint16(b[52:], 65)
			case "machine":
				w.PutUint16(b[18:], uint16(elf.EM_MIPS))
			case "PIE":
				b = pieFixture()
			case "interpreter":
				w.PutUint32(b[64:], uint32(elf.PT_INTERP))
			case "no-load":
				w.PutUint32(b[64:], uint32(elf.PT_NOTE))
			case "nonexecuting-entry":
				w.PutUint32(b[68:], uint32(elf.PF_R))
			case "entry-in-bss":
				w.PutUint64(b[24:], 0x4000a0)
			case "beyond-file":
				w.PutUint64(b[96:], 33)
			case "address-overflow":
				w.PutUint64(b[80:], ^uint64(0)-10)
			case "alignment":
				w.PutUint64(b[112:], 4095)
			case "ph-count-zero":
				w.PutUint16(b[56:], 0)
			case "ph-count-over":
				w.PutUint16(b[56:], 257)
			case "ph-width":
				w.PutUint16(b[54:], 65535)
			case "ph-offset-overflow":
				w.PutUint64(b[32:], ^uint64(0))
			case "ph-table-truncated":
				w.PutUint64(b[32:], uint64(len(b)-55))
			case "sh-count-over":
				w.PutUint16(b[60:], 257)
			case "sh-extended":
				w.PutUint16(b[60:], 0)
			case "sh-width":
				w.PutUint16(b[58:], 65535)
			case "sh-table-truncated":
				w.PutUint64(b[40:], uint64(len(b)-127))
			case "sh-offset-zero":
				w.PutUint64(b[40:], 0)
			case "sh-index-over":
				w.PutUint16(b[62:], 65535)
			case "section-name-compressed":
				w.PutUint64(b[224:], uint64(elf.SHF_COMPRESSED))
			case "section-name-type":
				w.PutUint32(b[220:], uint32(elf.SHT_PROGBITS))
			case "section-name-size-over":
				w.PutUint64(b[248:], MaxPlan+1)
			case "section-name-beyond":
				w.PutUint64(b[240:], uint64(len(b)))
			case "malformed-section-name":
				w.PutUint32(b[216:], 2)
			case "hidden-needed", "hidden-audit":
				b = pieFixture()
				w.PutUint16(b[16:], uint16(elf.ET_EXEC))
				tag := uint64(elf.DT_NEEDED)
				if kind == "hidden-audit" {
					tag = 0x6ffffefc
				}
				w.PutUint64(b[224:], tag)
				w.PutUint64(b[232:], 1)
			}
			e := runtimeNativeProgram(programContext(t), bytes.NewReader(b), int64(len(b)))
			if (e == nil) != (kind == "native" || kind == "sections") {
				t.Fatal("bounded native structural policy mismatch", e)
			}
		})
	}
}

type imageReadProbe struct {
	data   []byte
	reads  int
	bytes  int
	change func([]byte, int64)
}

func (r *imageReadProbe) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	r.bytes += len(p)
	if r.change != nil {
		r.change(r.data, off)
	}
	return bytes.NewReader(r.data).ReadAt(p, off)
}

func TestRuntimeFileProgramImagesReaderBoundsAndAllocationPins(t *testing.T) {
	for _, kind := range []string{"exact-budget", "budget-exhausted", "negative-offset", "past-file", "cross-file", "cancelled", "unbounded", "size-small", "size-over", "header-rebound", "name-table-rebound"} {
		t.Run(kind, func(t *testing.T) {
			p := &imageReadProbe{data: imageSectionsFixture()}
			ctx, cancel := context.WithCancel(programContext(t))
			defer cancel()
			r := &runtimeImageReader{ctx: ctx, input: p, size: int64(len(p.data)), left: 32}
			var e error
			switch kind {
			case "exact-budget":
				_, e = r.ReadAt(make([]byte, 32), 0)
				if e != nil || r.left != 0 || p.reads != 1 || p.bytes != 32 {
					t.Fatal("exact budget failed", e)
				}
				return
			case "budget-exhausted":
				_, e = r.ReadAt(make([]byte, 33), 0)
			case "negative-offset":
				_, e = r.ReadAt(make([]byte, 1), -1)
			case "past-file":
				_, e = r.ReadAt(make([]byte, 1), int64(len(p.data)+1))
			case "cross-file":
				_, e = r.ReadAt(make([]byte, 2), int64(len(p.data)-1))
			case "cancelled":
				cancel()
				_, e = r.ReadAt(make([]byte, 1), 0)
			case "unbounded":
				e = runtimeNativeProgram(context.Background(), p, int64(len(p.data)))
			case "size-small":
				e = runtimeNativeProgram(ctx, p, 63)
			case "size-over":
				e = runtimeNativeProgram(ctx, p, 64<<20+1)
			case "header-rebound", "name-table-rebound":
				p.change = func(b []byte, off int64) {
					if kind == "header-rebound" && p.reads == 3 {
						binary.LittleEndian.PutUint16(b[56:], 65535)
					}
					if kind == "name-table-rebound" && off == 152 {
						binary.LittleEndian.PutUint64(b[248:], ^uint64(0))
					}
				}
				e = runtimeNativeProgram(ctx, p, int64(len(p.data)))
				if e == nil || p.bytes > 32<<10 || p.reads > 8 {
					t.Fatal("preflight/parser metadata race escaped allocation pins", e)
				}
				return
			}
			if e == nil || p.reads != 0 {
				t.Fatal("invalid request reached original reader", e)
			}
		})
	}
}

func TestRuntimeFileProgramImagesOriginalFDOffsetsAndShortReads(t *testing.T) {
	for _, kind := range []string{"valid", "closed", "short", "pre-cancelled"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir() + "/not-executed-structural-ELF"
			b := imageSectionsFixture()
			if e := os.WriteFile(path, b, 0600); e != nil {
				t.Fatal(e)
			}
			in, e := os.Open(path)
			if e != nil {
				t.Fatal(e)
			}
			defer in.Close()
			if _, e = in.Seek(17, io.SeekStart); e != nil {
				t.Fatal(e)
			}
			if kind == "closed" {
				in.Close()
			}
			if kind == "short" {
				if e = os.Truncate(path, 70); e != nil {
					t.Fatal(e)
				}
			}
			ctx, cancel := context.WithCancel(programContext(t))
			defer cancel()
			if kind == "pre-cancelled" {
				cancel()
			}
			e = runtimeNativeProgram(ctx, in, int64(len(b)))
			if (e == nil) != (kind == "valid") {
				t.Fatal("original FD validation mismatch", e)
			}
			if kind == "pre-cancelled" && !errors.Is(e, context.Canceled) {
				t.Fatal("cancellation lost", e)
			}
			if kind != "closed" {
				if off, e := in.Seek(0, io.SeekCurrent); e != nil || off != 17 {
					t.Fatal("borrowed FD closed or offset moved", off, e)
				}
			}
		})
	}
}

func TestRuntimeFileProgramImagesCurrentTestELFPolicyAndOffsets(t *testing.T) {
	// Actual current TEST ELF, not a shipping artifact/provenance/ABI claim.
	// CGO-free gates must accept its native static shape; a dynamic race image
	// remains subject to the original interpreter/import refusal, not an exemption.
	in, e := os.Open("/proc/self/exe")
	if e != nil {
		t.Fatal(e)
	}
	defer in.Close()
	st, e := in.Stat()
	if e != nil {
		t.Fatal(e)
	}
	want := staticProgram(in, st.Size()) == nil
	if os.Getenv("CGO_ENABLED") == "0" && !want {
		t.Fatal("current CGO-free test ELF is not native static")
	}
	if _, e = in.Seek(17, io.SeekStart); e != nil {
		t.Fatal(e)
	}
	if e = runtimeNativeProgram(programContext(t), in, st.Size()); (e == nil) != want {
		t.Fatal("bounded parser diverged on current actual test ELF", e)
	}
	if off, e := in.Seek(0, io.SeekCurrent); e != nil || off != 17 {
		t.Fatal("actual ELF descriptor closed or offset changed", off, e)
	}
}
