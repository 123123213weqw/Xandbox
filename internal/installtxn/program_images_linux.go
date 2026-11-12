//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"io"

	"golang.org/x/sys/unix"
)

// A per-call metadata reader, NOT a byte/hash cache or source-FD owner. The
// new parser envelope is 32 KiB of actual metadata reads per program, including
// repeated parser requests. This does not enlarge any existing IO/FD/host cap;
// an eventual file consumer must still charge all work to its original budget.
type runtimeImageReader struct {
	ctx        context.Context
	input      io.ReaderAt
	size, left int64
	pins       [2]runtimeImagePin
	pinCount   int
}

type runtimeImagePin struct {
	off int64
	raw [64]byte
}

func (r *runtimeImageReader) ReadAt(p []byte, off int64) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	if off < 0 || off > r.size || int64(len(p)) > r.size-off || int64(len(p)) > r.left {
		return 0, ErrInventory
	}
	r.left -= int64(len(p)) // Charge requests even when the underlying read fails.
	n, e := r.input.ReadAt(p, off)
	if n < 0 || n > len(p) {
		return 0, ErrInventory
	}
	for i := 0; i < r.pinCount; i++ {
		pin := &r.pins[i]
		lo, hi := max(off, pin.off), min(off+int64(n), pin.off+64)
		if lo < hi && !bytes.Equal(p[lo-off:hi-off], pin.raw[lo-pin.off:hi-pin.off]) {
			return 0, ErrConflict
		}
	}
	if e == nil && n != len(p) {
		e = io.ErrUnexpectedEOF
	}
	return n, e
}

func runtimeImageRange(off, count, width uint64, size int64) bool {
	return size >= 0 && width > 0 && off <= uint64(size) && count <= (uint64(size)-off)/width
}

// Preflight bounds BEFORE debug/elf may allocate header or string tables.
// This new program-image contract supports canonical ELF64 table widths and
// at most 256 program/section headers, no extended table counts, and a plain
// section-name table <= MaxPlan. It does NOT claim that ELF shape proves a
// source build, reader ABI, usable executable or compatible persisted state.
func runtimeImagePreflight(r *runtimeImageReader) error {
	var h [64]byte
	if _, e := r.ReadAt(h[:], 0); e != nil {
		return e
	}
	r.pins[0], r.pinCount = runtimeImagePin{0, h}, 1
	w := binary.LittleEndian
	if string(h[:7]) != "\x7fELF\x02\x01\x01" || w.Uint16(h[52:]) != 64 {
		return ErrPolicy
	}
	phoff, shoff := w.Uint64(h[32:]), w.Uint64(h[40:])
	phnum, shnum, names := uint64(w.Uint16(h[56:])), uint64(w.Uint16(h[60:])), uint64(w.Uint16(h[62:]))
	if phnum < 1 || phnum > 256 || w.Uint16(h[54:]) != 56 || !runtimeImageRange(phoff, phnum, 56, r.size) {
		return ErrPolicy
	}
	if shnum == 0 {
		if shoff != 0 || names != 0 {
			return ErrPolicy // No extended counts hidden in section zero.
		}
		return nil
	}
	if shnum > 256 || shoff == 0 || w.Uint16(h[58:]) != 64 || names >= shnum || !runtimeImageRange(shoff, shnum, 64, r.size) {
		return ErrPolicy
	}
	// Read only the table that debug/elf would load as bytes. Other compressed
	// debug sections are not inflated by the shared static validator.
	if names != 0 {
		var s [64]byte
		if _, e := r.ReadAt(s[:], int64(shoff+names*64)); e != nil {
			return e
		}
		r.pins[1], r.pinCount = runtimeImagePin{int64(shoff + names*64), s}, 2
		bytes, off := w.Uint64(s[32:]), w.Uint64(s[24:])
		if w.Uint32(s[4:]) != uint32(elf.SHT_STRTAB) || w.Uint64(s[8:])&uint64(elf.SHF_COMPRESSED) != 0 || bytes > MaxPlan || !runtimeImageRange(off, bytes, 1, r.size) {
			return ErrPolicy
		}
	}
	return nil
}

func runtimeNativeProgram(ctx context.Context, input io.ReaderAt, size int64) error {
	if _, bounded := ctx.Deadline(); !bounded || input == nil || size < 64 || size > 64<<20 {
		return ErrPolicy
	}
	r := &runtimeImageReader{ctx: ctx, input: input, size: size, left: 32 << 10}
	if e := runtimeImagePreflight(r); e != nil {
		return e
	}
	// EXACT same native machine/class/type/load-entry/alignment/interpreter/
	// dynamic-import policy as the existing installed static Go-program reader.
	// This is never the Firecracker/jailer static-PIE role exception.
	if e := staticNativeReader(r, size, false); e != nil {
		return e
	}
	return ctx.Err()
}

// Additional read-only prerequisite under the authentic original Stop scope.
// Neither a successful return nor a serialized report is file-selection,
// execution, ABI/format/budget, ingress-release or reboot/rollback permission.
func (a *runtimeProgramApproval) validateNativePrograms(ctx context.Context) error {
	if a == nil || a.scope == nil {
		return ErrPolicy
	}
	s := a.scope
	if e := s.programApprovalPolicy(ctx, a.base, a.operation, &a.proof); e != nil {
		return e
	}
	return s.run(ctx, func(f *filesystem) error {
		if e := s.programApprovalSource(ctx, a.base, a.operation, &a.proof); e != nil {
			return e
		}
		current, e := f.inspectRuntimeProgramApproval(ctx, a.inputs)
		if e != nil {
			return e
		}
		if current != a.evidence {
			return ErrConflict
		}
		for _, in := range a.inputs {
			if e := runtimeNativeProgram(ctx, in.source, in.file.Bytes); e != nil {
				return e
			}
		}
		if e := f.point("runtime-program-images-before-final"); e != nil {
			return e
		}
		// NO injectable callback after this boundary. Reprove record identities,
		// revocation and every original FD after metadata IO, then original
		// source/WAL, SAME retained state FD and pidfd absence. No extra hash
		// pass/cache: full fresh hashes above plus original inode/ctime pins.
		_, authority, e := f.runtimeApprovalRecord(ctx, runtimeProgramAuthorityPath, false)
		if e != nil {
			return e
		}
		programs, e := runtimeProgramInputs(a.inputs)
		if e != nil {
			return e
		}
		path := runtimeProgramCertificateRoot + "/" + digest(encode(programs)) + ".json"
		_, certificate, e := f.runtimeApprovalRecord(ctx, path, true)
		if e != nil {
			return e
		}
		if authority != current.authority || certificate != current.certificate {
			return ErrConflict
		}
		for i, in := range a.inputs {
			var st unix.Stat_t
			if e := unix.Fstat(int(in.source.Fd()), &st); e != nil {
				return e
			}
			if stateEntry(st) != current.sources[i] {
				return ErrConflict
			}
		}
		return s.programApprovalSource(ctx, a.base, a.operation, &a.proof)
	})
}
