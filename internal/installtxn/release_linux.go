//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/123123213weqw/Xandbox/internal/releasestore"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

type releaseView struct {
	description Release
	artifact    map[string]Artifact
	sources     map[string]*os.File
	close       func()
}

// Hold the publisher's ORIGINAL lock inode, never a separate installer lock for
// that store. The selected committed reference cannot change during the copy.
func (f *filesystem) release(ctx context.Context, p Plan, pending bool) (*releaseView, error) {
	lock, e := f.open(releasestore.Root+"/.lock", unix.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	// The lock helper opens the same permanent inode with bounded waiting.
	unlock, e := flock(ctx, lock, true)
	if e != nil {
		return nil, e
	}
	view := &releaseView{artifact: map[string]Artifact{}, sources: map[string]*os.File{}}
	view.close = func() {
		for _, in := range view.sources {
			in.Close()
		}
		unlock()
	}
	ok := false
	defer func() {
		if !ok {
			view.close()
		}
	}()
	if e = f.privateDirectory(releasestore.Root, 0700); e != nil {
		return nil, e
	}
	if e = f.privateDirectory(releasestore.Root+"/objects", 0700); e != nil {
		return nil, e
	}
	names, e := f.names(releasestore.Root)
	if e != nil {
		return nil, e
	}
	if fmt.Sprint(names) != fmt.Sprint([]string{".lock", "objects", "ref.json"}) {
		return nil, ErrInventory
	}
	raw, e := f.read(releasestore.Root+"/ref.json", MaxPlan, 0600)
	if e != nil {
		return nil, e
	}
	var ref releasestore.Reference
	if strictjson.Decode(raw, &ref) != nil || !bytes.Equal(encode(ref), raw) || ref.Version != 1 || ref.Revision == 0 || ref.ExpectedRevision != ref.Revision-1 || !requestPattern.MatchString(ref.RequestID) || !digestPattern.MatchString(ref.IntentSHA256) || !digestPattern.MatchString(ref.Release) || (ref.Revision == 1 && ref.Previous != "") || (ref.Revision > 1 && (!digestPattern.MatchString(ref.Previous) || ref.Previous == ref.Release)) {
		return nil, ErrInventory
	}
	if (!pending && (ref.Revision != p.ReleaseRevision || ref.Release != p.Release)) || (pending && p.Release != ref.Release && p.Release != ref.Previous) {
		return nil, ErrConflict
	}
	expected := map[string]bool{ref.Release: true}
	if ref.Previous != "" {
		expected[ref.Previous] = true
	}
	ids, e := f.names(releasestore.Root + "/objects")
	if e != nil || len(ids) != len(expected) {
		return nil, ErrInventory
	}
	for _, id := range ids {
		if !expected[id] {
			return nil, ErrInventory
		}
		base := releasestore.Root + "/objects/" + id
		if e = f.privateDirectory(base, 0700); e != nil {
			return nil, e
		}
		raw, e = f.read(base+"/manifest.json", MaxPlan, 0400)
		if e != nil {
			return nil, e
		}
		var release Release
		if strictjson.Decode(raw, &release) != nil || digest(raw) != id || !bytes.Equal(raw, encode(release)) || release.GOARCH != runtime.GOARCH {
			return nil, ErrInventory
		}
		m := releasestore.Manifest{Version: release.Version, SourceRevision: release.SourceRevision, Toolchain: release.Toolchain, GOARCH: release.GOARCH}
		for _, a := range release.Files {
			m.Files = append(m.Files, releasestore.File{Role: a.Role, Source: "/release-source/" + a.Role, SHA256: a.SHA256, Bytes: a.Bytes})
		}
		normalized, e := releasestore.Decode(encode(m))
		if e != nil {
			return nil, ErrInventory
		}
		if len(normalized.Files) != len(roles) {
			return nil, ErrInventory
		}
		names, e = f.names(base)
		if e != nil || len(names) != len(roles)+1 {
			return nil, ErrInventory
		}
		if id == p.Release {
			view.description = release
		}
		for i, a := range release.Files {
			if a.Role != roles[i] {
				return nil, ErrInventory
			}
			mode := uint32(0400)
			if executable(a.Role) {
				mode = 0500
			}
			in, e := f.open(base+"/"+a.Role, unix.O_RDONLY, mode)
			if e != nil {
				return nil, e
			}
			sum, e := hashFile(ctx, in, a.Bytes)
			if e != nil || sum != a.SHA256 {
				in.Close()
				return nil, ErrInventory
			}
			if executable(a.Role) {
				if e = staticArtifact(in, a.Bytes, a.Role); e != nil {
					in.Close()
					return nil, e
				}
			} else if a.Role == "workspace" && a.Bytes != 128<<20 {
				in.Close()
				return nil, ErrPolicy
			}
			if id == p.Release {
				view.artifact[a.Role] = a
				view.sources[a.Role] = in
			} else {
				in.Close()
			}
		}
	}
	if len(view.artifact) != len(roles) {
		return nil, ErrInventory
	}
	ok = true
	return view, nil
}

// A staged role is data until the consumer verifies a native static executable.
// This rejects script/interpreter fallbacks, not a malicious trusted root's ELF.
func staticProgram(in *os.File, size int64) error {
	return staticNative(in, size, false)
}
func staticArtifact(in *os.File, size int64, role string) error {
	// The pinned Firecracker/jailer distributions are static PIE (ET_DYN), not
	// the ET_EXEC required by the existing Go service launchers. A role-specific
	// exception must still forbid interpreters and all shared-library imports.
	return staticNative(in, size, role == "firecracker" || role == "jailer")
}
func staticNative(in *os.File, size int64, allowPIE bool) error {
	if size < 64 || size > 64<<20 {
		return ErrPolicy
	}
	v, e := elf.NewFile(in)
	if e != nil {
		return ErrPolicy
	}
	defer v.Close()
	machine := elf.EM_X86_64
	if runtime.GOARCH == "arm64" {
		machine = elf.EM_AARCH64
	} else if runtime.GOARCH != "amd64" {
		return ErrPlatform
	}
	if (v.Type != elf.ET_EXEC && !(allowPIE && v.Type == elf.ET_DYN)) || v.Class != elf.ELFCLASS64 || v.Data != elf.ELFDATA2LSB || v.Machine != machine || len(v.Progs) < 1 || len(v.Progs) > 256 {
		return ErrPolicy
	}
	entry := false
	pie, dynamic := false, false
	for _, p := range v.Progs {
		if p.Type == elf.PT_INTERP {
			return ErrPolicy
		}
		if p.Type == elf.PT_DYNAMIC {
			if dynamic || p.Filesz == 0 || p.Filesz > 65536 || p.Filesz%16 != 0 || p.Off > uint64(size) || p.Filesz > uint64(size)-p.Off {
				return ErrPolicy
			}
			dynamic = true
			reader := p.Open()
			null := false
			for left := p.Filesz; left > 0; left -= 16 {
				var b [16]byte
				if _, e := io.ReadFull(reader, b[:]); e != nil {
					return ErrPolicy
				}
				tag, value := binary.LittleEndian.Uint64(b[:8]), binary.LittleEndian.Uint64(b[8:])
				if tag == uint64(elf.DT_NULL) {
					null = true
					break
				}
				switch tag {
				case uint64(elf.DT_NEEDED), uint64(elf.DT_RPATH), uint64(elf.DT_RUNPATH), 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff:
					// Includes DEPAUDIT/AUDIT/AUXILIARY/FILTER. Inspect the
					// program header, not optional section names a stripped
					// ELF can omit, so dependencies cannot be hidden there.
					return ErrPolicy
				case uint64(elf.DT_FLAGS_1):
					pie = pie || value&0x08000000 != 0 // DF_1_PIE
				}
			}
			if !null {
				return ErrPolicy
			}
		}
		if p.Type == elf.PT_LOAD {
			if p.Filesz > p.Memsz || p.Off > uint64(size) || p.Filesz > uint64(size)-p.Off || p.Memsz > ^uint64(0)-p.Vaddr || (p.Align > 1 && (p.Align&(p.Align-1) != 0 || p.Vaddr%p.Align != p.Off%p.Align)) {
				return ErrPolicy
			}
			if p.Flags&elf.PF_X != 0 && v.Entry >= p.Vaddr && v.Entry-p.Vaddr < p.Filesz {
				entry = true
			}
		}
	}
	if !entry || (v.Type == elf.ET_DYN && !pie) {
		return ErrPolicy
	}
	return nil
}
