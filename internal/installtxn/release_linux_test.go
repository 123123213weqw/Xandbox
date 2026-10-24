//go:build linux

package installtxn

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/releasestore"
)

func pieFixture() []byte {
	b := make([]byte, 272)
	copy(b, elfFixture())
	w := binary.LittleEndian
	w.PutUint16(b[16:], uint16(elf.ET_DYN))
	w.PutUint16(b[56:], 2)
	w.PutUint64(b[24:], 0x4000b0)
	w.PutUint64(b[72:], 176)
	w.PutUint64(b[80:], 0x4000b0)
	w.PutUint64(b[96:], 96)
	w.PutUint64(b[104:], 96)
	w.PutUint32(b[120:], uint32(elf.PT_DYNAMIC))
	w.PutUint32(b[124:], uint32(elf.PF_R))
	w.PutUint64(b[128:], 208)
	w.PutUint64(b[136:], 0x4000d0)
	w.PutUint64(b[152:], 64)
	w.PutUint64(b[160:], 64)
	w.PutUint64(b[168:], 8)
	w.PutUint64(b[208:], uint64(elf.DT_FLAGS_1))
	w.PutUint64(b[216:], 0x08000000)
	return b
}
func TestStaticPIEOnlyForVMMRolesAndNoHiddenDependencies(t *testing.T) {
	for _, role := range roles {
		if !executable(role) {
			continue
		}
		t.Run(role, func(t *testing.T) {
			p := t.TempDir() + "/elf"
			b := pieFixture()
			if e := os.WriteFile(p, b, 0600); e != nil {
				t.Fatal(e)
			}
			in, e := os.Open(p)
			if e != nil {
				t.Fatal(e)
			}
			defer in.Close()
			e = staticArtifact(in, int64(len(b)), role)
			if (e == nil) != (role == "firecracker" || role == "jailer") {
				t.Fatal("role-bound static PIE mismatch", e)
			}
		})
	}
	for _, tag := range []uint64{uint64(elf.DT_NEEDED), uint64(elf.DT_RPATH), uint64(elf.DT_RUNPATH), 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff} {
		b := pieFixture()
		binary.LittleEndian.PutUint64(b[224:], tag)
		binary.LittleEndian.PutUint64(b[232:], 1)
		p := t.TempDir() + "/elf"
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		in, e := os.Open(p)
		if e != nil {
			t.Fatal(e)
		}
		e = staticArtifact(in, int64(len(b)), "firecracker")
		in.Close()
		if e == nil {
			t.Fatal("sectionless dependency/loader tag accepted", tag)
		}
	}
	for _, kind := range []string{"no-pie-flag", "interpreter", "truncated-dynamic", "unterminated-dynamic"} {
		b := pieFixture()
		w := binary.LittleEndian
		switch kind {
		case "no-pie-flag":
			w.PutUint64(b[216:], 0)
		case "interpreter":
			w.PutUint32(b[120:], uint32(elf.PT_INTERP))
		case "truncated-dynamic":
			w.PutUint64(b[152:], 63)
		case "unterminated-dynamic":
			for i := 208; i < len(b); i += 16 {
				w.PutUint64(b[i:], uint64(elf.DT_FLAGS_1))
				w.PutUint64(b[i+8:], 0x08000000)
			}
		}
		p := t.TempDir() + "/elf"
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		in, e := os.Open(p)
		if e != nil {
			t.Fatal(e)
		}
		e = staticArtifact(in, int64(len(b)), "jailer")
		in.Close()
		if e == nil {
			t.Fatal("invalid static PIE accepted", kind)
		}
	}
}

func TestExplicitPinnedStaticPIEDataFiles(t *testing.T) {
	dir := os.Getenv("XANDBOX_TEST_STATIC_PIE_DATA")
	if dir == "" {
		t.Skip("explicit readonly VMM data parser control, not execution")
	}
	pins := map[string]string{"firecracker": "99ad0f5cd0514a88aad0e9ae8cfdb3cc3b4ab9d190e1194602406c786b5de7a5", "jailer": "65ef226e96f0ceda55ba643f445801ef2cc0ea667ef67cad8ac4f406c9c8434f"}
	for role, pin := range pins {
		in, e := os.Open(dir + "/" + role)
		if e != nil {
			t.Fatal(e)
		}
		defer in.Close()
		st, e := in.Stat()
		if e != nil {
			t.Fatal(e)
		}
		sum, e := hashFile(context.Background(), in, st.Size())
		if e != nil || sum != pin {
			t.Fatal("pinned fixture byte mismatch", e)
		}
		if e = staticProgram(in, st.Size()); e == nil {
			t.Fatal("ET_EXEC service-only rule unexpectedly accepts this static PIE")
		}
		if e = staticArtifact(in, st.Size(), role); e != nil {
			t.Fatal("actual pinned native static PIE rejected", role, e)
		}
		if e = staticArtifact(in, st.Size(), "daemon"); e == nil {
			t.Fatal("Go service ELF requirement relaxed")
		}
	}
}

// A structural parser fixture, never executed and not proof of a usable VMM.
func elfFixture() []byte {
	b := make([]byte, 152)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	w := binary.LittleEndian
	w.PutUint16(b[16:], uint16(elf.ET_EXEC))
	machine := elf.EM_X86_64
	if runtime.GOARCH == "arm64" {
		machine = elf.EM_AARCH64
	}
	w.PutUint16(b[18:], uint16(machine))
	w.PutUint32(b[20:], 1)
	w.PutUint64(b[24:], 0x400078)
	w.PutUint64(b[32:], 64)
	w.PutUint16(b[52:], 64)
	w.PutUint16(b[54:], 56)
	w.PutUint16(b[56:], 1)
	w.PutUint32(b[64:], uint32(elf.PT_LOAD))
	w.PutUint32(b[68:], uint32(elf.PF_R|elf.PF_X))
	w.PutUint64(b[72:], 120)
	w.PutUint64(b[80:], 0x400078)
	w.PutUint64(b[96:], 32)
	w.PutUint64(b[104:], 32)
	w.PutUint64(b[112:], 4096)
	return b
}

func releaseFixture(t *testing.T, f *filesystem, script bool) Release {
	t.Helper()
	r := Release{Version: 1, SourceRevision: strings.Repeat("a", 40), Toolchain: "go1.27.3", GOARCH: runtime.GOARCH}
	base := f.root.Name() + "/release-staging"
	if e := os.Mkdir(base, 0700); e != nil {
		t.Fatal(e)
	}
	for _, role := range roles {
		b := []byte("model-asset")
		mode := os.FileMode(0400)
		if executable(role) {
			b = elfFixture()
			mode = 0500
		}
		if role == "daemon" && script {
			b = []byte("#!/bin/sh\nexit 0\n")
		}
		path := base + "/" + role
		if e := os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
		if role == "workspace" {
			if e := os.Truncate(path, 128<<20); e != nil {
				t.Fatal(e)
			}
		}
		in, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		st, e := in.Stat()
		if e != nil {
			t.Fatal(e)
		}
		sum, e := hashFile(context.Background(), in, st.Size())
		in.Close()
		if e != nil {
			t.Fatal(e)
		}
		r.Files = append(r.Files, Artifact{role, sum, st.Size()})
		if e = os.Chmod(path, mode); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(base+"/manifest.json", encode(r), 0400); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(base, f.root.Name()+releasestore.Root+"/objects/"+digest(encode(r))); e != nil {
		t.Fatal(e)
	}
	return r
}
func TestReleaseConsumerUsesPublisherLockAndValidatesRetainedBytes(t *testing.T) {
	for _, kind := range []string{"valid", "script", "previous-script", "missing-original-lock", "changed-bytes", "wrong-reference", "unknown-object", "held-original-lock"} {
		t.Run(kind, func(t *testing.T) {
			f, _, _ := fixture(t)
			base := f.root.Name() + releasestore.Root
			if e := os.MkdirAll(base+"/objects", 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(base+"/.lock", nil, 0600); e != nil {
				t.Fatal(e)
			}
			r := releaseFixture(t, f, kind == "script")
			p := samplePlan()
			p.Release = digest(encode(r))
			ref := releasestore.Reference{Version: 1, Revision: 1, Release: p.Release, RequestID: request(), IntentSHA256: strings.Repeat("a", 64)}
			if kind == "previous-script" {
				previous := releaseFixture(t, f, true)
				ref.Revision, ref.ExpectedRevision, ref.Previous = 2, 1, digest(encode(previous))
				p.ReleaseRevision = 2
			}
			if e := os.WriteFile(base+"/ref.json", encode(ref), 0600); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "missing-original-lock":
				if e := os.Remove(base + "/.lock"); e != nil {
					t.Fatal(e)
				}
			case "changed-bytes":
				path := base + "/objects/" + p.Release + "/kernel"
				if e := os.Chmod(path, 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(path, []byte("changed"), 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.Chmod(path, 0400); e != nil {
					t.Fatal(e)
				}
			case "wrong-reference":
				p.ReleaseRevision++
			case "unknown-object":
				if e := os.Mkdir(base+"/objects/foreign", 0700); e != nil {
					t.Fatal(e)
				}
			}
			ctx := context.Background()
			if kind == "held-original-lock" {
				unlock, e := f.lock(ctx, releasestore.Root+"/.lock", true)
				if e != nil {
					t.Fatal(e)
				}
				defer unlock()
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
				defer cancel()
			}
			view, e := f.release(ctx, p, false)
			if view != nil {
				defer view.close()
			}
			if (e == nil) != (kind == "valid") {
				t.Fatal("release validation mismatch", e)
			}
			if kind == "valid" && len(view.sources) != 13 {
				t.Fatal("incomplete retained release")
			}
			if kind == "missing-original-lock" {
				if _, e = os.Lstat(base + "/.lock"); !os.IsNotExist(e) {
					t.Fatal("reader replaced publisher lock")
				}
			}
		})
	}
}
func TestNativeStaticConsumerRejectsInterpreterAndMalformedELF(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"native":              func(b []byte) []byte { return b },
		"script":              func([]byte) []byte { return []byte("#!/bin/sh\nexit 0\n") },
		"truncated":           func(b []byte) []byte { return b[:80] },
		"wrong-machine":       func(b []byte) []byte { binary.LittleEndian.PutUint16(b[18:], uint16(elf.EM_MIPS)); return b },
		"pie":                 func(b []byte) []byte { binary.LittleEndian.PutUint16(b[16:], uint16(elf.ET_DYN)); return b },
		"interpreter":         func(b []byte) []byte { binary.LittleEndian.PutUint32(b[64:], uint32(elf.PT_INTERP)); return b },
		"no-load":             func(b []byte) []byte { binary.LittleEndian.PutUint16(b[56:], 0); return b },
		"no-executable-entry": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[68:], uint32(elf.PF_R)); return b },
		"entry-in-bss":        func(b []byte) []byte { binary.LittleEndian.PutUint64(b[24:], 0x4000a0); return b },
		"beyond-file":         func(b []byte) []byte { binary.LittleEndian.PutUint64(b[96:], 33); return b },
		"size-overflow":       func(b []byte) []byte { binary.LittleEndian.PutUint64(b[80:], ^uint64(0)-10); return b },
		"bad-alignment":       func(b []byte) []byte { binary.LittleEndian.PutUint64(b[112:], 4095); return b },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			b := change(elfFixture())
			path := t.TempDir() + "/fixture"
			if e := os.WriteFile(path, b, 0600); e != nil {
				t.Fatal(e)
			}
			in, e := os.Open(path)
			if e != nil {
				t.Fatal(e)
			}
			defer in.Close()
			e = staticProgram(in, int64(len(b)))
			if (e == nil) != (name == "native") {
				t.Fatal("structural ELF policy mismatch", e)
			}
			if _, e = hashFile(context.Background(), in, int64(len(b))); e != nil {
				t.Fatal("parser closed caller FD", e)
			}
		})
	}
}
