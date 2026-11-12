//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"runtime/debug"
)

const resultModule = "github.com/123123213weqw/Xandbox"

// SAME-SOURCE cold builds only, under the operator's independently trusted
// release/self SHA pins and trusted builder. These strings are NOT source
// attestation, arbitrary-version compatibility, retained-state reader ABI or
// permission to migrate/start an existing installation. The current executing
// pinned installer supplies the reference; a candidate cannot choose it.
func resultBuildMatches(info, self *debug.BuildInfo, release Release, command string) bool {
	if info == nil || self == nil || release.Toolchain != "go1.27.4" || info.GoVersion != release.Toolchain || info.Path != resultModule+"/cmd/"+command || info.Main.Path != resultModule || info.Main.Version == "" || self.Main.Version == "" || info.Main.Version != self.Main.Version || info.Main.Sum != "" || info.Main.Replace != nil {
		return false
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		if _, ok := settings[s.Key]; ok {
			return false
		}
		settings[s.Key] = s.Value
	}
	for k, v := range map[string]string{"GOOS": "linux", "GOARCH": release.GOARCH, "CGO_ENABLED": "0", "-buildmode": "exe", "-compiler": "gc", "vcs": "git", "vcs.revision": release.SourceRevision, "vcs.modified": "false"} {
		if settings[k] != v {
			return false
		}
	}
	if settings["-tags"] != "" || settings["GOEXPERIMENT"] != "" || settings["-race"] != "" && settings["-race"] != "false" {
		return false
	}
	allowed := map[string]debug.Module{}
	for _, d := range self.Deps {
		if d == nil || d.Replace != nil {
			return false
		}
		if _, ok := allowed[d.Path]; ok {
			return false
		}
		allowed[d.Path] = *d
	}
	seen := map[string]bool{}
	for _, d := range info.Deps {
		if d == nil || d.Replace != nil || seen[d.Path] {
			return false
		}
		seen[d.Path] = true
		want, ok := allowed[d.Path]
		if !ok || d.Version != want.Version || d.Sum != want.Sum {
			return false
		}
	}
	return true
}

// Decode ONLY an already bounded Go >=1.18 inline build-info section. Pointer
// formats, noncanonical length encodings, unknown flags, oversized strings and
// nonzero tail refuse BEFORE an unbounded library read/allocation is possible.
func resultInlineBuildInfo(raw []byte) (*debug.BuildInfo, error) {
	if len(raw) < 32 || len(raw) > MaxPlan || !bytes.Equal(raw[:14], []byte("\xff Go buildinf:")) || raw[14] != 8 || raw[15] != 2 || !bytes.Equal(raw[16:32], make([]byte, 16)) {
		return nil, ErrInventory
	}
	tail := raw[32:]
	read := func(maximum int) ([]byte, bool) {
		n, width := binary.Uvarint(tail)
		if width <= 0 || n > uint64(maximum) || n > uint64(len(tail)-width) {
			return nil, false
		}
		var canonical [10]byte
		size := binary.PutUvarint(canonical[:], n)
		if size != width || !bytes.Equal(canonical[:size], tail[:width]) {
			return nil, false
		}
		out := tail[width : width+int(n)]
		tail = tail[width+int(n):]
		return out, true
	}
	version, ok := read(64)
	if !ok {
		return nil, ErrInventory
	}
	mod, ok := read(MaxPlan)
	if !ok || len(mod) < 32 {
		return nil, ErrInventory
	}
	for _, b := range tail {
		if b != 0 {
			return nil, ErrInventory
		}
	}
	start, _ := hex.DecodeString("3077af0c9274080241e1c107e6d618e6")
	end, _ := hex.DecodeString("f932433186182072008242104116d8f2")
	if !bytes.Equal(mod[:16], start) || !bytes.Equal(mod[len(mod)-16:], end) {
		return nil, ErrInventory
	}
	info, e := debug.ParseBuildInfo(string(mod[16 : len(mod)-16]))
	if e != nil {
		return nil, ErrInventory
	}
	info.GoVersion = string(version)
	return info, nil
}

func resultNativeBuild(ctx context.Context, in io.ReaderAt, size int64) (*debug.BuildInfo, error) {
	if _, ok := ctx.Deadline(); !ok || in == nil || size < 64 || size > 64<<20 {
		return nil, ErrPolicy
	}
	r := &runtimeImageReader{ctx: ctx, input: in, size: size, left: 32 << 10}
	if e := runtimeImagePreflight(r); e != nil {
		return nil, e
	}
	if e := staticNativeReader(r, size, false); e != nil {
		return nil, e
	}
	image, e := elf.NewFile(r)
	if e != nil {
		return nil, e
	}
	defer image.Close()
	count := 0
	for _, section := range image.Sections {
		if section.Name == ".go.buildinfo" {
			count++
		}
	}
	if count != 1 {
		return nil, ErrInventory
	}
	section := image.Section(".go.buildinfo")
	if section == nil || section.Type != elf.SHT_PROGBITS || section.Flags&elf.SHF_COMPRESSED != 0 || section.Size < 32 || section.Size > MaxPlan || !runtimeImageRange(section.Offset, section.Size, 1, size) {
		return nil, ErrInventory
	}
	raw := make([]byte, int(section.Size))
	if _, e = r.ReadAt(raw, int64(section.Offset)); e != nil {
		return nil, e
	}
	info, e := resultInlineBuildInfo(raw)
	if e != nil {
		return nil, e
	}
	return info, ctx.Err()
}

func resultCommands() map[string]string {
	return map[string]string{"daemon": "sandboxd", "gateway": "xandbox-gateway", "ingress": "xandbox-ingress-launch", "installer": "xandbox-install", "launcher": "xandbox-launch", "node": "xandbox-node", "ready": "xandbox-ready", "template": "xandbox-template"}
}

func resultTrustedSelf(release Release) (*debug.BuildInfo, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok || !resultBuildMatches(info, info, release, "xandbox-install") {
		return nil, ErrPolicy
	}
	return info, nil
}

// One original source/target FD for metadata plus full fresh hash, then exact
// identity recheck. No byte cache, external digest, executable invocation,
// constructor, result-store mutation or retained-state binding migration.
func resultProgramFD(ctx context.Context, in *os.File, file File, self *debug.BuildInfo, release Release, command string) error {
	var before, after unix.Stat_t
	if e := unix.Fstat(int(in.Fd()), &before); e != nil {
		return e
	}
	if before.Size != file.Bytes || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != uint32(os.Geteuid()) {
		return ErrInventory
	}
	info, e := resultNativeBuild(ctx, in, file.Bytes)
	if e != nil {
		return e
	}
	if !resultBuildMatches(info, self, release, command) {
		return ErrPolicy
	}
	sum, e := hashFile(ctx, in, file.Bytes)
	if e != nil {
		return e
	}
	if sum != file.SHA256 {
		return ErrInventory
	}
	if e = unix.Fstat(int(in.Fd()), &after); e != nil {
		return e
	}
	if stateEntry(before) != stateEntry(after) {
		return ErrConflict
	}
	return ctx.Err()
}

func resultSourceBuilds(ctx context.Context, p *prepared, view *releaseView) error {
	self, e := resultTrustedSelf(p.release)
	if e != nil {
		return e
	}
	commands := resultCommands()
	for _, v := range p.targets {
		role := ""
		if v.file.Path == SelfPath {
			role = "installer"
		} else {
			for candidate := range commands {
				if candidate != "installer" && v.file.Path == rolePath(candidate) {
					role = candidate
					break
				}
			}
		}
		if role == "" {
			continue
		}
		if v.source == nil {
			return ErrInventory
		}
		if e = resultProgramFD(ctx, v.source, v.file, self, p.release, commands[role]); e != nil {
			return e
		}
		delete(commands, role)
	}
	if len(commands) != 0 || view == nil {
		return ErrInventory
	}
	return nil
}

func (f *filesystem) resultProgramBuilds(ctx context.Context, plan Plan, release Release) error {
	self, e := resultTrustedSelf(release)
	if e != nil {
		return e
	}
	art, e := descriptor(release)
	if e != nil {
		return e
	}
	commands := resultCommands()
	for _, role := range runtimeProgramRoles() {
		command := commands[role]
		path := SelfPath
		pin := plan.Self.SHA256
		var size int64
		if role != "installer" {
			path = rolePath(role)
			pin = art[role].SHA256
			size = art[role].Bytes
		}
		in, e := f.open(path, unix.O_RDONLY, 0555)
		if e != nil {
			return e
		}
		if role == "installer" {
			st, err := in.Stat()
			if err != nil {
				in.Close()
				return err
			}
			size = st.Size()
		}
		e = resultProgramFD(ctx, in, File{Path: path, SHA256: pin, Bytes: size, Mode: 0555}, self, release, command)
		in.Close()
		if e != nil {
			return e
		}
	}
	return ctx.Err()
}
