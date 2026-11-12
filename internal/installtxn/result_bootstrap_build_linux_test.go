//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"os"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func resultInfoSeed() (*debug.BuildInfo, Release) {
	release := Release{Version: 1, SourceRevision: strings.Repeat("a", 40), Toolchain: "go1.27.4", GOARCH: "amd64"}
	info := &debug.BuildInfo{GoVersion: release.Toolchain, Path: resultModule + "/cmd/xandbox-install", Main: debug.Module{Path: resultModule, Version: "(devel)"}}
	for _, kv := range [][2]string{{"GOOS", "linux"}, {"GOARCH", "amd64"}, {"CGO_ENABLED", "0"}, {"-buildmode", "exe"}, {"-compiler", "gc"}, {"vcs", "git"}, {"vcs.revision", release.SourceRevision}, {"vcs.modified", "false"}} {
		info.Settings = append(info.Settings, debug.BuildSetting{Key: kv[0], Value: kv[1]})
	}
	return info, release
}
func resultInfoBlob(t *testing.T, info *debug.BuildInfo) []byte {
	t.Helper()
	mod := info.String()
	mod = strings.TrimPrefix(mod, "go\t"+info.GoVersion+"\n")
	start, _ := hex.DecodeString("3077af0c9274080241e1c107e6d618e6")
	end, _ := hex.DecodeString("f932433186182072008242104116d8f2")
	raw := make([]byte, 32)
	copy(raw, []byte("\xff Go buildinf:"))
	raw[14] = 8
	raw[15] = 2
	appendString := func(b []byte) {
		var n [10]byte
		width := binary.PutUvarint(n[:], uint64(len(b)))
		raw = append(raw, n[:width]...)
		raw = append(raw, b...)
	}
	appendString([]byte(info.GoVersion))
	appendString(append(append(start, []byte(mod)...), end...))
	return raw
}
func TestResultBootstrapBoundedInlineBuildMetadataAndIdentityPolicy(t *testing.T) {
	info, release := resultInfoSeed()
	raw := resultInfoBlob(t, info)
	got, e := resultInlineBuildInfo(raw)
	if e != nil || !resultBuildMatches(got, info, release, "xandbox-install") {
		t.Fatal("bounded synthetic build metadata", got, e)
	}
	for _, name := range []string{"empty", "short", "oversize", "magic", "pointer", "flags", "reserved", "version-length", "module-length", "sentinel", "tail", "revision", "dirty", "cgo", "race", "role", "module", "replacement", "duplicate-setting", "unknown-dependency"} {
		t.Run(name, func(t *testing.T) {
			candidate, r := resultInfoSeed()
			data := resultInfoBlob(t, candidate)
			switch name {
			case "empty":
				data = nil
			case "short":
				data = data[:31]
			case "oversize":
				data = make([]byte, MaxPlan+1)
			case "magic":
				data[0] = 0
			case "pointer":
				data[14] = 4
			case "flags":
				data[15] = 0
			case "reserved":
				data[16] = 1
			case "version-length":
				data[32] = 0xff
				data[33] = 0xff
			case "module-length":
				at := 33 + len(candidate.GoVersion)
				data[at] = 0xff
				data[at+1] = 0xff
			case "sentinel":
				data[len(data)-1] ^= 1
			case "tail":
				data = append(data, 1)
			case "revision", "dirty", "cgo":
				for i := range candidate.Settings {
					if name == "revision" && candidate.Settings[i].Key == "vcs.revision" {
						candidate.Settings[i].Value = strings.Repeat("b", 40)
					}
					if name == "dirty" && candidate.Settings[i].Key == "vcs.modified" {
						candidate.Settings[i].Value = "true"
					}
					if name == "cgo" && candidate.Settings[i].Key == "CGO_ENABLED" {
						candidate.Settings[i].Value = "1"
					}
				}
				data = resultInfoBlob(t, candidate)
			case "race":
				candidate.Settings = append(candidate.Settings, debug.BuildSetting{Key: "-race", Value: "true"})
				data = resultInfoBlob(t, candidate)
			case "role":
				candidate.Path = resultModule + "/cmd/sandboxd"
				data = resultInfoBlob(t, candidate)
			case "module":
				candidate.Main.Path = "different.example/module"
				data = resultInfoBlob(t, candidate)
			case "replacement":
				candidate.Main.Replace = &debug.Module{Path: "local.example/fork"}
				data = resultInfoBlob(t, candidate)
			case "duplicate-setting":
				candidate.Settings = append(candidate.Settings, candidate.Settings[0])
				data = resultInfoBlob(t, candidate)
			case "unknown-dependency":
				candidate.Deps = []*debug.Module{{Path: "unknown.example/dependency", Version: "v1.0.0"}}
				data = resultInfoBlob(t, candidate)
			}
			before := append([]byte(nil), data...)
			decoded, e := resultInlineBuildInfo(data)
			if e == nil && resultBuildMatches(decoded, info, r, "xandbox-install") {
				t.Fatal("unsupported metadata admitted", name)
			}
			if !bytes.Equal(before, data) {
				t.Fatal("metadata mutated")
			}
		})
	}
}

// Optional here ONLY because ordinary race builds do not create distribution
// binaries. The separate REQUIRED linux-build step sets both pins, and proves
// all eight actual CGO-free SDK4 ELF files; no other run may count this as PASS.
func TestResultBootstrapBuiltArtifacts(t *testing.T) {
	prefix, revision := os.Getenv("XANDBOX_TEST_RESULT_ARTIFACT_PREFIX"), os.Getenv("XANDBOX_TEST_RESULT_SOURCE")
	if prefix == "" && revision == "" {
		t.Skip("requires explicit existing Linux SDK4 build artifacts")
	}
	if prefix != "/tmp/" || len(revision) != 40 {
		t.Fatal("fixed build artifact fixture pins required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	release := Release{Version: 1, SourceRevision: revision, Toolchain: "go1.27.4", GOARCH: "amd64"}
	read := func(command string) *debug.BuildInfo {
		t.Helper()
		in, e := os.Open(prefix + command + "-amd64")
		if e != nil {
			t.Fatal(e)
		}
		defer in.Close()
		st, e := in.Stat()
		if e != nil {
			t.Fatal(e)
		}
		info, e := resultNativeBuild(ctx, in, st.Size())
		if e != nil {
			t.Fatal(command, e)
		}
		return info
	}
	self := read("xandbox-install")
	if !resultBuildMatches(self, self, release, "xandbox-install") {
		t.Fatal("actual installed-self build identity")
	}
	commands := resultCommands()
	for _, role := range runtimeProgramRoles() {
		t.Run(role, func(t *testing.T) {
			info := read(commands[role])
			if !resultBuildMatches(info, self, release, commands[role]) {
				t.Fatal("actual same-source role metadata", role)
			}
			t.Log("existing native SDK4 artifact metadata joined", role)
		})
	}
}
