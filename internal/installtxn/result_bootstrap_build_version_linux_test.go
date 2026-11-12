//go:build linux

package installtxn

import (
	"runtime/debug"
	"strings"
	"testing"
)

// Go1.27.4 derives Main.Version from the VCS revision; it is not universally
// (devel). Source: golang/go go1.27.4 cmd/go/internal/load/pkg.go, VCS stamping.
// This remains a SAME trusted-self metadata join, NOT source attestation or
// arbitrary-version/retained-state compatibility. All existing guards apply.
func TestResultBootstrapBuildVersionMatchesTrustedSelf(t *testing.T) {
	for _, tc := range []struct{ name, version string }{
		{"development", "(devel)"},
		{"release-tag", "v0.1.0"},
		{"vcs-pseudoversion", "v0.1.1-0.20261112000000-aaaaaaaaaaaa"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			self, release := resultInfoSeed()
			candidate, _ := resultInfoSeed()
			self.Main.Version = tc.version
			candidate.Main.Version = tc.version
			raw := resultInfoBlob(t, candidate)
			decoded, e := resultInlineBuildInfo(raw)
			if e != nil || !resultBuildMatches(decoded, self, release, "xandbox-install") {
				t.Fatal("matching actual module version rejected", tc.name, e)
			}
			if decoded.Main.Version != tc.version || self.Main.Version != tc.version {
				t.Fatal("module version normalized instead of compared")
			}
		})
	}
}

func TestResultBootstrapBuildVersionKeepsAllIdentityGuards(t *testing.T) {
	for _, name := range []string{"version-mismatch", "empty-candidate", "empty-self", "both-empty", "wrong-revision", "dirty", "wrong-role", "wrong-sdk", "unknown-dependency"} {
		t.Run(name, func(t *testing.T) {
			self, release := resultInfoSeed()
			candidate, _ := resultInfoSeed()
			version := "v0.1.1-0.20261112000000-aaaaaaaaaaaa"
			self.Main.Version = version
			candidate.Main.Version = version
			switch name {
			case "version-mismatch":
				candidate.Main.Version = "v0.1.0"
			case "empty-candidate":
				candidate.Main.Version = ""
			case "empty-self":
				self.Main.Version = ""
			case "both-empty":
				self.Main.Version = ""
				candidate.Main.Version = ""
			case "wrong-revision":
				for i := range candidate.Settings {
					if candidate.Settings[i].Key == "vcs.revision" {
						candidate.Settings[i].Value = strings.Repeat("b", 40)
					}
				}
			case "dirty":
				for i := range candidate.Settings {
					if candidate.Settings[i].Key == "vcs.modified" {
						candidate.Settings[i].Value = "true"
					}
				}
			case "wrong-role":
				candidate.Path = resultModule + "/cmd/sandboxd"
			case "wrong-sdk":
				candidate.GoVersion = "go1.27.3"
			case "unknown-dependency":
				candidate.Deps = []*debug.Module{{Path: "unknown.example/dependency", Version: "v1.0.0"}}
			}
			raw := resultInfoBlob(t, candidate)
			decoded, e := resultInlineBuildInfo(raw)
			if e == nil && resultBuildMatches(decoded, self, release, "xandbox-install") {
				t.Fatal("version support bypassed an original identity guard", name)
			}
			if self.Main.Version != "" && self.Main.Version != version {
				t.Fatal("trusted reference mutated")
			}
		})
	}
}
