package installtxn

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/ingresslaunch"
	"github.com/123123213weqw/Xandbox/internal/launch"
)

// Independent pinned d3 constructor/JSON producer. Do not call either candidate
// ingress builder, encode, digest or line helper for this expected value.
func originalIngressNodeLineD3(p Plan, n launch.Manifest, device string, art map[string]Artifact) ingresslaunch.Manifest {
	data, e := json.Marshal(n)
	if e != nil {
		panic("closed TEST node not encodable")
	}
	data = append(data, '\n')
	sum := sha256.Sum256(data)
	return ingresslaunch.Manifest{Version: 1, UnitRoot: "/sys/fs/cgroup/system.slice/" + IngressUnit, PolicyStateDir: policyDir, Gateway: firecracker.Asset{Path: rolePath("gateway"), SHA256: art["gateway"].SHA256}, Config: firecracker.Asset{Path: Root + "/gateway.json", SHA256: p.Gateway.SHA256}, NodeLaunch: firecracker.Asset{Path: launchPath, SHA256: hex.EncodeToString(sum[:])}, Device: device, Ingress: p.Ingress, Reserve: p.Reserve, Capacity: p.Capacity}
}
func compareNodeLineD3(t *testing.T, p Plan, n launch.Manifest, device string, art map[string]Artifact) {
	t.Helper()
	before := n
	planBefore := snapshotPlanValue(p)
	raw, e := json.Marshal(n)
	wantFits := e == nil && len(raw) < launch.MaxManifest
	line, fits := nodeManifestLine(n)
	if fits != wantFits || nodeLineFitsManifest(n) != wantFits || n != before || !samePlanValue(p, planBefore) {
		t.Fatal("node byte predicate or caller changed", fits, wantFits)
	}
	if !fits {
		if line != nil {
			t.Fatal("rejected line exposed partial bytes")
		}
		return
	}
	want := append(append([]byte(nil), raw...), '\n')
	if !bytes.Equal(line, want) || len(line) != len(raw)+1 || line[len(line)-1] != '\n' {
		t.Fatal("exact independent JSON+LF bytes changed")
	}
	original := originalIngressNodeLineD3(p, n, device, art)
	wrapped := ingressManifest(p, n, device, art)
	got := ingressManifestWithNodeSHA(p, digest(line), device, art)
	a, _ := json.Marshal(original)
	b, _ := json.Marshal(wrapped)
	c, _ := json.Marshal(got)
	if got != original || wrapped != original || !bytes.Equal(a, b) || !bytes.Equal(a, c) || n != before || !samePlanValue(p, planBefore) {
		t.Fatal("ingress complete value/bytes/caller differs from pinned d3", got, original)
	}
}

func TestRuntimeFileNodeLineReuseMatchesIndependentD3JSONAndIngress(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version int
		metrics bool
	}{{"v1-metrics-off", 1, false}, {"v1-metrics-on", 1, true}, {"v2-metrics-off", 2, false}, {"v2-metrics-on", 2, true}} {
		t.Run(tc.name, func(t *testing.T) {
			p := typedPlanSeed(tc.version)
			p.Frontend.Metrics = tc.metrics
			n := nodeManifest(p, map[string]Artifact{"daemon": {SHA256: strings.Repeat("a", 64)}})
			art := map[string]Artifact{"gateway": {SHA256: strings.Repeat("b", 64)}}
			for _, device := range []string{"1:1", "259:0"} {
				for _, pins := range []map[string]Artifact{art, nil, {}, {"gateway": {SHA256: strings.Repeat("c", 64)}}} {
					compareNodeLineD3(t, p, n, device, pins)
				}
			}
			if originalValidatePlanFlow98(p) != validatePlan(p) {
				t.Fatal("original full composition policy changed")
			}
		})
	}
}

func TestRuntimeFileNodeLineReuseKeepsExactLFCeiling(t *testing.T) {
	p := typedPlanSeed(2)
	seed := nodeManifest(p, map[string]Artifact{"daemon": {SHA256: strings.Repeat("a", 64)}})
	for _, tc := range []struct {
		name string
		size int
	}{{"bare-max-minus-one", launch.MaxManifest - 1}, {"bare-max", launch.MaxManifest}, {"bare-max-plus-one", launch.MaxManifest + 1}} {
		t.Run(tc.name, func(t *testing.T) {
			n := seed
			n.Daemon.Path = "/usr/libexec//sandboxd"
			raw, e := json.Marshal(n)
			if e != nil {
				t.Fatal(e)
			}
			n.Daemon.Path = "/usr/libexec/" + strings.Repeat("x", tc.size-len(raw)) + "/sandboxd"
			raw, e = json.Marshal(n)
			if e != nil || len(raw) != tc.size {
				t.Fatal("wrong exact wire boundary", len(raw), e)
			}
			art := map[string]Artifact{"gateway": {SHA256: strings.Repeat("b", 64)}}
			compareNodeLineD3(t, p, n, "1:1", art)
			_, fits := nodeManifestLine(n)
			_, old := launch.ValidateLineValue(n)
			if fits != (old == nil) || fits != (tc.size < launch.MaxManifest) {
				t.Fatal("lost final LF byte", tc.name, fits, old)
			}
			g := originalIngressNodeLineD3(p, n, "1:1", art)
			if ingressManifest(p, n, "1:1", art) != g {
				t.Fatal("old constructor changed even on oversized node input")
			}
			if (g.CheckComposition(n) == nil) != (tc.size <= launch.MaxManifest) {
				t.Fatal("bare/line distinction silently widened")
			}
		})
	}
}

func TestRuntimeFileNodeLineReusePreservesJSONEscapesAndInvalidUTF8(t *testing.T) {
	p := typedPlanSeed(2)
	seed := nodeManifest(p, map[string]Artifact{"daemon": {SHA256: strings.Repeat("a", 64)}})
	fields := []struct {
		name  string
		field func(*launch.Manifest) *string
	}{
		{"unit-root", func(n *launch.Manifest) *string { return &n.UnitRoot }},
		{"input-dir", func(n *launch.Manifest) *string { return &n.InputDir }},
		{"state-dir", func(n *launch.Manifest) *string { return &n.StateDir }},
		{"daemon-path", func(n *launch.Manifest) *string { return &n.Daemon.Path }},
		{"daemon-sha", func(n *launch.Manifest) *string { return &n.Daemon.SHA256 }},
		{"backend-path", func(n *launch.Manifest) *string { return &n.Backend.Path }},
		{"backend-sha", func(n *launch.Manifest) *string { return &n.Backend.SHA256 }},
		{"auth-path", func(n *launch.Manifest) *string { return &n.Auth.Path }},
		{"auth-sha", func(n *launch.Manifest) *string { return &n.Auth.SHA256 }},
	}
	values := []struct{ name, value string }{{"empty", ""}, {"ascii", "abc/123"}, {"html", "<>&"}, {"newline", "\n\r\x00"}, {"unicode", "ſK😀"}, {"invalid-utf8", string([]byte{255})}, {"mixed-invalid", string([]byte{'a', 255, 'b'})}, {"line-separator", "\u2028\u2029"}}
	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			for _, value := range values {
				t.Run(value.name, func(t *testing.T) {
					n := seed
					*field.field(&n) = value.value
					compareNodeLineD3(t, p, n, "1:1", map[string]Artifact{"gateway": {SHA256: strings.Repeat("b", 64)}})
				})
			}
		})
	}
}

func TestRuntimeFileNodeLineReuseDoesNotCacheOrShareMutableBytes(t *testing.T) {
	p := typedPlanSeed(2)
	n := nodeManifest(p, map[string]Artifact{"daemon": {SHA256: strings.Repeat("a", 64)}})
	before := n
	first, ok := nodeManifestLine(n)
	second, again := nodeManifestLine(n)
	raw, e := json.Marshal(n)
	if e != nil {
		t.Fatal(e)
	}
	want := append(append([]byte(nil), raw...), '\n')
	if !ok || !again || len(first) == 0 || !bytes.Equal(first, want) || !bytes.Equal(second, want) {
		t.Fatal("independent producer unavailable")
	}
	first[0] ^= 1
	if !bytes.Equal(second, want) || n != before {
		t.Fatal("cross-call byte sharing or caller mutation")
	}
	n.Frontend.Metrics = !n.Frontend.Metrics
	third, ok := nodeManifestLine(n)
	if !ok || bytes.Equal(third, want) || !bytes.Equal(second, want) {
		t.Fatal("cached stale node line or modified previous bytes")
	}
}

func TestRuntimeFileNodeLineReuseNeverSubstitutesForCompositionOrDigestProof(t *testing.T) {
	p := typedPlanSeed(2)
	n := nodeManifest(p, map[string]Artifact{"daemon": {SHA256: strings.Repeat("a", 64)}})
	art := map[string]Artifact{"gateway": {SHA256: strings.Repeat("b", 64)}}
	t.Run("byte-fit-not-semantic", func(t *testing.T) {
		q := n
		q.Version = 0
		line, fits := nodeManifestLine(q)
		if !fits || len(line) == 0 {
			t.Fatal("budget predicate unexpectedly semantic")
		}
		g := ingressManifestWithNodeSHA(p, digest(line), "1:1", art)
		if g.CheckComposition(q) == nil {
			t.Fatal("original complete semantic policy was lost")
		}
	})
	t.Run("composition-not-node-hash", func(t *testing.T) {
		line, fits := nodeManifestLine(n)
		if !fits {
			t.Fatal("valid node not encodable")
		}
		bad := strings.Repeat("f", 64)
		if bad == digest(line) {
			t.Fatal("bad digest control collision")
		}
		g := ingressManifestWithNodeSHA(p, bad, "1:1", art)
		if g.CheckComposition(n) != nil || g.NodeLaunch.SHA256 == digest(line) {
			t.Fatal("review changed composition digest contract")
		}
		good := ingressManifestWithNodeSHA(p, digest(line), "1:1", art)
		if good != originalIngressNodeLineD3(p, n, "1:1", art) {
			t.Fatal("trusted producer did not bind actual node line")
		}
	})
	t.Run("caller-change-not-authorized", func(t *testing.T) {
		line, fits := nodeManifestLine(n)
		if !fits {
			t.Fatal("valid seed not encodable")
		}
		q := n
		q.Frontend.Metrics = !q.Frontend.Metrics
		g := ingressManifestWithNodeSHA(p, digest(line), "1:1", art)
		if g.NodeLaunch.SHA256 == originalIngressNodeLineD3(p, q, "1:1", art).NodeLaunch.SHA256 {
			t.Fatal("stale bytes supplied authority for changed node")
		}
		if n == q {
			t.Fatal("mutation control ineffective")
		}
	})
}
