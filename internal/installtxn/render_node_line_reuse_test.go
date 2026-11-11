package installtxn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"github.com/123123213weqw/Xandbox/internal/policycontrol"
	"github.com/123123213weqw/Xandbox/internal/serviceready"
)

// Pinned3a producer and renderer, with only function names rebound to independent
// TEST constructors/JSON. OriginalIngressNodeLineD3 is the existing literal
// constructor, not either candidate ingress builder. Production generators and
// validators are unchanged and still run in both paths.
func originalRenderJSON3a(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic("fixed install schema not encodable")
	}
	return append(b, '\n')
}
func originalRenderNode3a(p Plan, art map[string]Artifact) launch.Manifest {
	return launch.Manifest{Version: 1, UnitRoot: unitRoot, InputDir: inputDir, StateDir: stateDir, Daemon: firecracker.Asset{Path: rolePath("daemon"), SHA256: art["daemon"].SHA256}, Backend: firecracker.Asset{Path: Root + "/backend.json", SHA256: p.Backend.SHA256}, Auth: firecracker.Asset{Path: Root + "/auth.json", SHA256: p.Auth.SHA256}, Frontend: p.Frontend, Parent: p.Parent}
}
func originalRender3a(p Plan, device string, art map[string]Artifact) (map[string][]byte, error) {
	n := originalRenderNode3a(p, art)
	g := originalIngressNodeLineD3(p, n, device, art)
	r := serviceready.Manifest{Version: 1, NodeLaunch: g.NodeLaunch, Helper: firecracker.Asset{Path: serviceready.HelperPath, SHA256: art["ready"].SHA256}, Device: device}
	main, e := r.DaemonUnit(n, readyPath, p.DevicePath)
	if e != nil {
		return nil, ErrPolicy
	}
	ingress, e := g.Unit(n, ingressPath, p.DevicePath)
	if e != nil {
		return nil, ErrPolicy
	}
	needle := "Type=exec\nExecStart="
	if strings.Count(main, needle) != 1 {
		return nil, ErrPolicy
	}
	main = strings.Replace(main, needle, "Type=exec\nExecStartPre="+SelfPath+" verify\nExecStart=", 1)
	if p.Version == 2 {
		line := "ReadWritePaths=" + policyDir + "\n"
		if strings.Count(ingress, line) != 1 || strings.Count(ingress, "Type=exec\n") != 1 {
			return nil, ErrPolicy
		}
		ingress = strings.Replace(ingress, line, "ReadWritePaths="+policyDir+" "+policycontrol.OperatorDirectory+"\n", 1)
		ingress = strings.Replace(ingress, "Type=exec\n", "Type=exec\nRuntimeDirectory=xandbox-ingress-control\nRuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=no\n", 1)
	}
	return map[string][]byte{launchPath: originalRenderJSON3a(n), ingressPath: originalRenderJSON3a(g), readyPath: originalRenderJSON3a(r), UnitDir + "/" + MainUnit: []byte(main), UnitDir + "/" + IngressUnit: []byte(ingress)}, nil
}

func renderPins3a() map[string]Artifact {
	art := map[string]Artifact{}
	for _, a := range descriptorValueSeed44().Files {
		art[a.Role] = a
	}
	return art
}
func renderMapsEqual3a(a, b map[string][]byte) bool {
	if (a == nil) != (b == nil) || len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || !bytes.Equal(v, w) {
			return false
		}
	}
	return true
}
func cloneRenderMap3a(a map[string][]byte) map[string][]byte {
	b := map[string][]byte{}
	for k, v := range a {
		b[k] = append([]byte(nil), v...)
	}
	return b
}
func compareRender3a(t *testing.T, p Plan, device string, art map[string]Artifact, valid bool) map[string][]byte {
	t.Helper()
	before := snapshotPlanValue(p)
	pins, e := json.Marshal(art)
	if e != nil {
		t.Fatal(e)
	}
	want, old := originalRender3a(p, device, art)
	got, err := render(p, device, art)
	after, e := json.Marshal(art)
	if e != nil {
		t.Fatal(e)
	}
	if old != err || (err == nil) != valid || !renderMapsEqual3a(want, got) || !samePlanValue(p, before) || !bytes.Equal(pins, after) {
		t.Fatal("original complete renderer/error/caller contract changed", old, err, valid)
	}
	if !valid {
		if got != nil {
			t.Fatal("error returned partial artifacts")
		}
		return nil
	}
	if len(got) != 5 || !bytes.Equal(got[launchPath], originalRenderJSON3a(originalRenderNode3a(p, art))) {
		t.Fatal("original five artifacts or exact node JSON+LF changed")
	}
	return got
}

func TestRuntimeFileRenderNodeLineReuseKeepsExactOriginalArtifacts(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, metrics := range []bool{false, true} {
			for i, device := range []string{"1:1", "259:0"} {
				name := fmt.Sprintf("v%d-metrics-%t-dev%d", version, metrics, i)
				t.Run(name, func(t *testing.T) {
					p := typedPlanSeed(version)
					p.Frontend.Metrics = metrics
					compareRender3a(t, p, device, renderPins3a(), true)
				})
			}
		}
	}
}

func TestRuntimeFileRenderNodeLineReuseKeepsEveryOriginalErrorAndNoPartialOutput(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			for _, kind := range []string{"nil-pins", "empty-pins", "missing-daemon", "missing-gateway", "missing-ready", "bad-daemon-sha", "bad-gateway-sha", "bad-ready-sha", "bad-backend-sha", "bad-auth-sha", "bad-gateway-config-sha", "bad-device", "unsafe-device-path", "bad-node-memory", "oversized-auth-sha", "invalid-utf8-auth-sha"} {
				t.Run(kind, func(t *testing.T) {
					p := typedPlanSeed(version)
					art := renderPins3a()
					device := "1:1"
					switch kind {
					case "nil-pins":
						art = nil
					case "empty-pins":
						art = map[string]Artifact{}
					case "missing-daemon":
						delete(art, "daemon")
					case "missing-gateway":
						delete(art, "gateway")
					case "missing-ready":
						delete(art, "ready")
					case "bad-daemon-sha", "bad-gateway-sha", "bad-ready-sha":
						role := strings.TrimSuffix(strings.TrimPrefix(kind, "bad-"), "-sha")
						a := art[role]
						a.SHA256 = "BAD"
						art[role] = a
					case "bad-backend-sha":
						p.Backend.SHA256 = "BAD"
					case "bad-auth-sha":
						p.Auth.SHA256 = "BAD"
					case "bad-gateway-config-sha":
						p.Gateway.SHA256 = "BAD"
					case "bad-device":
						device = "0:0"
					case "unsafe-device-path":
						p.DevicePath = "/dev/vdb\n"
					case "bad-node-memory":
						p.Parent.MemoryMax = 0
					case "oversized-auth-sha":
						p.Auth.SHA256 = strings.Repeat("a", launch.MaxManifest)
					case "invalid-utf8-auth-sha":
						p.Auth.SHA256 = string([]byte{255})
					}
					compareRender3a(t, p, device, art, false)
				})
			}
		})
	}
}

func TestRuntimeFileRenderNodeLineReuseDoesNotCacheShareBytesOrGrantPlanAuthority(t *testing.T) {
	t.Run("fresh-output-bytes", func(t *testing.T) {
		p := typedPlanSeed(2)
		art := renderPins3a()
		first := compareRender3a(t, p, "1:1", art, true)
		second := compareRender3a(t, p, "1:1", art, true)
		saved := cloneRenderMap3a(second)
		for _, v := range first {
			if len(v) == 0 {
				t.Fatal("empty artifact")
			}
			v[0] ^= 1
		}
		third := compareRender3a(t, p, "1:1", art, true)
		if !renderMapsEqual3a(second, saved) || !renderMapsEqual3a(third, saved) {
			t.Fatal("cross-call mutable output shared")
		}
	})
	t.Run("fresh-caller-values", func(t *testing.T) {
		p := typedPlanSeed(2)
		art := renderPins3a()
		first := compareRender3a(t, p, "1:1", art, true)
		saved := cloneRenderMap3a(first)
		p.Frontend.Metrics = true
		a := art["daemon"]
		a.SHA256 = strings.Repeat("d", 64)
		art["daemon"] = a
		second := compareRender3a(t, p, "1:1", art, true)
		if bytes.Equal(first[launchPath], second[launchPath]) || !renderMapsEqual3a(first, saved) {
			t.Fatal("stale caller values cached or previous output mutated")
		}
	})
	t.Run("generator-not-plan-policy", func(t *testing.T) {
		p := typedPlanSeed(2)
		p.Release = ""
		if validatePlan(p) == nil {
			t.Fatal("invalid Plan control unexpectedly valid")
		}
		// The original renderer validates generated composition, not the whole Plan.
		// Equal bytes here are NOT permission to bypass the caller's Plan policy.
		compareRender3a(t, p, "1:1", renderPins3a(), true)
	})
}
