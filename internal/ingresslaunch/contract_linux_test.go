//go:build linux

package ingresslaunch

import (
	"testing"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/launch"
)

// Binding structs are MODELS; no service, socket, cgroup, KVM or task is started.
func TestRetainedLaunchIngressRequiresSameBackendPolicyAndOriginalComposition(t *testing.T) {
	p := firecracker.ResultPolicy{Version: 1, Bytes: 8 << 20, TenantBytes: 2 << 20, Records: 32}
	c, e := launch.NewResultContract(nodePolicy(), p)
	if e != nil {
		t.Fatal(e)
	}
	g, b := binding()
	b.Version, b.Results = 4, &p
	if e = policy().checkContractBinding(c, g, b); e != nil {
		t.Fatal(e)
	}
	if policy().checkBinding(nodePolicy(), g, b) == nil {
		t.Fatal("legacy consumer reinterpreted V4")
	}
	for name, change := range map[string]func(*gateway.Config, *firecracker.Config){
		"bytes":           func(_ *gateway.Config, b *firecracker.Config) { b.Results.Bytes++ },
		"tenant":          func(_ *gateway.Config, b *firecracker.Config) { b.Results.TenantBytes++ },
		"records":         func(_ *gateway.Config, b *firecracker.Config) { b.Results.Records++ },
		"missing-policy":  func(_ *gateway.Config, b *firecracker.Config) { b.Results = nil },
		"legacy-version":  func(_ *gateway.Config, b *firecracker.Config) { b.Version = 3 },
		"gateway-state":   func(g *gateway.Config, _ *firecracker.Config) { g.StateDir += "-other" },
		"tenant-socket":   func(g *gateway.Config, _ *firecracker.Config) { g.TenantSocket += "-other" },
		"auth-snapshot":   func(g *gateway.Config, _ *firecracker.Config) { g.BackendAuthFile = nodePolicy().Auth.Path },
		"io-device":       func(_ *gateway.Config, b *firecracker.Config) { b.IO.Device = "8:0" },
		"runtime-overlap": func(_ *gateway.Config, b *firecracker.Config) { b.RuntimeRoot = policy().PolicyStateDir },
	} {
		t.Run(name, func(t *testing.T) {
			q := p
			g, b := binding()
			b.Version, b.Results = 4, &q
			change(&g, &b)
			if policy().checkContractBinding(c, g, b) == nil {
				t.Fatal("backend, authority or composition mismatch accepted")
			}
		})
	}
	m := policy()
	m.Capacity.MemoryMax = nodePolicy().Parent.MemoryMax
	if m.checkContractBinding(c, g, b) == nil {
		t.Fatal("separate ingress and host reserve disappeared")
	}
}
