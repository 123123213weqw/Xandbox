//go:build linux

package ingresslaunch

import (
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"testing"
)

func binding() (gateway.Config, firecracker.Config) {
	return gateway.Config{Version: 1, StateDir: policy().PolicyStateDir, TenantSocket: nodePolicy().StateDir + "/api.sock", BackendAuthFile: nodePolicy().InputDir + "/auth.json"}, firecracker.Config{Version: 3, RuntimeRoot: "/srv/xb/r", CgroupRoot: nodePolicy().UnitRoot + "/node/instances", Quota: &firecracker.QuotaPolicy{}, Node: &firecracker.NodePolicy{CgroupRoot: nodePolicy().UnitRoot + "/node", MemoryMax: 7 << 30, PidsMax: 384, CPUQuota: 800000, IOBytesPerSecond: 256 << 20, IOOperationsPerSecond: 8192}, IO: &firecracker.IOPolicy{Device: policy().Device}}
}
func TestOnlyReviewedBackendAuthorityAndIndependentState(t *testing.T) {
	m, n := policy(), nodePolicy()
	c, b := binding()
	if e := m.checkBinding(n, c, b); e != nil {
		t.Fatal(e)
	}
	for i, change := range []func(*gateway.Config, *firecracker.Config){func(c *gateway.Config, b *firecracker.Config) { c.StateDir += "-other" }, func(c *gateway.Config, b *firecracker.Config) { c.TenantSocket = "/run/other/api.sock" }, func(c *gateway.Config, b *firecracker.Config) { c.BackendAuthFile = n.Auth.Path }, func(c *gateway.Config, b *firecracker.Config) { b.IO = nil }, func(c *gateway.Config, b *firecracker.Config) { b.IO.Device = "8:0" }, func(c *gateway.Config, b *firecracker.Config) { b.RuntimeRoot = m.PolicyStateDir }, func(c *gateway.Config, b *firecracker.Config) { b.RuntimeRoot = m.PolicyStateDir + "/runtime" }, func(c *gateway.Config, b *firecracker.Config) { b.RuntimeRoot = "/srv/xb" }} {
		c, b := binding()
		change(&c, &b)
		if m.checkBinding(n, c, b) == nil {
			t.Fatalf("binding drift accepted %d", i)
		}
	}
}
func TestFailureOnlyContainsClosedStage(t *testing.T) {
	e := &failure{stage: "asset"}
	if e.Error() != "ingress preflight failed" || FailureStage(e) != "asset" {
		t.Fatal("error projection drift")
	}
	if capabilityCeiling&(1<<24|1<<21) != 0 {
		t.Fatal("privileged resource or admin bypass")
	}
}
