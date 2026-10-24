package launch

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
)

func policy() Manifest {
	return Manifest{Version: 1, UnitRoot: "/sys/fs/cgroup/system.slice/xandbox.service", InputDir: "/run/xandbox-inputs", StateDir: "/srv/xb/s",
		Daemon: firecracker.Asset{Path: "/srv/assets/sandboxd", SHA256: strings.Repeat("a", 64)}, Backend: firecracker.Asset{Path: "/etc/xandbox/backend.json", SHA256: strings.Repeat("b", 64)}, Auth: firecracker.Asset{Path: "/etc/xandbox/auth.json", SHA256: strings.Repeat("c", 64)},
		Frontend: Frontend{MaxInstances: 4, MaxRecords: 1024, MaxTenantRecords: 512, MaxSessions: 32, MaxTenantSessions: 16, SessionHistory: 64, StopWorkers: 4, CleanupWorkers: 2, WorkQueueSize: 32, Metrics: true},
		Parent:   ParentEnvelope{MemoryMax: 15 << 29, PidsMax: 512, CPUQuota: 800000, IOBytesPerSecond: 512 << 20, IOOperationsPerSecond: 16384}}
}
func config(m Manifest) firecracker.Config {
	return firecracker.Config{Version: 3, RuntimeRoot: "/srv/xb/r", CgroupRoot: m.UnitRoot + "/node/instances", Quota: &firecracker.QuotaPolicy{}, IO: &firecracker.IOPolicy{Device: "253:0"}, Node: &firecracker.NodePolicy{CgroupRoot: m.UnitRoot + "/node", MaxInstances: 4, MemoryMax: 7 << 30, ControllerMemoryMax: 1 << 30, PidsMax: 384, ControllerPidsMax: 128, CPUQuota: 800000, IOBytesPerSecond: 256 << 20, IOOperationsPerSecond: 8192}}
}
func TestManifestClosedAndCanonical(t *testing.T) {
	m := policy()
	data, _ := json.Marshal(m)
	got, e := Decode(data)
	if e != nil || !reflect.DeepEqual(m, got) {
		t.Fatal(e)
	}
	for _, change := range []func(*Manifest){func(m *Manifest) { m.Version = 2 }, func(m *Manifest) { m.UnitRoot = "/sys/fs/cgroup" }, func(m *Manifest) { m.UnitRoot = "/sys/fs/cgroup/system.slice/xandbox.service/../other.service" }, func(m *Manifest) { m.InputDir = "/etc" }, func(m *Manifest) { m.StateDir = "/tmp/state" }, func(m *Manifest) { m.Daemon.Path = "/bin/sh" }, func(m *Manifest) { m.Auth.Path = m.Backend.Path }, func(m *Manifest) { m.Daemon.SHA256 = "not-sha" }, func(m *Manifest) { m.Frontend.MaxTenantRecords = 0 }, func(m *Manifest) { m.Frontend.StopWorkers = 65 }, func(m *Manifest) { m.Parent.MemoryMax = 0 }, func(m *Manifest) { m.Backend.Path = m.StateDir + "/backend.json" }} {
		bad := m
		change(&bad)
		raw, _ := json.Marshal(bad)
		if _, e := Decode(raw); e == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	for _, raw := range [][]byte{append(data[:len(data)-1], []byte(`,"version":1}`)...), append(data[:len(data)-1], []byte(`,"extra":"private"}`)...), []byte(strings.Repeat(" ", 16385))} {
		if _, e := Decode(raw); e == nil {
			t.Fatal("ambiguous/extra/oversize accepted")
		}
	}
}
func TestNoMockShellOrSourceConfigInArguments(t *testing.T) {
	m := policy()
	args := m.Arguments()
	joined := strings.Join(args, " ")
	for _, want := range []string{"-backend firecracker", "-firecracker-config /run/xandbox-inputs/backend.json", "-auth-file /run/xandbox-inputs/auth.json", "-max-instances 4", "-max-records 1024", "-max-sessions 32", "-metrics"} {
		if !strings.Contains(joined, want) {
			t.Fatal("fixed argument missing")
		}
	}
	for _, forbidden := range []string{"mock", m.Backend.Path, m.Auth.Path, "-insecure", "/bin/sh"} {
		if strings.Contains(joined, forbidden) {
			t.Fatal("unsafe argument")
		}
	}
	if m.Admission().MaxInstances != 4 || m.Admission().MaxRecords != 1024 || m.Admission().MaxSessions != 32 {
		t.Fatal("admission drift")
	}
}
func TestNestedBackendAndParentHeadroom(t *testing.T) {
	m := policy()
	c := config(m)
	if e := m.checkBackend(c); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*firecracker.Config){func(c *firecracker.Config) { c.Version = 2 }, func(c *firecracker.Config) { c.Node = nil }, func(c *firecracker.Config) { c.CgroupRoot = "/sys/fs/cgroup/foreign" }, func(c *firecracker.Config) { c.RuntimeRoot = m.StateDir }, func(c *firecracker.Config) { c.RuntimeRoot = m.StateDir + "/runtime" }} {
		bad := config(m)
		change(&bad)
		if e := m.checkBackend(bad); e == nil {
			t.Fatal("wrong backend accepted")
		}
	}
	for _, change := range []func(*Manifest){func(m *Manifest) { m.Parent.MemoryMax = 7 << 30 }, func(m *Manifest) { m.Parent.PidsMax = 384 }, func(m *Manifest) { m.Parent.CPUQuota = 799999 }, func(m *Manifest) { m.Parent.IOBytesPerSecond = 1 << 20 }} {
		bad := m
		change(&bad)
		if e := bad.checkBackend(c); e == nil {
			t.Fatal("no parent headroom accepted")
		}
	}
}
