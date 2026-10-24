package serviceready

import (
	"encoding/json"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"strings"
	"testing"
)

func policies() (Manifest, launch.Manifest) {
	m := Manifest{Version: 1, NodeLaunch: firecracker.Asset{Path: "/etc/xandbox/launch.json", SHA256: strings.Repeat("a", 64)}, Helper: firecracker.Asset{Path: HelperPath, SHA256: strings.Repeat("b", 64)}, Device: "253:0"}
	n := launch.Manifest{Version: 1, UnitRoot: "/sys/fs/cgroup/system.slice/xandbox.service", InputDir: "/run/xandbox-inputs", StateDir: "/srv/xb/s", Daemon: firecracker.Asset{Path: "/srv/assets/sandboxd", SHA256: strings.Repeat("c", 64)}, Backend: firecracker.Asset{Path: "/etc/xandbox/backend.json", SHA256: strings.Repeat("d", 64)}, Auth: firecracker.Asset{Path: "/etc/xandbox/auth.json", SHA256: strings.Repeat("e", 64)}, Frontend: launch.Frontend{MaxInstances: 4, MaxRecords: 1024, MaxTenantRecords: 512, MaxSessions: 32, MaxTenantSessions: 16, SessionHistory: 64, StopWorkers: 4, CleanupWorkers: 2, WorkQueueSize: 32}, Parent: launch.ParentEnvelope{MemoryMax: 15 << 29, PidsMax: 512, CPUQuota: 800000, IOBytesPerSecond: 512 << 20, IOOperationsPerSecond: 16384}}
	return m, n
}
func TestClosedManifest(t *testing.T) {
	m, _ := policies()
	data, _ := json.Marshal(m)
	if _, e := Decode(data); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Manifest){func(m *Manifest) { m.Version = 2 }, func(m *Manifest) { m.NodeLaunch.Path = "/etc/a%H" }, func(m *Manifest) { m.NodeLaunch.Path = "/etc/a b" }, func(m *Manifest) { m.NodeLaunch.Path = "/etc/a/../b" }, func(m *Manifest) { m.NodeLaunch.SHA256 = strings.Repeat("A", 64) }, func(m *Manifest) { m.Helper.Path = "/bin/sh" }, func(m *Manifest) { m.NodeLaunch.Path = m.Helper.Path }, func(m *Manifest) { m.Device = "0253:0" }, func(m *Manifest) { m.Device = "0:0" }, func(m *Manifest) { m.Device = "253:0\nextra" }} {
		bad := m
		change(&bad)
		b, _ := json.Marshal(bad)
		if _, e := Decode(b); e == nil {
			t.Fatal("invalid manifest accepted")
		}
	}
	for _, b := range [][]byte{[]byte(strings.Repeat(" ", 16385)), append(data[:len(data)-1], []byte(`,"version":1}`)...), append(data[:len(data)-1], []byte(`,"argv":"private"}`)...), []byte(`{"version":true}`)} {
		if _, e := Decode(b); e == nil {
			t.Fatal("ambiguous manifest accepted")
		}
	}
}
func TestDaemonUnitUsesFixedGateAndExactLimits(t *testing.T) {
	m, n := policies()
	unit, e := m.DaemonUnit(n, "/etc/xandbox/readiness.json", "/dev/vda")
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"Type=exec", "ExecStart=/usr/libexec/xandbox-launch -manifest /etc/xandbox/launch.json", "ExecStartPost=/usr/libexec/xandbox-ready -manifest /etc/xandbox/readiness.json", "DelegateSubgroup=bootstrap", "RuntimeDirectory=xandbox-inputs", "MemoryMax=8053063680", "TasksMax=512", "CPUQuota=800%", "IOReadIOPSMax=/dev/vda 16384", "CapabilityBoundingSet=~CAP_SYS_RESOURCE", "NoNewPrivileges=yes", "TimeoutStartSec=45s", "TimeoutStopSec=12s", "KillMode=mixed", "WantedBy=multi-user.target"} {
		if !strings.Contains(unit, v+"\n") {
			t.Fatal("missing closed unit field", v)
		}
	}
	for _, v := range []string{"/bin/sh", "ExecStartPre=", "ExecReload=", "$MAINPID", "%i", "Restart=always", "User=root", "Group=root", "-insecure", "mock"} {
		if strings.Contains(unit, v) {
			t.Fatal("unsafe unit field", v)
		}
	}
	for _, p := range []string{"/etc/a%H", "/etc/a b", "/etc/a\nExecStart=/bin/sh", m.NodeLaunch.Path} {
		if _, e := m.DaemonUnit(n, p, "/dev/vda"); e == nil {
			t.Fatal("unsafe manifest path")
		}
	}
	if _, e := m.DaemonUnit(n, "/etc/ready.json", "/dev/disk/by-id/disk"); e == nil {
		t.Fatal("device alias")
	}
	n.Parent.CPUQuota = 800001
	if _, e := m.DaemonUnit(n, "/etc/ready.json", "/dev/vda"); e == nil {
		t.Fatal("unrepresentable quota")
	}
	n.Parent.CPUQuota = 800010
	u, e := m.DaemonUnit(n, "/etc/ready.json", "/dev/vda")
	if e != nil || !strings.Contains(u, "CPUQuota=800.01%\n") {
		t.Fatal("exact percentage", e)
	}
}
