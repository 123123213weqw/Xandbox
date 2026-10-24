package ingresslaunch

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/launch"
)

func nodePolicy() launch.Manifest {
	return launch.Manifest{Version: 1, UnitRoot: "/sys/fs/cgroup/system.slice/xandbox.service", InputDir: "/run/xandbox-inputs", StateDir: "/srv/xb/s",
		Daemon: firecracker.Asset{Path: "/srv/assets/sandboxd", SHA256: strings.Repeat("a", 64)}, Backend: firecracker.Asset{Path: "/etc/xandbox/backend.json", SHA256: strings.Repeat("b", 64)}, Auth: firecracker.Asset{Path: "/etc/xandbox/auth.json", SHA256: strings.Repeat("c", 64)},
		Frontend: launch.Frontend{MaxInstances: 4, MaxRecords: 1024, MaxTenantRecords: 512, MaxSessions: 32, MaxTenantSessions: 16, SessionHistory: 64, StopWorkers: 4, CleanupWorkers: 2, WorkQueueSize: 32},
		Parent:   launch.ParentEnvelope{MemoryMax: 15 << 29, PidsMax: 512, CPUQuota: 800000, IOBytesPerSecond: 512 << 20, IOOperationsPerSecond: 16384}}
}
func policy() Manifest {
	return Manifest{Version: 1, UnitRoot: "/sys/fs/cgroup/system.slice/xandbox-ingress.service", PolicyStateDir: "/srv/xb/policy", Device: "253:0",
		Gateway: firecracker.Asset{Path: "/srv/assets/xandbox-gateway", SHA256: strings.Repeat("a", 64)}, Config: firecracker.Asset{Path: "/etc/xandbox/gateway.json", SHA256: strings.Repeat("b", 64)}, NodeLaunch: firecracker.Asset{Path: "/etc/xandbox/launch.json", SHA256: strings.Repeat("c", 64)},
		Ingress:  launch.ParentEnvelope{MemoryMax: 512 << 20, PidsMax: 64, CPUQuota: 200000, IOBytesPerSecond: 64 << 20, IOOperationsPerSecond: 2048},
		Reserve:  launch.ParentEnvelope{MemoryMax: 2 << 30, PidsMax: 64, CPUQuota: 200000, IOBytesPerSecond: 128 << 20, IOOperationsPerSecond: 4096},
		Capacity: launch.ParentEnvelope{MemoryMax: 12 << 30, PidsMax: 1024, CPUQuota: 1200000, IOBytesPerSecond: 1 << 30, IOOperationsPerSecond: 32768}}
}
func TestManifestClosedSchema(t *testing.T) {
	m := policy()
	b, _ := json.Marshal(m)
	got, e := Decode(b)
	if e != nil || got != m {
		t.Fatal("valid manifest rejected", e)
	}
	for _, raw := range []string{string(b[:len(b)-1]) + `,"version":1}`, string(b[:len(b)-1]) + `,"argv":["private"]}`, strings.Replace(string(b), `"version":1`, `"version":true`, 1), strings.Replace(string(b), `"version":1`, `"version":1.1`, 1), strings.Repeat(" ", 16385), "null", "{}"} {
		if _, e = Decode([]byte(raw)); e == nil {
			t.Fatal("ambiguous manifest accepted")
		}
	}
}
func TestManifestRejectsAliasesInjectionAndUnboundedValues(t *testing.T) {
	changes := []func(*Manifest){
		func(m *Manifest) { m.Version = 2 }, func(m *Manifest) { m.UnitRoot += "/child" }, func(m *Manifest) { m.UnitRoot = "/sys/fs/cgroup/user.slice/a.service" }, func(m *Manifest) { m.UnitRoot = "/sys/fs/cgroup/system.slice/%i.service" }, func(m *Manifest) { m.PolicyStateDir = "/srv/a/../policy" }, func(m *Manifest) { m.PolicyStateDir = "/srv/a\nExecStart=/bin/sh" }, func(m *Manifest) { m.Config.Path = "/etc/a b" }, func(m *Manifest) { m.Gateway.Path = "/bin/sh" }, func(m *Manifest) { m.Config.Path = m.NodeLaunch.Path }, func(m *Manifest) { m.NodeLaunch.Path = m.PolicyStateDir + "/launch.json" }, func(m *Manifest) { m.Config.SHA256 = "A" + strings.Repeat("a", 63) }, func(m *Manifest) { m.Device = "253:0\n8:0" }, func(m *Manifest) { m.Device = "0253:0" }, func(m *Manifest) { m.Device = "0:0" }, func(m *Manifest) { m.Ingress.MemoryMax = 0 }, func(m *Manifest) { m.Ingress.PidsMax = math.MaxUint64 }, func(m *Manifest) { m.Reserve.CPUQuota = 0 }, func(m *Manifest) { m.Capacity.IOBytesPerSecond = math.MaxUint64 }, func(m *Manifest) { m.Capacity.IOOperationsPerSecond = 0 },
	}
	for i, change := range changes {
		m := policy()
		change(&m)
		b, _ := json.Marshal(m)
		if _, e := Decode(b); e == nil {
			t.Fatalf("invalid manifest accepted: %d", i)
		}
	}
}
func TestEntireDaemonParentAndReserveCountedInEveryDimension(t *testing.T) {
	if e := policy().CheckComposition(nodePolicy()); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 5; i++ {
		m := policy()
		n := nodePolicy()
		switch i {
		case 0:
			m.Capacity.MemoryMax = n.Parent.MemoryMax + m.Ingress.MemoryMax + m.Reserve.MemoryMax - 1
		case 1:
			m.Capacity.PidsMax = n.Parent.PidsMax + m.Ingress.PidsMax + m.Reserve.PidsMax - 1
		case 2:
			m.Capacity.CPUQuota = n.Parent.CPUQuota + m.Ingress.CPUQuota + m.Reserve.CPUQuota - 1
		case 3:
			m.Capacity.IOBytesPerSecond = n.Parent.IOBytesPerSecond + m.Ingress.IOBytesPerSecond + m.Reserve.IOBytesPerSecond - 1
		case 4:
			m.Capacity.IOOperationsPerSecond = n.Parent.IOOperationsPerSecond + m.Ingress.IOOperationsPerSecond + m.Reserve.IOOperationsPerSecond - 1
		}
		if m.CheckComposition(n) == nil {
			t.Fatalf("dimension overcommitted: %d", i)
		}
	}
	for _, change := range []func(*Manifest){func(m *Manifest) { m.UnitRoot = nodePolicy().UnitRoot }, func(m *Manifest) { m.PolicyStateDir = nodePolicy().StateDir }, func(m *Manifest) { m.PolicyStateDir = nodePolicy().StateDir + "/policy" }, func(m *Manifest) { m.PolicyStateDir = "/srv/xb" }, func(m *Manifest) { m.Reserve.MemoryMax = math.MaxUint64 }} {
		m := policy()
		change(&m)
		if m.CheckComposition(nodePolicy()) == nil {
			t.Fatal("invalid composition accepted")
		}
	}
	n := nodePolicy()
	n.Version = 0
	if policy().CheckComposition(n) == nil {
		t.Fatal("invalid daemon policy accepted")
	}
}
func TestUnitHasSeparateBudgetAndNoShellOrControlHelper(t *testing.T) {
	m := policy()
	unit, e := m.Unit(nodePolicy(), "/etc/xandbox/ingress-launch.json", "/dev/vda")
	if e != nil {
		t.Fatal(e)
	}
	for _, text := range []string{"BindsTo=xandbox.service", "After=xandbox.service", "PartOf=xandbox.service", "WantedBy=xandbox.service", "Delegate=no", "MemoryMax=536870912", "OOMPolicy=kill", "TasksMax=64", "CPUQuota=200.000%", "IOReadBandwidthMax=/dev/vda 67108864", "IOWriteIOPSMax=/dev/vda 2048", "CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_SYS_CHROOT", "ProtectControlGroups=yes", "ReadWritePaths=/srv/xb/policy", "KillMode=control-group"} {
		if !strings.Contains(unit, text) {
			t.Fatal("missing unit contract", text)
		}
	}
	for _, bad := range []string{"ExecStartPre=", "ExecReload=", "ExecStop=", "/bin/sh", "DelegateSubgroup=", "CAP_SYS_ADMIN", "CAP_SYS_RESOURCE", "%i", "Restart=always"} {
		if strings.Contains(unit, bad) {
			t.Fatal("unsafe helper or contract", bad)
		}
	}
	for _, values := range [][2]string{{"/etc/a b", "/dev/vda"}, {"/etc/a%H", "/dev/vda"}, {"/etc/a", "/dev/disk/by-id/disk"}, {"/etc/a", "/dev/vda\nExecStart=/bin/sh"}} {
		if _, e = m.Unit(nodePolicy(), values[0], values[1]); e == nil {
			t.Fatal("unit injection accepted")
		}
	}
	m.Ingress.CPUQuota = 200001
	m.Capacity.CPUQuota++
	unit, e = m.Unit(nodePolicy(), "/etc/xandbox/ingress-launch.json", "/dev/vda")
	if e != nil || !strings.Contains(unit, "CPUQuota=200.001%") {
		t.Fatal("CPU unit conversion drift")
	}
}
