//go:build linux && xandbox_host_fixture

package main

import "testing"

func TestSystemdIngressResourcesAreSeparateAndKeepOriginalProfiles(t *testing.T) {
	p := testPolicy()
	p.Profile = "systemd-ingress-v1"
	m, d, c, e := p.resources()
	if e != nil || p.validate() != nil || m != 16384 || d != 24<<30 || c != 18<<30 || p.cpuCount() != 12 || p.pidCount() != 512 {
		t.Fatal("explicit ingress resource envelope")
	}
	args := p.arguments()
	have := map[string]string{}
	for i, a := range args {
		if a == "-m" || a == "-smp" || a == "-nic" {
			have[a] = args[i+1]
		}
	}
	if have["-m"] != "16384" || have["-smp"] != "12" || have["-nic"] != "none" {
		t.Fatal("actual bounded QEMU arguments")
	}
	for _, row := range []struct {
		profile        string
		mem, cpu, pids int
		disk           int64
		cg             uint64
	}{{"", 2048, 4, 128, 2 << 30, 3 << 30}, {"node-budget-v1", 8192, 8, 256, 12 << 30, 10 << 30}, {"node-snapshot-v1", 8192, 8, 256, 12 << 30, 10 << 30}} {
		p.Profile = row.profile
		m, d, c, e = p.resources()
		if e != nil || m != row.mem || d != row.disk || c != row.cg || p.cpuCount() != row.cpu || p.pidCount() != row.pids {
			t.Fatal("legacy profile silently changed")
		}
	}
	p.Profile = "systemd-ingress-v2"
	if p.validate() == nil || p.arguments() != nil {
		t.Fatal("unreviewed profile accepted")
	}
}
