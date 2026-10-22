//go:build linux && xandbox_host_fixture

package main

import (
	"encoding/json"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"strings"
	"testing"
)

func TestLifecycleBodyDoesNotInventAnIDFieldRejectedByStrictAPI(t *testing.T) {
	b, e := json.Marshal(generationBody(sandbox.Ref{ID: "private", Generation: "generation"}))
	if e != nil {
		t.Fatal(e)
	}
	if string(b) != `{"generation":"generation"}` {
		t.Fatal("incorrect lifecycle request fields")
	}
}

func testPolicy() launchPolicy {
	h := strings.Repeat("a", 64)
	return launchPolicy{Version: 1, Root: "/srv/nh-abcdef", Cgroup: "/sys/fs/cgroup/xandbox-nested-proof-abcdef/" + h,
		UID: 850100, KVMGroup: 109, Warden: "/var/lib/private/warden", WardenSHA: h, FixtureSHA: h, QEMUSHA: h, KernelSHA: h, InitrdSHA: h}
}

func TestLaunchPolicyCannotTargetSharedRuntimeOrCgroup(t *testing.T) {
	p := testPolicy()
	if e := p.validate(); e != nil {
		t.Fatal(e)
	}
	for _, f := range []func(*launchPolicy){func(p *launchPolicy) { p.Root = "/srv" }, func(p *launchPolicy) { p.Cgroup = "/sys/fs/cgroup" },
		func(p *launchPolicy) { p.Cgroup = strings.Replace(p.Cgroup, "abcdef", "012345", 1) }, func(p *launchPolicy) { p.Root += "/../root" },
		func(p *launchPolicy) { p.UID = 0 }, func(p *launchPolicy) { p.KVMGroup = 0 }, func(p *launchPolicy) { p.QEMUSHA = "" }} {
		q := p
		f(&q)
		if q.validate() == nil {
			t.Fatal("unsafe fixture target accepted")
		}
	}
}

func TestQEMUArgumentsHaveNoNetworkTCGFallbackOrUnsafeCache(t *testing.T) {
	a := strings.Join(testPolicy().arguments(), " ")
	for _, required := range []string{"accel=kvm", "-cpu host,vmx=on", "-nic none", "format=raw,cache=none,aio=native", "werror=report,rerror=report", "-sandbox on", "mem-merge=off", "dump-guest-core=off"} {
		if !strings.Contains(a, required) {
			t.Fatalf("missing %s", required)
		}
	}
	for _, bad := range []string{"tcg", "cache=unsafe", "-netdev", "/dev/sda", "-daemonize", "-virtfs"} {
		if strings.Contains(a, bad) {
			t.Fatal("unsafe fixture fallback/host device")
		}
	}
}

func TestControlOperationsAreFixedAndHaveNoHostCommandSurface(t *testing.T) {
	for _, q := range []nodeRequest{{Version: 1, Operation: "probe"}, {Version: 1, Operation: "recover"}, {Version: 1, Operation: "checkpoint", Phase: "running"}, {Version: 1, Operation: "checkpoint", Phase: "stopped"}, {Version: 1, Operation: "checkpoint", Phase: "destroyed"}} {
		if e := q.validate(); e != nil {
			t.Fatal(e)
		}
	}
	for _, q := range []nodeRequest{{Version: 0, Operation: "probe"}, {Version: 1, Operation: "exec"}, {Version: 1, Operation: "checkpoint", Phase: "arbitrary"}, {Version: 1, Operation: "recover", Phase: "running"}} {
		if q.validate() == nil {
			t.Fatal("unbounded operation accepted")
		}
	}
}
