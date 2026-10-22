//go:build linux && xandbox_host_fixture

package main

import (
	"encoding/binary"
	"encoding/json"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"os"
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

func TestDMUAPIAndCommandsExcludeGlobalDestruction(t *testing.T) {
	request, e := dmRequest(9)
	if e != nil || request != 0xc138fd09 {
		t.Fatal("wrong Linux dm table ABI", request, e)
	}
	for _, cmd := range []uint32{1, 2, 4, 5, 8, 10, 11, 13, 14, 255} {
		if _, e := dmRequest(cmd); e == nil {
			t.Fatal("unsafe dm command accepted", cmd)
		}
	}
	b := dmBuffer(dmSuspended | dmSkipLockFS | dmNoFlush)
	if len(b) != 4096 || binary.LittleEndian.Uint32(b[12:]) != 4096 || binary.LittleEndian.Uint32(b[16:]) != 312 || string(b[48:48+len(dmName)]) != dmName {
		t.Fatal("invalid fixed header")
	}
}

func TestDMTableCoversOnlyFixedWholeL1Disk(t *testing.T) {
	b, e := dmTable("linear", "252:0")
	if e != nil {
		t.Fatal(e)
	}
	s := b[dmHeader:]
	if binary.LittleEndian.Uint64(s) != 0 || binary.LittleEndian.Uint64(s[8:]) != 4194304 || string(s[40:48]) != "252:0 0\x00" {
		t.Fatal("wrong bounded linear target")
	}
	b, e = dmTable("error", "")
	if e != nil || string(b[dmHeader+24:dmHeader+29]) != "error" {
		t.Fatal("missing fixed error target")
	}
	for _, target := range []string{"flakey", "zero", "crypt", "linear /dev/sda"} {
		if _, e := dmTable(target, "252:0"); e == nil {
			t.Fatal("unexpected target accepted")
		}
	}
	for _, backing := range []string{"/dev/sda", "252:00", "+252:0", "252:0 0", "252:0;reboot", "-1:0"} {
		if _, e := dmTable("linear", backing); e == nil {
			t.Fatal("noncanonical backing accepted")
		}
	}
}

func TestStateMapperCannotRunOnL0OrAnOrdinaryTestProcess(t *testing.T) {
	if os.Getpid() == 1 {
		t.Fatal("unit tests must never run as PID1")
	}
	if _, e := setupStateMapper(); e == nil {
		t.Fatal("L1-only hardware guard bypassed")
	}
	for _, phase := range []string{"eio-busy", "eio-idle", "hang-busy", "hang-idle"} {
		if e := (nodeRequest{Version: 1, Operation: "io-fault", Phase: phase}).validate(); e != nil {
			t.Fatal(e)
		}
	}
	for _, phase := range []string{"/dev/sda", "linear", "hang-idle;reboot", "running", ""} {
		if e := (nodeRequest{Version: 1, Operation: "io-fault", Phase: phase}).validate(); e == nil {
			t.Fatal("arbitrary I/O operation accepted")
		}
	}
}
