//go:build linux && xandbox_host_fixture

package main

import (
	"os"
	"testing"
	"unsafe"
)

func TestQuotaUAPIAndFixedOperationAllowlist(t *testing.T) {
	if unsafe.Sizeof(quotaAttr{}) != 28 || unsafe.Offsetof(quotaAttr{}.Project) != 12 || unsafe.Sizeof(quotaRecord{}) != 72 || unsafe.Offsetof(quotaRecord{}.Valid) != 64 {
		t.Fatal("wrong Linux quota/file attribute UAPI layout")
	}
	for _, q := range []struct{ command, id uint32 }{{0x800001, 0}, {0x800004, 0}, {0x800007, quotaFirst}, {0x800008, quotaFirst + 2}} {
		bits, e := quotaCommand(q.command, q.id)
		if e != nil || bits != uintptr(q.command<<8|2) {
			t.Fatal("missing fixed quota operation", e)
		}
	}
	for _, q := range []struct{ command, id uint32 }{{0x800002, 0}, {0x800003, 0}, {0x800006, 0}, {0x800008, 0}, {0x800007, 42}, {0x800008, quotaFirst + 3}, {0x800001, quotaFirst}, {0x800004, quotaFirst}} {
		if _, e := quotaCommand(q.command, q.id); e == nil {
			t.Fatal("unsafe quota operation accepted")
		}
	}
}
func TestQuotaFixturesNeverRunInOrdinaryTestOrL0Process(t *testing.T) {
	if os.Getpid() == 1 {
		t.Fatal("test must not run as PID1")
	}
	if _, e := openQuotaFS(false); e == nil {
		t.Fatal("L1-only hardware guard bypassed")
	}
	if e := requireQuotaChild(); e == nil {
		t.Fatal("L1-only root child guard bypassed")
	}
	if e := quotaWorker("quota-drop"); e == nil {
		t.Fatal("capability-drop fixture escaped L1 guard")
	}
}
func TestQuotaMountAndCapabilityParsingIsExact(t *testing.T) {
	if !quotaOption("rw,prjquota", "prjquota") || quotaOption("rw,noprjquota", "prjquota") {
		t.Fatal("substring mount option match")
	}
	for _, status := range []string{"", "CapEff:\tbadmask\n", "CapEff:\t0000000001000000\nCapEff:\t0\n"} {
		if _, e := capabilityPresent(status, "CapEff", 24); e == nil {
			t.Fatal("malformed capability status accepted")
		}
	}
	present, e := capabilityPresent("CapEff:\t0000000001000000\n", "CapEff", 24)
	if e != nil || !present {
		t.Fatal("missing resource capability")
	}
	present, e = capabilityPresent("CapBnd:\t0000000000000000\n", "CapBnd", 24)
	if e != nil || present {
		t.Fatal("invented resource capability")
	}
}
func TestQuotaRequestAcceptsOnlyFixedPhaseLessOperation(t *testing.T) {
	if e := (nodeRequest{Version: 1, Operation: "quota-probe"}).validate(); e != nil {
		t.Fatal(e)
	}
	for _, phase := range []string{"1100001", "/dev/vda", "running"} {
		if e := (nodeRequest{Version: 1, Operation: "quota-probe", Phase: phase}).validate(); e == nil {
			t.Fatal("quota argument injection accepted")
		}
	}
}

func TestOrdinaryQuotaDriverHelpersCannotRunOnL0(t *testing.T) {
	if e := runQuotaDaemon(); e == nil {
		t.Fatal("fixed daemon cap drop escaped L1 guard")
	}
	if _, e := driverQuotaRead(driverProjectFirst); e == nil {
		t.Fatal("driver quota read escaped L1 guard")
	}
	if _, e := driverQuotaRead(0); e == nil {
		t.Fatal("arbitrary project read accepted")
	}
	for _, phase := range []string{"running", "stopped", "destroyed"} {
		if e := (nodeRequest{Version: 1, Operation: "quota-checkpoint", Phase: phase}).validate(); e != nil {
			t.Fatal(e)
		}
	}
	if e := (nodeRequest{Version: 1, Operation: "quota-checkpoint", Phase: "1300000"}).validate(); e == nil {
		t.Fatal("arbitrary quota phase accepted")
	}
}
