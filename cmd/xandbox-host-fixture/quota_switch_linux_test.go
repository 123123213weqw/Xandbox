//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func TestSwitchResourceProfileIsExplicitAndOldBoundsStayFixed(t *testing.T) {
	p := testPolicy()
	m, d, c, e := p.resources()
	if e != nil || m != 2048 || d != 2<<30 || c != 3<<30 {
		t.Fatal("legacy bounds changed")
	}
	p.Profile = "quota-switch-v1"
	if p.validate() != nil {
		t.Fatal("fixed profile rejected")
	}
	m, d, c, e = p.resources()
	if e != nil || m != 3072 || d != 4<<30 || c != 4<<30 {
		t.Fatal("wrong switch bounds")
	}
	a := strings.Join(p.arguments(), " ")
	if !strings.Contains(a, "-m 3072") || !strings.Contains(a, "accel=kvm") || !strings.Contains(a, "-nic none") {
		t.Fatal("unsafe new profile")
	}
	for _, v := range []string{"switch", "quota-switch-v2", "3072", "quota-switch-v1/extra"} {
		p.Profile = v
		if p.validate() == nil || p.arguments() != nil {
			t.Fatal("unbounded resource profile")
		}
	}
}
func TestSwitchOperationsCannotRunOnL0OrAcceptParameters(t *testing.T) {
	n := &node{quotaSwitch: true, quotaSnapshot: true}
	ctx := context.Background()
	if n.initializeQuotaSwitch() == nil || runQuotaSwitchDaemon() == nil {
		t.Fatal("L0 startup escaped")
	}
	if _, e := n.quotaSwitchSetup(ctx); e == nil {
		t.Fatal("L0 setup")
	}
	if _, e := n.quotaSwitchRun(ctx); e == nil {
		t.Fatal("L0 workload")
	}
	if _, e := n.quotaSwitchCheckpoint(ctx); e == nil {
		t.Fatal("L0 crash checkpoint")
	}
	if _, e := n.quotaSwitchRecover(ctx); e == nil {
		t.Fatal("L0 recovery")
	}
	if _, e := switchQuotaRead(nil, driverProjectFirst); e == nil {
		t.Fatal("L0 quota read")
	}
	for _, op := range []string{"quota-switch-setup", "quota-switch-run", "quota-switch-checkpoint", "quota-switch-recover"} {
		if (nodeRequest{Version: 1, Operation: op}).validate() != nil {
			t.Fatal("fixed op rejected")
		}
		if (nodeRequest{Version: 1, Operation: op, Phase: "120"}).validate() == nil {
			t.Fatal("caller-selected workload")
		}
	}
}
func TestSwitchQuantilesAndFixedMetricsDoNotHideBadSamples(t *testing.T) {
	rows := []switchRow{{BindingMS: 3, FirstCommandMS: 4, OldStoppedMS: 2, OldDestroyedMS: 5}, {BindingMS: 1, FirstCommandMS: 2, OldStoppedMS: 1, OldDestroyedMS: 3}, {BindingMS: 2, FirstCommandMS: 3, OldStoppedMS: 1.5, OldDestroyedMS: 4}}
	q := switchQuantiles(rows)
	if q["binding"]["p50"] != 2 || q["binding"]["p95"] != 3 || q["binding"]["count"] != 3 || rows[0].BindingMS != 3 {
		t.Fatal("not nearest rank or source reordered")
	}
	text := "xandbox_allocated 2\nxandbox_stop_queued 0\nxandbox_cleanup_queued 1\nxandbox_stop_running 0\nxandbox_cleanup_running 1\n"
	g, e := switchParseGauges(text)
	if e != nil || g["allocated"] != 2 {
		t.Fatal("fixed gauge rejected")
	}
	for _, s := range []string{strings.Replace(text, "xandbox_allocated 2\n", "", 1), text + "xandbox_allocated 0\n", strings.Replace(text, "allocated 2", "allocated -1", 1), strings.Replace(text, "allocated 2", "allocated NaN", 1)} {
		if _, e = switchParseGauges(s); e == nil {
			t.Fatal("bad gauge accepted")
		}
	}
	if _, e = readSwitchMetrics(strings.NewReader(strings.Repeat("x", (256<<10)+1))); e == nil {
		t.Fatal("unbounded metric reply")
	}
	if b, e := readSwitchMetrics(strings.NewReader(text)); e != nil || string(b) != text {
		t.Fatal("bounded metrics changed")
	}
}
func TestSwitchFreshnessAndBusyStopCannotPassOnTimeoutOrIgnoredShellFailure(t *testing.T) {
	if switchCycles != 120 || switchMinimumSeconds != 180 || switchSlots != 8 || switchCapacity != 4 {
		t.Fatal("workload target silently reduced")
	}
	if !strings.HasPrefix(switchFreshCommand()[2], "set -e;") || !strings.Contains(switchBusyWriter()[2], "while :") {
		t.Fatal("freshness/busy assertion weakened")
	}
	good := "12345678-1234-4234-9234-123456789abc"
	if b, e := switchGuestIdentity(sandbox.Output{Stdout: "65534\n" + good + "\n"}); e != nil || b != good {
		t.Fatal("guest identity rejected")
	}
	for _, v := range []string{"0\n" + good, "65534\n" + strings.Repeat("x", 36), "65534\n00000000-0000-0000-0000-000000000000", "65534\n" + good + " extra"} {
		if _, e := switchGuestIdentity(sandbox.Output{Stdout: v}); e == nil {
			t.Fatal("bad guest identity")
		}
	}
	for _, status := range []string{"RUNNING", "TIMED_OUT", "UNKNOWN", "EXITED"} {
		if switchOldJobStopped(sandbox.Job{Status: status, FinishedAt: time.Now()}) {
			t.Fatal("natural exit/timeout accepted as busy stop")
		}
	}
	for _, status := range []string{"CANCELLED", "FAILED"} {
		if !switchOldJobStopped(sandbox.Job{Status: status, FinishedAt: time.Now()}) || switchOldJobStopped(sandbox.Job{Status: status}) {
			t.Fatal("stop terminal handling wrong")
		}
	}
}
func TestSwitchPublicReplyBoundForFullTargetsAndNoPrivateIdentityFields(t *testing.T) {
	r := switchReport{Cycles: 120, Resources: make([]switchResource, 1252)}
	for i := range r.Workers {
		r.Workers[i].Rows = make([]switchRow, 120)
	}
	b, e := json.Marshal(r)
	if e != nil || len(b) > 1<<20 {
		t.Fatal("full target no longer fits explicit control reply bound")
	}
	for _, v := range []string{`"id":`, `"generation":`, `"token":`, `"argv":`, `"stdout":`, `"uid":`} {
		if strings.Contains(string(b), v) {
			t.Fatal("public report exposes private identity")
		}
	}
}
