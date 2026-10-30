//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNodeLoadKernelParsersNeverSumUnrelatedDevicesOrInventMissingRows(t *testing.T) {
	raw := []byte("252:0 rbytes=11 wbytes=22 rios=3 wios=4 dbytes=0 dios=0\n253:0 rbytes=9000 wbytes=9000 rios=9 wios=9\n")
	v, e := nodeLoadIO(raw, "252:0")
	if e != nil || v["observed"] != 1 || v["wbytes"] != 22 || v["rbytes"] != 11 {
		t.Fatal(v, e)
	}
	v, e = nodeLoadIO(raw, "254:0")
	if e != nil || v["observed"] != 0 || v["wbytes"] != 0 {
		t.Fatal("missing row relabeled observed", v, e)
	}
	for _, bad := range []string{"252:0 rbytes=1 wbytes=2 rios=3", "252:0 rbytes=1 wbytes=2 rios=3 wios=-1", "252:0 rbytes=1 wbytes=2 rios=3 wios=4 rbytes=9", string(raw) + string(raw)} {
		if _, e := nodeLoadIO([]byte(bad), "252:0"); e == nil {
			t.Fatal("invalid device sample admitted")
		}
	}
	pairs, e := nodeLoadPairs([]byte("usage_usec 100\nthrottled_usec 2\nnr_throttled 1\n"))
	if e != nil || pairs["usage_usec"] != 100 {
		t.Fatal(e)
	}
	for _, bad := range []string{"max 1\nmax 2\n", "max -1", "max nan", "max 1 extra", strings.Repeat("x", 65537)} {
		if _, e := nodeLoadPairs([]byte(bad)); e == nil {
			t.Fatal("malformed primitive counter admitted")
		}
	}
}

func TestNodeLoadShadowObservationCannotReadOrMutateL0(t *testing.T) {
	n := &node{nodeLoad: true, nodeBudget: true, quotaDriver: true}
	if _, e := n.nodeLoadKernelCounters(nil); e == nil {
		t.Fatal("kernel reader escaped L1")
	}
	out := n.nodeLoadObserve(context.Background(), 0, strings.Repeat("a", 64), "", time.Now())
	if out.Available || out.Complete || out.RecordFound || out.Kernel != nil || out.LastError != "" || !out.OfferedOriginKnown {
		t.Fatal("observer ran outside owned L1")
	}
	preflight := n.nodeLoadObserve(context.Background(), 0, "", "", time.Time{})
	if preflight.OfferedOriginKnown || preflight.ElapsedMS != 0 {
		t.Fatal("preflight invented offered-clock timing")
	}
	if nodeLoadProbeAfter != 20*time.Second || nodeLoadProbeBudget != 2*time.Second || nodeLoadProbeSlots != 8 {
		t.Fatal("probe scope silently retuned")
	}
}

func TestNodeLoadShadowProbeHasFixedSlotsCancellationAndPrivateBounds(t *testing.T) {
	s := &nodeLoadState{observe: func(context.Context, int, string) nodeLoadObservation {
		return nodeLoadObservation{Available: true, LastError: "private-diagnostic-sentinel"}
	}}
	for i := 0; i < nodeLoadProbeSlots+2; i++ {
		trigger := make(chan time.Time, 1)
		trigger <- time.Now()
		done := make(chan struct{})
		// Wait for a completed probe, not a scheduler sleep or a fabricated elapsed time.
		previous := s.probesStarted + s.probesOmitted
		stop := s.nodeLoadProbe(context.Background(), trigger, 1, "never-export-this-key", 0, i)
		go func() {
			for {
				s.mu.Lock()
				n := len(s.privateDiagnostics.Slow) + s.probesOmitted
				s.mu.Unlock()
				if n > previous {
					close(done)
					return
				}
				time.Sleep(time.Millisecond)
			}
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("probe did not finish")
		}
		stop()
	}
	if s.probesStarted != 8 || s.probesOmitted != 2 || len(s.privateDiagnostics.Slow) != 8 {
		t.Fatal("unbounded probe allocation")
	}
	out, e := s.summary()
	if e != nil {
		t.Fatal(e)
	}
	capsule := out["private_load_diagnostics"].(nodeLoadPrivateDiagnostics)
	if nodeLoadPrivateBound(capsule) != nil || capsule.Slow[0].IntentIndex != 0 || capsule.Slow[0].Tenant != 1 {
		t.Fatal("unbound private observation")
	}
	b, e := json.Marshal(out)
	if e != nil || strings.Contains(string(b), "never-export-this-key") {
		t.Fatal("request capability escaped")
	}
	if !strings.Contains(string(b), "private_load_diagnostics") {
		t.Fatal("private evidence silently lost")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stop := s.nodeLoadProbe(ctx, make(chan time.Time), 0, "", 0, 0)
	stop()
	if s.probesOmitted != 2 {
		t.Fatal("invented observation after cancellation")
	}
	if nodeLoadPrivateBound(nodeLoadPrivateDiagnostics{Slow: []nodeLoadObservation{{LastError: strings.Repeat("x", 193<<10)}}}) == nil {
		t.Fatal("unbounded private capsule accepted")
	}
}

func TestNodeLoadFatalAPICodeIsClosedAnd500StaysFatal(t *testing.T) {
	for _, code := range []string{"INTERNAL", "NODE_DRAINING", "JOB_LIMIT", "private-error-token"} {
		_, e := nodeLoadReply(500, []byte(`{"error":{"code":"`+code+`","message":"private-response-body"}}`), 201, nil)
		if e == nil || strings.Contains(e.Error(), "private-response-body") || strings.Contains(e.Error(), "private-error-token") {
			t.Fatal("failure reclassified or raw text leaked", e)
		}
		want := nodeLoadClosedAPICode(code)
		if !strings.Contains(e.Error(), "code="+want) {
			t.Fatal("closed API cause discarded")
		}
	}
}
