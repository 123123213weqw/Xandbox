//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"golang.org/x/sys/unix"
)

type switchTestTransport func(*http.Request) (*http.Response, error)

func (f switchTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSwitchSessionJobUsesActualPublicWireContractAndRejectsWrongBindings(t *testing.T) {
	ref := sandbox.Ref{ID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}
	binding := session.Result{ID: strings.Repeat("c", 32), Current: ref, Revision: 7}
	job := sandbox.Job{ID: strings.Repeat("d", 32), Ref: ref, Status: "RUNNING", StartedAt: time.Now()}
	// Match execSession's actual production response, not an invented nested Ref.
	wire := func(revision uint64, r sandbox.Ref, j sandbox.Job) []byte {
		b, e := json.Marshal(map[string]any{"revision": revision, "sandbox": r, "job": j})
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	good := wire(binding.Revision, ref, job)
	var decoded struct {
		Job sandbox.Job `json:"job"`
	}
	if json.Unmarshal(good, &decoded) != nil || decoded.Job.ID != job.ID || decoded.Job.Ref.ID != "" || decoded.Job.Generation != ref.Generation {
		t.Fatal("test no longer models the public embedded-ID JSON contract")
	}
	response := good
	lookup := false
	client := &switchAPI{token: "fixture-test", http: &http.Client{Transport: switchTestTransport(func(r *http.Request) (*http.Response, error) {
		wantPath, status := "/v1/sessions/"+binding.ID+"/exec", 202
		if lookup {
			wantPath, status = switchPath(ref)+"/executions/"+job.ID, 200
		}
		if r.URL.Path != wantPath || r.Header.Get("Authorization") != "Bearer fixture-test" {
			t.Fatal("wrong fixed API request")
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(response))), Header: make(http.Header)}, nil
	})}}
	actual, e := client.sessionJob(context.Background(), binding, []string{"true"})
	if e != nil || actual.ID != job.ID || actual.Ref != ref {
		t.Fatal("valid session job binding not reconstructed", e)
	}
	wrongRef := ref
	wrongRef.ID = strings.Repeat("e", 32)
	wrongGen := job
	wrongGen.Generation = strings.Repeat("f", 32)
	invalidID := job
	invalidID.ID = "bad"
	for _, bad := range [][]byte{wire(6, ref, job), wire(7, wrongRef, job), wire(7, ref, wrongGen), wire(7, ref, invalidID), []byte(`{"revision":7}`)} {
		response = bad
		if _, e = client.sessionJob(context.Background(), binding, []string{"true"}); e == nil {
			t.Fatal("wrong session execution binding accepted")
		}
	}
	lookup = true
	response, _ = json.Marshal(job)
	if got, e := client.job(context.Background(), ref, actual); e != nil || got.Ref != ref || got.ID != job.ID {
		t.Fatal("valid job lookup binding", e)
	}
	wrongID := job
	wrongID.ID = strings.Repeat("e", 32)
	for _, bad := range []sandbox.Job{wrongID, wrongGen} {
		response, _ = json.Marshal(bad)
		if _, e = client.job(context.Background(), ref, actual); e == nil {
			t.Fatal("wrong lookup identity accepted")
		}
	}
	if _, e = client.job(context.Background(), wrongRef, actual); e == nil {
		t.Fatal("caller bound job to a different sandbox")
	}
}

func TestSwitchPrivateCrashReceiptPreservesExplicitJobReference(t *testing.T) {
	ref := sandbox.Ref{ID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}
	saved := switchCrashReceipt{Version: 3}
	saved.Bindings[0] = switchSavedBinding{Binding: session.Result{Current: ref}, JobRef: ref, JobID: strings.Repeat("c", 32)}
	b, e := json.Marshal(saved)
	if e != nil {
		t.Fatal(e)
	}
	var got switchCrashReceipt
	if json.Unmarshal(b, &got) != nil || got.Version != 3 || got.Bindings[0].JobRef != ref || got.Bindings[0].JobID != saved.Bindings[0].JobID || got.Bindings[0].Binding.Current != ref {
		t.Fatal("private receipt lost sandbox ID through embedded job-ID collision")
	}
}

func TestSwitchSharedCheckpointRejectsPreSecondCloneBaselineWithoutWaivingColdLinks(t *testing.T) {
	saved := switchCrashReceipt{Version: 3}
	for i := range saved.Bindings {
		entries := map[string]driverQuotaEntry{}
		for j, name := range []string{"root/template.mem", "root/template.state"} {
			entries[name] = driverQuotaEntry{Shared: true, Inode: uint64(100 + j), Links: 3, Mode: unix.S_IFREG | 0444, Size: 512 << 20, Blocks: 512 << 20}
		}
		entries["root/workspace.ext4"] = driverQuotaEntry{Inode: uint64(200 + i), Links: 1, Mode: unix.S_IFREG | 0600, Size: 128 << 20, Blocks: 128 << 20}
		saved.Bindings[i].Quota = driverQuotaReceipt{Snapshot: true, Project: driverProjectFirst + uint32(i), Entries: entries, Record: quotaRecord{BHard: 192 << 10, IHard: 128, Space: 128 << 20, Inodes: 1}}
	}
	if e := switchStableCheckpointSharing(saved); e != nil {
		t.Fatal("stable two-clone baseline rejected", e)
	}
	first := &saved.Bindings[0].Quota
	stale := first.Entries["root/template.mem"]
	stale.Links = 2
	first.Entries["root/template.mem"] = stale
	if switchStableCheckpointSharing(saved) == nil {
		t.Fatal("first-clone-only link count accepted as two-clone baseline")
	}
	// Re-sampling after both clones exist restores the exact actual link count;
	// it does not teach cold recovery to ignore legitimate metadata fields.
	stale.Links = 3
	first.Entries["root/template.mem"] = stale
	actual := map[string]driverQuotaEntry{}
	for k, v := range first.Entries {
		actual[k] = v
	}
	if e := validateDriverQuotaAccounting(*first, first.Record, 128<<20, 1, actual); e != nil {
		t.Fatal("stable cold metadata", e)
	}
	changed := actual["root/template.mem"]
	changed.Links = 4
	actual["root/template.mem"] = changed
	if validateDriverQuotaAccounting(*first, first.Record, 128<<20, 1, actual) == nil {
		t.Fatal("cold link-count drift was waived")
	}
	for _, name := range []string{"root/template.mem", "root/template.state"} {
		original := first.Entries[name]
		bad := original
		bad.Inode++
		first.Entries[name] = bad
		if switchStableCheckpointSharing(saved) == nil {
			t.Fatal("different backing inode accepted")
		}
		first.Entries[name] = original
	}
	saved.Version = 2
	if switchStableCheckpointSharing(saved) == nil {
		t.Fatal("old checkpoint semantics accepted")
	}
}

func TestSwitchMissingJobHistoryIsNotStopProofOrAnInventedTerminalStatus(t *testing.T) {
	row := switchRow{BusyOldRunning: true, BusyProgress: true, OldStoppedMS: 25, OldDestroyedMS: 40, OldTimeoutMS: 59000}
	missing := &switchHTTPStatusError{Got: 404, Want: 200}
	if status, e := switchOldJobOutcome(sandbox.Job{}, missing, row); e != nil || status != "HISTORY_DROPPED_AFTER_RECLAIM" {
		t.Fatal("actual reclamation contract", e)
	}
	for _, bad := range []switchRow{
		{BusyOldRunning: true, OldStoppedMS: 25, OldDestroyedMS: 40, OldTimeoutMS: 59000},
		{BusyOldRunning: true, BusyProgress: true, OldStoppedMS: 25, OldDestroyedMS: 0, OldTimeoutMS: 59000},
		{BusyOldRunning: true, BusyProgress: true, OldStoppedMS: 25, OldDestroyedMS: 24, OldTimeoutMS: 59000},
		{BusyOldRunning: true, BusyProgress: true, OldStoppedMS: 25, OldDestroyedMS: 40, OldTimeoutMS: 25},
		{BusyOldRunning: true, BusyProgress: true, OldStoppedMS: math.NaN(), OldDestroyedMS: 40, OldTimeoutMS: 59000},
	} {
		if _, e := switchOldJobOutcome(sandbox.Job{}, missing, bad); e == nil {
			t.Fatal("404 substituted for independent physical/durable proof")
		}
	}
	for _, e := range []error{&switchHTTPStatusError{Got: 500, Want: 200}, context.Canceled, errors.New("transport")} {
		if _, got := switchOldJobOutcome(sandbox.Job{}, e, row); got == nil {
			t.Fatal("non404 failure ignored")
		}
	}
	for _, status := range []string{"RUNNING", "TIMED_OUT", "EXITED", "UNKNOWN"} {
		if _, e := switchOldJobOutcome(sandbox.Job{Status: status, FinishedAt: time.Now()}, nil, row); e == nil {
			t.Fatal("invalid terminal passed")
		}
	}
	if status, e := switchOldJobOutcome(sandbox.Job{Status: "CANCELLED", FinishedAt: time.Now()}, nil, row); e != nil || status != "CANCELLED" {
		t.Fatal("observed terminal rejected")
	}
}

func TestSwitchBusyProofRequiresSecondGuestExecutionBeforeRunningCheck(t *testing.T) {
	ref := sandbox.Ref{ID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}
	binding := session.Result{ID: strings.Repeat("c", 32), Revision: 1, Current: ref}
	busy := sandbox.Job{ID: strings.Repeat("d", 32), Ref: ref, Status: "RUNNING"}
	probe := sandbox.Job{ID: strings.Repeat("e", 32), Ref: ref, Status: "EXITED", FinishedAt: time.Now()}
	step := 0
	client := &switchAPI{http: &http.Client{Transport: switchTestTransport(func(r *http.Request) (*http.Response, error) {
		step++
		var value any
		status := 200
		switch step {
		case 1, 2:
			var body struct {
				Argv []string `json:"argv"`
			}
			if r.Method != "POST" || r.URL.Path != "/v1/sessions/"+binding.ID+"/exec" || json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Fatal("unexpected guest operation")
			}
			want, job := switchBusyWriter(), busy
			if step == 2 {
				want, job = switchBusyProgressCommand(), probe
			}
			if strings.Join(body.Argv, "\x00") != strings.Join(want, "\x00") {
				t.Fatal("actual guest progress command missing or wrong order")
			}
			value, status = map[string]any{"revision": 1, "sandbox": ref, "job": job}, 202
		case 3:
			if r.URL.Path != switchPath(ref)+"/executions/"+probe.ID {
				t.Fatal("progress was not awaited")
			}
			value = probe
		case 4:
			if r.URL.Path != switchPath(ref)+"/executions/"+busy.ID {
				t.Fatal("old job was not rechecked after progress")
			}
			value = busy
		default:
			t.Fatal("unexpected additional request")
		}
		b, _ := json.Marshal(value)
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header)}, nil
	})}}
	began := time.Now()
	job, deadline, e := client.waitBusy(context.Background(), binding)
	if e != nil || step != 4 || job.ID != busy.ID || job.Ref != ref || deadline.Before(began.Add(60*time.Second)) || deadline.After(time.Now().Add(60*time.Second)) {
		t.Fatal("busy proof/deadline contract", e)
	}
}

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
	if switchRunBudget != 720*time.Second || switchSampleLimit != 1450 || switchReplyMax != 2<<20 {
		t.Fatal("unreviewed bounded experiment change")
	}
	r := switchReport{Cycles: 120, Resources: make([]switchResource, switchSampleLimit+2)}
	for i := range r.Workers {
		r.Workers[i].Rows = make([]switchRow, 120)
	}
	b, e := json.Marshal(r)
	if e != nil || len(b) > switchReplyMax {
		t.Fatal("full target no longer fits explicit control reply bound")
	}
	for _, v := range []string{`"id":`, `"generation":`, `"token":`, `"argv":`, `"stdout":`, `"uid":`} {
		if strings.Contains(string(b), v) {
			t.Fatal("public report exposes private identity")
		}
	}
}
