//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

type nodeOOMTestTransport func(*http.Request) (*http.Response, error)

func (f nodeOOMTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNodeOOMOrdinaryStopRequires200AndExactStoppedRecord(t *testing.T) {
	ref := sandbox.Ref{ID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}
	good := sandbox.Record{Ref: ref, State: sandbox.Stopped, StoppedAt: time.Now().UTC()}
	for _, tc := range []struct {
		name   string
		status int
		change func(*sandbox.Record)
		pass   bool
	}{
		{"ordinary-synchronous-stop", 200, func(*sandbox.Record) {}, true},
		{"acceptance-not-stop", 202, func(*sandbox.Record) {}, false},
		{"wrong-generation", 200, func(r *sandbox.Record) { r.Generation = strings.Repeat("c", 32) }, false},
		{"wrong-id", 200, func(r *sandbox.Record) { r.ID = strings.Repeat("c", 32) }, false},
		{"still-stopping", 200, func(r *sandbox.Record) { r.State = sandbox.Stopping }, false},
		{"no-durable-stop", 200, func(r *sandbox.Record) { r.StoppedAt = time.Time{} }, false},
		{"reclaim-not-stop", 200, func(r *sandbox.Record) { r.DestroyedAt = time.Now().UTC() }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := good
			tc.change(&r)
			payload, e := json.Marshal(r)
			if e != nil {
				t.Fatal(e)
			}
			calls := 0
			api := &switchAPI{http: &http.Client{Transport: nodeOOMTestTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != "POST" || req.URL.Path != switchPath(ref)+"/stop" {
					t.Fatal("wrong ordinary operation")
				}
				var body map[string]string
				if e := json.NewDecoder(req.Body).Decode(&body); e != nil || len(body) != 1 || body["generation"] != ref.Generation {
					t.Fatal("generation binding lost")
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(string(payload))), Header: make(http.Header)}, nil
			})}}
			e = nodeOOMStop(context.Background(), api, ref)
			if calls != 1 || (e == nil) != tc.pass {
				t.Fatal("ordinary Stop contract changed", e)
			}
		})
	}
}

func TestNodeOOMFixedFixtureCannotAllocateOrOperateOnL0(t *testing.T) {
	if runNodeOOMPressure() == nil {
		t.Fatal("pressure helper escaped L1 child guard")
	}
	n := &node{nodeBudget: true, quotaDriver: true}
	ctx := context.Background()
	if _, e := n.nodeOOMCheckpoint(ctx); e == nil {
		t.Fatal("checkpoint escaped L1 PID1 guard")
	}
	if _, e := n.nodeOOMRecover(ctx); e == nil {
		t.Fatal("recovery escaped L1 PID1 guard")
	}
	if n.budgetFreshCheckpoint(ctx, nil, nil, nodeOOMCheckpointPhase) == nil {
		t.Fatal("checkpoint writer escaped L1 PID1 guard")
	}
	if _, e := n.recoverBudgetCheckpoint(ctx, "arbitrary"); e == nil {
		t.Fatal("recovery selector escaped L1")
	}
	if f, e := nodeOOMOpen("/dev/zero"); e == nil {
		f.Close()
		t.Fatal("observer escaped L1")
	}
	if _, e := nodeOOMEmpty("/sys/fs/cgroup"); e == nil {
		t.Fatal("empty observer escaped L1")
	}
	if _, _, e := budgetOwnerChild(sandbox.Ref{}); e == nil {
		t.Fatal("owner reader escaped L1 child guard")
	}
	if nodeOOMAllocation != 1<<30 || nodeOOMGuestBytes != 96<<20 || budgetPolicy().MemoryMax != 7<<30 || budgetPolicy().ControllerMemoryMax != 1<<30 {
		t.Fatal("fixed resource envelope changed")
	}
	for _, op := range []string{"node-oom-checkpoint", "node-oom-recover"} {
		if (nodeRequest{Version: 1, Operation: op}).validate() != nil {
			t.Fatal("fixed operation rejected")
		}
		if (nodeRequest{Version: 1, Operation: op, Phase: "arbitrary"}).validate() == nil {
			t.Fatal("arbitrary phase accepted")
		}
		if (nodeRequest{Version: 1, Operation: op, Receipt: []byte(`{}`)}).validate() == nil {
			t.Fatal("arbitrary receipt accepted")
		}
	}
}

func TestNodeOOMKernelRowsRejectMissingDuplicateOverflowAndTruncation(t *testing.T) {
	good := "low 0\nhigh 0\nmax 12\noom 3\noom_kill 2\noom_group_kill 1\n"
	testRead := func(s string) (nodeOOMEvents, error) {
		t.Helper()
		p := filepath.Join(t.TempDir(), "kernel-counter")
		if e := os.WriteFile(p, []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
		f, e := os.Open(p)
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		return nodeOOMReadEvents(f)
	}
	v, e := testRead(good)
	if e != nil || v != (nodeOOMEvents{12, 3, 2, 1}) {
		t.Fatal(v, e)
	}
	for _, bad := range []string{"", strings.TrimSuffix(good, "\n"), good + "oom_kill 1\n", strings.ReplaceAll(good, "max 12", "max +12"), strings.ReplaceAll(good, "max 12", "max -1"), strings.ReplaceAll(good, "max 12", "max 012"), strings.ReplaceAll(good, "max 12", "max 18446744073709551616"), strings.ReplaceAll(good, "oom_group_kill 1\n", ""), strings.ReplaceAll(good, "oom 3", "oom 3 extra"), strings.Repeat("x", 16385)} {
		if _, e = testRead(bad); e == nil {
			t.Fatal("invalid counter accepted")
		}
	}
	if d, e := v.delta(nodeOOMEvents{10, 2, 1, 0}); e != nil || d != (nodeOOMEvents{2, 1, 1, 1}) {
		t.Fatal(d, e)
	}
	for _, past := range []nodeOOMEvents{{13, 0, 0, 0}, {0, 4, 0, 0}, {0, 0, 3, 0}, {0, 0, 0, 2}, {math.MaxUint64, 0, 0, 0}} {
		if _, e = v.delta(past); e == nil {
			t.Fatal("counter reset/underflow accepted")
		}
	}
}

func TestNodeOOMMembershipIsOneExactExistingGeneration(t *testing.T) {
	id := strings.Repeat("a", 64)
	good := "0::/xandbox/instances/" + id + "\n"
	if path, e := nodeOOMMember([]byte(good)); e != nil || path != nodeBudgetInstances+"/"+id {
		t.Fatal(path, e)
	}
	for _, bad := range []string{strings.TrimSuffix(good, "\n"), good + good, strings.ReplaceAll(good, id, strings.Repeat("a", 63)), strings.ReplaceAll(good, id, strings.Repeat("A", 64)), strings.ReplaceAll(good, id, "../control"), "0::/xandbox/control\n", good + "0::/\n", strings.ReplaceAll(good, id, id+" (deleted)"), strings.ReplaceAll(good, "0::", "1::")} {
		if _, e := nodeOOMMember([]byte(bad)); e == nil {
			t.Fatal("unbound membership accepted", bad)
		}
	}
}

func TestNodeOOMPrivateDiagnosticsHaveNoCopyBypass(t *testing.T) {
	var b nodeOOMCapture
	if _, ok := any(&b).(io.ReaderFrom); ok {
		t.Fatal("promoted capture bypass")
	}
	n, e := io.Copy(&b, strings.NewReader(strings.Repeat("x", 65536)))
	if e != nil || n != 65536 || len(b.data) != 4096 {
		t.Fatal("private child diagnostics unbounded", n, e)
	}
	if n, e := b.Write([]byte("more")); e != nil || n != 4 || len(b.data) != 4096 {
		t.Fatal("bound changed after overflow")
	}
}

func TestNodeOOMRequiresEveryPrivilegeFieldAndNoImmunity(t *testing.T) {
	good := "Name:\tpressure\nUid:\t400000\t400000\t400000\t400000\nGid:\t400000\t400000\t400000\t400000\nGroups:\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n"
	if e := nodeOOMStatus([]byte(good), 400000); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"Uid:", "Gid:", "Groups:", "CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:", "NoNewPrivs:"} {
		lines := strings.Split(good, "\n")
		var omit []string
		var selected string
		for _, line := range lines {
			if strings.HasPrefix(line, field) {
				selected = line
				continue
			}
			omit = append(omit, line)
		}
		if nodeOOMStatus([]byte(strings.Join(omit, "\n")), 400000) == nil {
			t.Fatal("missing field accepted", field)
		}
		if nodeOOMStatus([]byte(good+selected+"\n"), 400000) == nil {
			t.Fatal("duplicate field accepted", field)
		}
	}
	for _, bad := range []string{strings.ReplaceAll(good, "NoNewPrivs:\t1", "NoNewPrivs:\t0"), strings.ReplaceAll(good, "Groups:\n", "Groups:\t0\n"), strings.ReplaceAll(good, "CapEff:\t0000000000000000", "CapEff:\t0000000000200000"), strings.ReplaceAll(good, "400000", "0")} {
		if nodeOOMStatus([]byte(bad), 400000) == nil {
			t.Fatal("privileged pressure accepted")
		}
	}
	if nodeOOMStatus([]byte(good), 399999) == nil || nodeOOMStatus([]byte(good), 400004) == nil || nodeOOMStatus([]byte(good), 400001) == nil {
		t.Fatal("wrong UID accepted")
	}
	// Truncated regular-file data is rejected independently of the row parser.
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	w.Close()
	if _, e = nodeOOMRead(r); e == nil || e == io.EOF {
		t.Fatal("non-seekable observer unexpectedly accepted")
	}
}

func TestNodeOOMColdReceiptCannotBorrowHealthyBudgetPhase(t *testing.T) {
	old := "11111111-1111-4111-8111-111111111111"
	fresh := "22222222-2222-4222-8222-222222222222"
	s := budgetCheckpoint{Node: nodeReceipt{Phase: nodeOOMCheckpointPhase, Ref: sandbox.Ref{ID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}, L1Boot: old, L2Boot: old, Key: strings.Repeat("c", 64)}, Config: strings.Repeat("d", 64)}
	if e := validateBudgetCheckpointIdentity(s, nodeOOMCheckpointPhase, fresh); e != nil {
		t.Fatal(e)
	}
	if validateBudgetCheckpointIdentity(s, nodeBudgetCheckpointPhase, fresh) == nil {
		t.Fatal("OOM receipt borrowed baseline recovery")
	}
	s.Node.Phase = nodeBudgetCheckpointPhase
	if validateBudgetCheckpointIdentity(s, nodeOOMCheckpointPhase, fresh) == nil {
		t.Fatal("baseline receipt borrowed OOM recovery")
	}
	if e := validateBudgetCheckpointIdentity(s, nodeBudgetCheckpointPhase, fresh); e != nil {
		t.Fatal(e)
	}
	if validateBudgetCheckpointIdentity(s, "arbitrary", fresh) == nil || validateBudgetCheckpointIdentity(s, nodeBudgetCheckpointPhase, old) == nil || validateBudgetCheckpointIdentity(s, nodeBudgetCheckpointPhase, "invalid") == nil {
		t.Fatal("unbound recovery accepted")
	}
	s.Node.Key = "invalid"
	if validateBudgetCheckpointIdentity(s, nodeBudgetCheckpointPhase, fresh) == nil {
		t.Fatal("invalid old replay key accepted")
	}
}
