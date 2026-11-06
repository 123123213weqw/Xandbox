//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func nodeLoadSyntheticStat(pid int, comm, state, parent string) []byte {
	f := strings.Split(strings.TrimSpace(strings.Repeat("0 ", 20)), " ")
	f[0], f[1], f[19] = state, parent, "123"
	return []byte(fmt.Sprintf("%d (%s) %s\n", pid, comm, strings.Join(f, " ")))
}

func TestNodeLoadProcCensusParsersHandleCommsAndExactIdentity(t *testing.T) {
	// Synthetic parser controls only; never a claim that an actual zombie was observed.
	for _, comm := range []string{"firecracker", "xandbox-warden", "name ) with space", "private-token-sentinel"} {
		p, e := nodeLoadParseProcStat(7, nodeLoadSyntheticStat(7, comm, "Z", "1"))
		if e != nil || p.comm != comm || p.state != 'Z' || p.parent != 1 {
			t.Fatal("proc comm changed field positions", e)
		}
	}
	for _, b := range [][]byte{nodeLoadSyntheticStat(8, "x", "Z", "1"), nodeLoadSyntheticStat(7, "x", "?", "1"), nodeLoadSyntheticStat(7, "x", "Z", "-1"), []byte("7 (x) Z 1"), []byte(strings.Repeat("x", 8193))} {
		if _, e := nodeLoadParseProcStat(7, b); e == nil {
			t.Fatal("ambiguous proc identity accepted")
		}
	}
	uid, e := nodeLoadProcEUID([]byte("Name:\tprivate\nUid:\t0\t400003\t0\t0\n"))
	if e != nil || uid != 400003 {
		t.Fatal("effective UID not separated from real UID")
	}
	for _, s := range []string{"", "Uid: 0 1 2", "Uid: 0 -1 2 3", "Uid: 0 1 2 3\nUid: 0 1 2 3", "Uid: 0 4294967296 2 3"} {
		if _, e := nodeLoadProcEUID([]byte(s)); e == nil {
			t.Fatal("ambiguous UID accepted")
		}
	}
	for _, suffix := range []string{"", " (deleted)"} {
		b := []byte("0::/xandbox/instances/" + strings.Repeat("a", 64) + suffix + "\n")
		scoped, deleted, unknown := nodeLoadProcMembership(b)
		if !scoped || unknown || deleted != (suffix != "") {
			t.Fatal("lost exact owned/deleted membership")
		}
	}
	for _, s := range []string{"", "0::/", "0::/xandbox/control", "0::/xandbox/instances/unknown", "0::/xandbox/instances/" + strings.Repeat("a", 64) + "/child"} {
		scoped, deleted, unknown := nodeLoadProcMembership([]byte(s))
		if scoped || deleted || !unknown {
			t.Fatal("unknown membership relabeled as exact owned scope")
		}
	}
}

func TestNodeLoadProcCensusReadGuardNeverTouchesHost(t *testing.T) {
	n := &node{nodeLoad: true, nodeBudget: true, quotaDriver: true}
	out := n.nodeLoadPID1Census(context.Background(), "private-start-ticks")
	if out.Available || out.Complete || out.Candidates != 0 || out.Scanned != 0 || out.AdoptedZombies != 0 {
		t.Fatal("proc census escaped owned L1")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out = n.nodeLoadPID1Census(ctx, ""); out.Available || out.Scanned != 0 {
		t.Fatal("canceled census read host processes")
	}
	if nodeLoadProcLimit != 4096 {
		t.Fatal("process census bound silently changed")
	}
	b, e := json.Marshal(out)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"pid", "ppid", "comm", "uid", "cgroup", "startticks"} {
		if strings.Contains(string(b), `"`+name+`":`) {
			t.Fatal("raw process identity exported")
		}
	}
}

func TestNodeLoadProcCensusPreflightRejectsZombiesWithoutReapingOrRelaxingBudget(t *testing.T) {
	good := nodeLoadCensus{Available: true, Complete: true, Candidates: 16, Scanned: 16}
	if nodeLoadPreflightCensusValid(good) != nil {
		t.Fatal("clean synthetic predicate rejected")
	}
	for _, modify := range []func(*nodeLoadCensus){
		func(v *nodeLoadCensus) { v.Available = false }, func(v *nodeLoadCensus) { v.Complete = false },
		func(v *nodeLoadCensus) { v.ReadErrors = 1 }, func(v *nodeLoadCensus) { v.Truncated = true },
		func(v *nodeLoadCensus) { v.Scanned = 0 }, func(v *nodeLoadCensus) { v.Candidates = 1 },
		func(v *nodeLoadCensus) { v.ManagedControllerDead = true },
		func(v *nodeLoadCensus) { v.AdoptedZombies = 8; v.VMM = 8; v.ReservedUID = 8; v.MembershipUnknown = 8 },
	} {
		bad := good
		modify(&bad)
		before := bad
		if nodeLoadPreflightCensusValid(bad) == nil || bad != before {
			t.Fatal("failed/partial census repaired or accepted")
		}
	}
	if nodeLoadPolicy().PidsMax != 384 || nodeLoadPolicy().ControllerPidsMax != 128 {
		t.Fatal("census hid leak by increasing PID budgets")
	}
	s := &nodeLoadState{}
	s.privateDiagnostics.PreflightBefore = &good
	s.privateDiagnostics.PreflightAfter = &good
	out, e := s.summary()
	if e != nil || out["private_load_diagnostics"] == nil || len(s.rows) != 0 {
		t.Fatal("private preflight census lost or counted as measured rows")
	}
}
