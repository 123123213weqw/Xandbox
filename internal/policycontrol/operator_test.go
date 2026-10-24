package policycontrol

import (
	"strings"
	"testing"
)

func operatorTestStatus(epoch, active uint64, phase string) PolicyStatus {
	s := PolicyStatus{Version: 1, DurableEpoch: epoch, SnapshotSHA256: strings.Repeat("a", 64), ActiveEpoch: active, Phase: phase}
	if active != 0 {
		s.ActiveSHA256 = s.SnapshotSHA256
	}
	return s
}

func TestOperatorClosedCommandsAndObservations(t *testing.T) {
	status := PolicyCommand{Version: 1, Operation: "status"}
	activate := PolicyCommand{Version: 1, Operation: "activate", ExpectedEpoch: 1, TargetEpoch: 2, SnapshotSHA256: strings.Repeat("b", 64)}
	if !status.Valid() || !activate.Valid() {
		t.Fatal("valid commands rejected")
	}
	for _, mutate := range []func(*PolicyCommand){
		func(c *PolicyCommand) { c.Version = 2 }, func(c *PolicyCommand) { c.Operation = "reload" },
		func(c *PolicyCommand) { c.TargetEpoch = 3 }, func(c *PolicyCommand) { c.ExpectedEpoch = ^uint64(0); c.TargetEpoch = 0 },
		func(c *PolicyCommand) { c.SnapshotSHA256 = strings.Repeat("B", 64) }, func(c *PolicyCommand) { c.SnapshotSHA256 = strings.Repeat("z", 64) },
		func(c *PolicyCommand) { c.SnapshotSHA256 = "" },
	} {
		c := activate
		mutate(&c)
		if c.Valid() {
			t.Fatal("invalid activation accepted")
		}
	}
	for _, mutate := range []func(*PolicyCommand){
		func(c *PolicyCommand) { c.TargetEpoch = 1 }, func(c *PolicyCommand) { c.ExpectedEpoch = 1 }, func(c *PolicyCommand) { c.SnapshotSHA256 = activate.SnapshotSHA256 },
	} {
		c := status
		mutate(&c)
		if c.Valid() {
			t.Fatal("status became a mutation")
		}
	}
	for _, s := range []PolicyStatus{operatorTestStatus(1, 0, "waiting"), operatorTestStatus(1, 1, "active"), operatorTestStatus(1, 1, "committing"), operatorTestStatus(2, 1, "waiting"), operatorTestStatus(2, 0, "fenced")} {
		if !s.Valid() {
			t.Fatal("valid status rejected")
		}
	}
	for _, s := range []PolicyStatus{operatorTestStatus(0, 0, "waiting"), operatorTestStatus(1, 1, "waiting"), operatorTestStatus(2, 1, "active"), operatorTestStatus(2, 1, "committing"), operatorTestStatus(1, 2, "fenced"), operatorTestStatus(1, 0, "healthy")} {
		if s.Valid() {
			t.Fatal("contradictory status accepted")
		}
	}
	good := operatorTestStatus(1, 1, "active")
	for _, mutate := range []func(*PolicyStatus){
		func(s *PolicyStatus) { s.Version = 2 }, func(s *PolicyStatus) { s.SnapshotSHA256 = "" },
		func(s *PolicyStatus) { s.ActiveSHA256 = strings.Repeat("b", 64) }, func(s *PolicyStatus) { s.ActiveEpoch = 0 },
		func(s *PolicyStatus) { s.ActiveSHA256 = strings.Repeat("A", 64) },
	} {
		s := good
		mutate(&s)
		if s.Valid() {
			t.Fatal("invalid status accepted")
		}
	}
}

func TestOperatorMonotonicProgressAndExactRetryClassification(t *testing.T) {
	initial := operatorTestStatus(1, 0, "waiting")
	active := operatorTestStatus(1, 1, "active")
	committing := operatorTestStatus(1, 1, "committing")
	waiting := operatorTestStatus(2, 1, "waiting")
	waiting.SnapshotSHA256 = strings.Repeat("b", 64)
	rotated := waiting
	rotated.ActiveEpoch = 2
	rotated.ActiveSHA256 = rotated.SnapshotSHA256
	rotated.Phase = "active"
	states := []PolicyStatus{initial, active, committing, waiting, rotated}
	for i, old := range states {
		for j, next := range states {
			if got, want := validPolicyTransition(old, next), i == j || j == i+1; got != want {
				t.Fatalf("progress edge %d -> %d: %v", i, j, got)
			}
		}
		fenced := old
		fenced.Phase = "fenced"
		if !validPolicyTransition(old, fenced) || !validPolicyTransition(fenced, fenced) {
			t.Fatal("cannot fence")
		}
		if validPolicyTransition(fenced, old) {
			t.Fatal("fence implicitly reopened")
		}
		for _, s := range states {
			if validPolicyTransition(fenced, s) {
				t.Fatal("fenced status escaped")
			}
		}
	}
	command := PolicyCommand{Version: 1, Operation: "activate", ExpectedEpoch: 1, TargetEpoch: 2, SnapshotSHA256: waiting.SnapshotSHA256}
	if duplicate, e := Classify(command, active); e != nil || duplicate {
		t.Fatal("new CAS rejected")
	}
	for _, s := range []PolicyStatus{waiting, rotated} {
		if duplicate, e := Classify(command, s); e != nil || !duplicate {
			t.Fatal("lost-response retry not exact")
		}
	}
	for _, s := range []PolicyStatus{initial, committing} {
		if _, e := Classify(command, s); e == nil {
			t.Fatal("activation admitted before prior ACK")
		}
	}
	for _, mutate := range []func(*PolicyCommand){
		func(c *PolicyCommand) { c.SnapshotSHA256 = strings.Repeat("c", 64) },
		func(c *PolicyCommand) { c.ExpectedEpoch = 0; c.TargetEpoch = 1 },
		func(c *PolicyCommand) { c.ExpectedEpoch = 3; c.TargetEpoch = 4 },
		func(c *PolicyCommand) { c.Operation = "status" },
	} {
		c := command
		mutate(&c)
		if _, e := Classify(c, rotated); e == nil {
			t.Fatal("conflicting retry accepted")
		}
	}
	fenced := waiting
	fenced.Phase = "fenced"
	if _, e := Classify(command, fenced); e == nil {
		t.Fatal("fenced retry reported success")
	}
	max := operatorTestStatus(^uint64(0), ^uint64(0), "active")
	c := PolicyCommand{Version: 1, Operation: "activate", ExpectedEpoch: ^uint64(0) - 1, TargetEpoch: ^uint64(0), SnapshotSHA256: max.SnapshotSHA256}
	if duplicate, e := Classify(c, max); e != nil || !duplicate {
		t.Fatal("last exact retry wrapped")
	}
	bad := waiting
	bad.DurableEpoch = 3
	if validPolicyTransition(committing, bad) {
		t.Fatal("durable commit skipped an epoch")
	}
}
