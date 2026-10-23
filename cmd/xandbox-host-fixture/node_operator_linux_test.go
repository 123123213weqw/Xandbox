//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
)

func TestForeignOperatorEmptyCgroupIgnoresKernelFilesNotDirectoriesOrProcesses(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"cgroup.procs", "memory.max", "pids.max", "cgroup.events"} {
		if e := os.WriteFile(filepath.Join(root, name), nil, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := operatorEmptyInstances(root); e != nil {
		t.Fatal("kernel files counted as VMs", e)
	}
	if e := os.WriteFile(filepath.Join(root, "cgroup.procs"), []byte("12\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if operatorEmptyInstances(root) == nil {
		t.Fatal("instance parent process ignored")
	}
	if e := os.WriteFile(filepath.Join(root, "cgroup.procs"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(root, "unexpected-domain"), 0700); e != nil {
		t.Fatal(e)
	}
	if operatorEmptyInstances(root) == nil {
		t.Fatal("possible execution domain ignored")
	}
}

func TestOperatorFixtureAndForeignChildCannotOperateOnL0(t *testing.T) {
	n := &node{nodeBudget: true, quotaDriver: true}
	ctx := context.Background()
	if n.operatorProfile() == nil || runOperatorForeignChild() == nil || n.operatorForeign(ctx, nil, nodecontrol.State{}) == nil {
		t.Fatal("operator helper escaped fixed isolated L1")
	}
	if _, e := n.nodeOperatorCheckpoint(ctx); e == nil {
		t.Fatal("checkpoint escaped L1")
	}
	if _, e := n.nodeOperatorRecover(ctx); e == nil {
		t.Fatal("recovery escaped L1")
	}
	for _, op := range []string{"node-operator-checkpoint", "node-operator-recover"} {
		if (nodeRequest{Version: 1, Operation: op}).validate() != nil || (nodeRequest{Version: 1, Operation: op, Phase: "arbitrary"}).validate() == nil || (nodeRequest{Version: 1, Operation: op, Receipt: []byte(`{}`)}).validate() == nil {
			t.Fatal("operator RPC widened")
		}
	}
}
func operatorTestReceipt() operatorCheckpoint {
	var refs []sandbox.Ref
	for _, ch := range []string{"1", "2", "3", "4", "5"} {
		refs = append(refs, sandbox.Ref{ID: strings.Repeat(ch, 32), Generation: strings.Repeat("a", 32)})
	}
	cmd := nodecontrol.Command{Version: 1, Epoch: strings.Repeat("b", 32), ExpectedRevision: 5, RequestID: strings.Repeat("c", 32)}
	return operatorCheckpoint{Version: 1, Phase: "node-operator-ack-drained", L1Boot: "11111111-1111-4111-8111-111111111111", L2Boot: "22222222-2222-4222-8222-222222222222", L2Boots: []string{"11111111-1111-4111-8111-111111111111", "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555", "22222222-2222-4222-8222-222222222222"}, Config: strings.Repeat("d", 64), AllRefs: refs, Session: session.Result{ID: strings.Repeat("f", 32), Revision: 2, Current: refs[4], Previous: refs[1]}, SessionKey: strings.Repeat("1", 64), RawKey: strings.Repeat("2", 64), RejectedRawKey: strings.Repeat("3", 64), RejectedSessionKey: strings.Repeat("4", 64), LastDrain: cmd, Committed: nodecontrol.State{Version: 1, Epoch: cmd.Epoch, Revision: 6, Mode: nodecontrol.ModeDrained, LastRequestID: cmd.RequestID, LastExpectedRevision: 5}, StaleResume: nodecontrol.Command{Version: 1, Epoch: cmd.Epoch, ExpectedRevision: 4, RequestID: strings.Repeat("e", 32)}}
}
func TestOperatorColdReceiptRequiresExactCommandsEpochRoutesAndFiveKnownRefs(t *testing.T) {
	const boot = "33333333-3333-4333-8333-333333333333"
	if e := validateOperatorCheckpoint(operatorTestReceipt(), boot); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*operatorCheckpoint){
		func(s *operatorCheckpoint) { s.L1Boot = boot }, func(s *operatorCheckpoint) { s.AllRefs = s.AllRefs[:4] }, func(s *operatorCheckpoint) { s.AllRefs[0] = s.AllRefs[1] }, func(s *operatorCheckpoint) { s.Session.Previous = s.AllRefs[0] }, func(s *operatorCheckpoint) { s.Committed.Mode = nodecontrol.ModeOpen }, func(s *operatorCheckpoint) { s.Committed.Revision++ }, func(s *operatorCheckpoint) { s.LastDrain.ExpectedRevision-- }, func(s *operatorCheckpoint) { s.StaleResume.ExpectedRevision = 6 }, func(s *operatorCheckpoint) { s.StaleResume.Epoch = strings.Repeat("a", 32) }, func(s *operatorCheckpoint) { s.RawKey = "bad" }, func(s *operatorCheckpoint) { s.Config = "bad" }, func(s *operatorCheckpoint) { s.Phase = "running" },
	} {
		s := operatorTestReceipt()
		mutate(&s)
		if validateOperatorCheckpoint(s, boot) == nil {
			t.Fatal("unsafe cold receipt accepted")
		}
	}
}
func TestForeignOperatorRequiresPresentUniqueZeroCapabilityFields(t *testing.T) {
	good := "CapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n"
	if operatorForeignCapabilities(good) != nil {
		t.Fatal("zero capabilities rejected")
	}
	for _, s := range []string{"", strings.Replace(good, "CapPrm", "other", 1), strings.Replace(good, "0000000000000000", "0000000000000001", 1), good + "CapEff:\t0\n", strings.Replace(good, "0000000000000000", "bad!", 1)} {
		if operatorForeignCapabilities(s) == nil {
			t.Fatal("invalid capabilities accepted")
		}
	}
}
