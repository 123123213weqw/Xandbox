//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"golang.org/x/sys/unix"
)

func TestOperatorStoreNoL0AndOnlyTwoFixedPhases(t *testing.T) {
	n := &node{nodeBudget: true, quotaDriver: true}
	ctx := context.Background()
	if runOperatorStoreDaemon() == nil || n.stopOperatorDaemon(ctx) == nil {
		t.Fatal("store child escaped L1")
	}
	if _, e := n.startOperatorStoreObserved(ctx); e == nil {
		t.Fatal("observed start escaped L1")
	}
	o := &operatorStoreObserver{}
	if o.arm(operatorStorePre, nodecontrol.State{}, nodecontrol.State{}) == nil || o.heldValid() == nil {
		t.Fatal("observer control escaped L1")
	}
	if _, _, _, e := o.descriptor(quotaNotif{}); e == nil {
		t.Fatal("descriptor inspection escaped L1")
	}
	for _, mode := range []operatorStoreMode{operatorStorePre, operatorStorePost, "arbitrary", ""} {
		if _, e := n.nodeOperatorStoreCheckpoint(ctx, mode); e == nil {
			t.Fatal("checkpoint escaped L1")
		}
		if _, e := n.nodeOperatorStoreRecover(ctx, mode); e == nil {
			t.Fatal("recovery escaped L1")
		}
		for _, operation := range []string{"node-operator-store-checkpoint", "node-operator-store-recover"} {
			q := nodeRequest{Version: 1, Operation: operation, Phase: string(mode)}
			if (q.validate() == nil) != mode.valid() {
				t.Fatal("store RPC phase widened")
			}
			q.Receipt = []byte(`{}`)
			if q.validate() == nil {
				t.Fatal("arbitrary store receipt accepted")
			}
		}
	}
}
func TestOperatorStoreSequenceRequiresActualFileAndPostDirectoryProgress(t *testing.T) {
	if !operatorStoreControlMember("0::/xandbox/control\n") {
		t.Fatal("actual hierarchy-relative member rejected")
	}
	for _, value := range []string{"0::/sys/fs/cgroup/xandbox/control", "0::/xandbox/instances", "0::/other/control", "0::/xandbox/control\n1:cpu:/other"} {
		if operatorStoreControlMember(value) {
			t.Fatal("wrong control membership accepted")
		}
	}
	for _, mode := range []operatorStoreMode{operatorStorePre, operatorStorePost} {
		s := operatorStoreSnapshot{HeldID: 1, FileEntries: 1}
		if mode == operatorStorePost {
			s.AdmissionDirEntries, s.RootEntries = 1, 1
		}
		if operatorStoreSequence(mode, s) != nil {
			t.Fatal("fixed valid sequence rejected")
		}
		for _, mutate := range []func(*operatorStoreSnapshot){func(s *operatorStoreSnapshot) { s.HeldID = 0 }, func(s *operatorStoreSnapshot) { s.FileEntries++ }, func(s *operatorStoreSnapshot) { s.AdmissionDirEntries++ }, func(s *operatorStoreSnapshot) { s.RootEntries++ }, func(s *operatorStoreSnapshot) { s.Err = errors.New("failed") }} {
			bad := s
			mutate(&bad)
			if operatorStoreSequence(mode, bad) == nil {
				t.Fatal("incomplete/duplicate sequence accepted")
			}
		}
	}
	r := operatorStoreEIO(12)
	if r.ID != 12 || r.Error != -int32(unix.EIO) || r.Value != 0 || r.Flags != 0 {
		t.Fatal("response synthesized success or wrong errno")
	}
	if operatorTempPattern.MatchString(".state-1/other") || operatorTempPattern.MatchString(".state-1 (deleted)") || operatorTempPattern.MatchString(".identity-1") || !operatorTempPattern.MatchString(".state-123") {
		t.Fatal("temp name scope widened")
	}
}
func storeTestReceipt(mode operatorStoreMode) operatorStoreReceiptValue {
	before := nodecontrol.State{Version: 1, Epoch: strings.Repeat("a", 32), Revision: 1, Mode: nodecontrol.ModeOpen}
	command := nodecontrol.Command{Version: 1, Epoch: before.Epoch, ExpectedRevision: 1, RequestID: strings.Repeat("b", 32)}
	next := nodecontrol.State{Version: 1, Epoch: before.Epoch, Revision: 2, Mode: nodecontrol.ModeDrained, LastRequestID: command.RequestID, LastExpectedRevision: 1}
	expected, _ := operatorStoreExpected(mode, before, next)
	return operatorStoreReceiptValue{Version: 1, Mode: mode, L1Boot: "11111111-1111-4111-8111-111111111111", Config: strings.Repeat("c", 64), Before: before, Attempted: next, Expected: expected, Command: command, Raw: sandbox.Ref{ID: strings.Repeat("1", 32), Generation: strings.Repeat("2", 32)}, Session: session.Result{ID: strings.Repeat("3", 32), Revision: 1, Current: sandbox.Ref{ID: strings.Repeat("4", 32), Generation: strings.Repeat("5", 32)}}, RawKey: strings.Repeat("6", 64), SessionKey: strings.Repeat("7", 64), RejectedKey: strings.Repeat("8", 64), RawBoot: "22222222-2222-4222-8222-222222222222", SessionBoot: "33333333-3333-4333-8333-333333333333"}
}
func TestOperatorStoreColdReceiptDoesNotInventDurableFailedIntent(t *testing.T) {
	const boot = "44444444-4444-4444-8444-444444444444"
	for _, mode := range []operatorStoreMode{operatorStorePre, operatorStorePost} {
		s := storeTestReceipt(mode)
		if e := validateOperatorStoreReceipt(s, mode, boot); e != nil {
			t.Fatal(e)
		}
		for _, mutate := range []func(*operatorStoreReceiptValue){func(s *operatorStoreReceiptValue) {
			s.Expected = s.Attempted
			if mode == operatorStorePost {
				s.Expected = s.Before
			}
		}, func(s *operatorStoreReceiptValue) { s.Mode = "other" }, func(s *operatorStoreReceiptValue) { s.Command.ExpectedRevision++ }, func(s *operatorStoreReceiptValue) { s.Before.Epoch = strings.Repeat("f", 32) }, func(s *operatorStoreReceiptValue) { s.Session.Current = s.Raw }, func(s *operatorStoreReceiptValue) { s.RawBoot = s.SessionBoot }, func(s *operatorStoreReceiptValue) { s.L1Boot = boot }, func(s *operatorStoreReceiptValue) { s.Config = "bad" }} {
			bad := s
			mutate(&bad)
			if validateOperatorStoreReceipt(bad, mode, boot) == nil {
				t.Fatal("fabricated failed-intent/cold receipt accepted")
			}
		}
	}
}
