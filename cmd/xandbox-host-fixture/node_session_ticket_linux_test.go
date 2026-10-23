//go:build linux && xandbox_host_fixture

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
)

func ticketTestRecord(t *testing.T) session.Record {
	t.Helper()
	kh, sh, e := sessionTicketHashes(strings.Repeat("1", 64))
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	return session.Record{ID: strings.Repeat("2", 32), TenantID: "nested-fixture", CreateKeyHash: kh, CreateSpecHash: sh, State: session.Creating, CreatedAt: now, UpdatedAt: now.Add(time.Millisecond), Attempts: []session.Attempt{{KeyHash: kh, SpecHash: sh, ExpectedRevision: 0, ResultRevision: 1, State: session.Preparing, StartedAt: now}}}
}
func ticketTestEnvelope(t *testing.T, r session.Record) []byte {
	t.Helper()
	b, e := json.MarshalIndent(struct {
		Version int            `json:"version"`
		Record  session.Record `json:"record"`
	}{1, r}, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	return append(b, '\n')
}
func TestSessionTicketExactInitialEnvelopeRejectsProgressAndOtherIdentity(t *testing.T) {
	r := ticketTestRecord(t)
	b := ticketTestEnvelope(t, r)
	if _, e := sessionTicketInitial(b, r.CreateKeyHash, r.CreateSpecHash); e != nil {
		t.Fatal(e)
	}
	mutations := []func(*session.Record){
		func(r *session.Record) { r.ID = "bad" }, func(r *session.Record) { r.TenantID = "other" }, func(r *session.Record) { r.State = session.Active }, func(r *session.Record) { r.Revision = 1 },
		func(r *session.Record) {
			r.Current = sandbox.Ref{ID: strings.Repeat("3", 32), Generation: strings.Repeat("4", 32)}
		}, func(r *session.Record) { r.CreateKeyHash = strings.Repeat("0", 64) }, func(r *session.Record) { r.CreateSpecHash = strings.Repeat("0", 64) },
		func(r *session.Record) { r.Attempts = append(r.Attempts, r.Attempts[0]) }, func(r *session.Record) { r.Attempts[0].State = session.Prepared }, func(r *session.Record) { r.Attempts[0].KeyHash = strings.Repeat("0", 64) }, func(r *session.Record) { r.Attempts[0].SpecHash = strings.Repeat("0", 64) },
		func(r *session.Record) { r.Attempts[0].ExpectedRevision = 1 }, func(r *session.Record) { r.Attempts[0].ResultRevision = 2 }, func(r *session.Record) { r.Attempts[0].From.ID = strings.Repeat("3", 32) }, func(r *session.Record) { r.Attempts[0].Target.ID = strings.Repeat("3", 32) },
		func(r *session.Record) { r.Attempts[0].StartedAt = r.CreatedAt.Add(time.Second) }, func(r *session.Record) { r.Attempts[0].ReadyAt = r.CreatedAt }, func(r *session.Record) { r.Attempts[0].FencedAt = r.CreatedAt }, func(r *session.Record) { r.Attempts[0].CommitStartedAt = r.CreatedAt }, func(r *session.Record) { r.Attempts[0].Timings.Measured = true },
		func(r *session.Record) { r.CreatedAt = time.Time{} }, func(r *session.Record) { r.UpdatedAt = r.CreatedAt.Add(-time.Second) }, func(r *session.Record) { r.UpdatedAt = r.CreatedAt.Add(41 * time.Second) },
	}
	for index, mutate := range mutations {
		bad := r
		bad.Attempts = append([]session.Attempt(nil), r.Attempts...)
		mutate(&bad)
		if _, e := sessionTicketInitial(ticketTestEnvelope(t, bad), r.CreateKeyHash, r.CreateSpecHash); e == nil {
			t.Fatalf("forged ticket accepted %d", index)
		}
	}
	for _, bad := range [][]byte{nil, []byte(strings.Repeat("x", sessionTicketMax+1)), bytes.Replace(b, []byte(`"version": 1`), []byte(`"version": 2`), 1), bytes.Replace(b, []byte(`"current":`), []byte(`"foreign":`), 1), bytes.Replace(b, []byte("  \"revision\": 0,"), nil, 1), append(b, ' ')} {
		if bytes.Equal(b, bad) {
			t.Fatal("negative envelope mutation did not change bytes")
		}
		if _, e := sessionTicketInitial(bad, r.CreateKeyHash, r.CreateSpecHash); e == nil {
			t.Fatal("non-ordinary or oversized envelope accepted")
		}
	}
}
func TestSessionTicketFixedPathsAndPrivateHashInputOnly(t *testing.T) {
	for _, path := range []string{"/srv/state/sessions/.session-123", "/srv/state/sessions/.session-0"} {
		if !sessionTicketPath(path) {
			t.Fatal(path)
		}
	}
	for _, path := range []string{"/srv/state/admission/.state-1", "/srv/state/sessions/.session-x", "/srv/state/sessions/a.json", "/tmp/.session-1", "/srv/state/sessions/../sessions/.session-1", ".session-1"} {
		if sessionTicketPath(path) {
			t.Fatal("foreign descriptor selected", path)
		}
	}
	for _, key := range []string{"", strings.Repeat("x", 64), strings.Repeat("1", 63)} {
		if _, _, e := sessionTicketHashes(key); e == nil {
			t.Fatal("non-fixed private key accepted")
		}
	}
}
func ticketTestSaved() sessionTicketSaved {
	old := storeTestReceipt(operatorStorePost)
	return sessionTicketSaved{Version: 1, L1Boot: old.L1Boot, Config: old.Config, Before: old.Before, Committed: old.Attempted, Raw: old.Raw, Existing: old.Session, Accepted: session.Result{ID: strings.Repeat("a", 32), Revision: 1, Current: sandbox.Ref{ID: strings.Repeat("b", 32), Generation: strings.Repeat("c", 32)}}, RawKey: old.RawKey, ExistingKey: old.SessionKey, AcceptedKey: strings.Repeat("d", 64), RejectedKey: old.RejectedKey, RawBoot: old.RawBoot, ExistingBoot: old.SessionBoot, AcceptedBoot: "44444444-4444-4444-8444-444444444444"}
}
func TestSessionTicketColdReceiptRequiresExactAckAndDistinctGuests(t *testing.T) {
	const boot = "55555555-5555-4555-8555-555555555555"
	s := ticketTestSaved()
	if e := validateSessionTicketSaved(s, boot); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*sessionTicketSaved){func(s *sessionTicketSaved) { s.Version = 2 }, func(s *sessionTicketSaved) { s.Existing.Previous = s.Raw }, func(s *sessionTicketSaved) { s.Accepted.Previous = s.Raw }, func(s *sessionTicketSaved) { s.L1Boot = boot }, func(s *sessionTicketSaved) { s.Config = "bad" }, func(s *sessionTicketSaved) { s.Accepted = s.Existing }, func(s *sessionTicketSaved) { s.Accepted.Revision = 2 }, func(s *sessionTicketSaved) { s.Accepted.Current = s.Raw }, func(s *sessionTicketSaved) { s.AcceptedKey = s.ExistingKey }, func(s *sessionTicketSaved) { s.AcceptedBoot = s.RawBoot }, func(s *sessionTicketSaved) { s.Before.Mode = "drained" }, func(s *sessionTicketSaved) { s.Committed.Mode = "open" }, func(s *sessionTicketSaved) { s.Committed.Revision++ }, func(s *sessionTicketSaved) { s.Committed.LastExpectedRevision = 0 }, func(s *sessionTicketSaved) { s.Committed.Epoch = strings.Repeat("e", 32) }} {
		bad := s
		mutate(&bad)
		if validateSessionTicketSaved(bad, boot) == nil {
			t.Fatal("fabricated accepted-ticket/drain receipt accepted")
		}
	}
}
func TestSessionTicketNoL0OrGenericRPC(t *testing.T) {
	n := &node{nodeBudget: true, quotaDriver: true}
	ctx := context.Background()
	if _, e := n.nodeSessionTicketCheckpoint(ctx); e == nil {
		t.Fatal("L0 checkpoint")
	}
	if _, e := n.nodeSessionTicketRecover(ctx); e == nil {
		t.Fatal("L0 recover")
	}
	o := &operatorStoreObserver{}
	if e := o.armSessionTicket(strings.Repeat("1", 64), strings.Repeat("2", 32)); e == nil {
		t.Fatal("L0 arm")
	}
	for _, op := range []string{"node-session-ticket-checkpoint", "node-session-ticket-recover"} {
		q := nodeRequest{Version: 1, Operation: op}
		if e := q.validate(); e != nil {
			t.Fatal(e)
		}
		q.Phase = "arbitrary"
		if e := q.validate(); e == nil {
			t.Fatal("generic phase accepted")
		}
	}
}
