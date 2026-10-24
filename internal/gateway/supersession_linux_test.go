//go:build linux

package gateway

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func supersessionRecordFixture(t *testing.T) (Config, string, []byte, []byte, PolicySupersession, []byte) {
	t.Helper()
	c, p, old := managedTestConfig(t)
	base := strings.Repeat("b", 64)
	next := rotatedEnvelope(t, c, p)
	next.RequestID = strings.Repeat("d", 32)
	next.ReplacedPendingRequestID = strings.Repeat("a", 32)
	nextRaw, _ := EncodePolicyEnvelope(next)
	prev := PolicyIntent{Version: 1, ExpectedRevision: 1, RequestID: next.ReplacedPendingRequestID, BaseCommitSHA256: base, ConfigSHA256: next.ConfigSHA256, InitialPolicySHA256: c.InitialPolicySHA256, OldPayloadSHA256: policyBytesDigest(old), NewPayloadSHA256: strings.Repeat("e", 64), Source: PolicySource{Path: "/bootstrap/abandoned.json", SHA256: strings.Repeat("f", 64)}}
	sha, _ := SnapshotDigest(p.Snapshot)
	s := PolicySupersession{Version: 1, ExpectedRevision: 1, RequestID: next.RequestID, ReplacesRequestID: prev.RequestID, BaseCommitSHA256: base, ConfigSHA256: next.ConfigSHA256, InitialPolicySHA256: c.InitialPolicySHA256, OldPayloadSHA256: policyBytesDigest(old), PreviousSnapshotSHA256: sha, NewPayloadSHA256: policyBytesDigest(nextRaw), Source: next.Source, PreviousIntent: prev}
	return c, base, old, nextRaw, s, recoveryBytes(prev)
}
func TestSupersessionClosedMetadataAndNoPredecessorStartup(t *testing.T) {
	c, base, old, next, s, prev := supersessionRecordFixture(t)
	raw := recoveryBytes(s)
	if _, e := DecodePolicySupersession(c, base, raw); e != nil {
		t.Fatal(e)
	}
	for _, intent := range [][]byte{prev, recoveryBytes(s.NextIntent())} {
		if _, e := ValidateSupersessionPredecessor(c, base, old, intent, raw); e != nil {
			t.Fatal(e)
		}
		if _, e := ValidateVisiblePolicySupersession(c, base, old, intent, raw); e == nil {
			t.Fatal("old credential restart allowed")
		}
	}
	if _, e := ValidateVisiblePolicySupersession(c, base, next, recoveryBytes(s.NextIntent()), raw); e != nil {
		t.Fatal(e)
	}
	if _, e := ValidateVisiblePolicySupersession(c, base, next, prev, raw); e == nil {
		t.Fatal("new file with old intent allowed")
	}
	for name, mutate := range map[string]func(*PolicySupersession){
		"version": func(s *PolicySupersession) { s.Version = 2 }, "zero": func(s *PolicySupersession) { s.ExpectedRevision = 0 }, "max": func(s *PolicySupersession) { s.ExpectedRevision = ^uint64(0) },
		"request": func(s *PolicySupersession) { s.RequestID = "invalid" }, "same-request": func(s *PolicySupersession) { s.RequestID = s.ReplacesRequestID }, "base": func(s *PolicySupersession) { s.BaseCommitSHA256 = strings.Repeat("e", 64) },
		"config": func(s *PolicySupersession) { s.ConfigSHA256 = strings.Repeat("e", 64) }, "initial": func(s *PolicySupersession) { s.InitialPolicySHA256 = strings.Repeat("e", 64) }, "payload": func(s *PolicySupersession) { s.OldPayloadSHA256 = "bad" },
		"same-payload": func(s *PolicySupersession) { s.NewPayloadSHA256 = s.OldPayloadSHA256 }, "snapshot": func(s *PolicySupersession) { s.PreviousSnapshotSHA256 = "bad" }, "source": func(s *PolicySupersession) { s.Source.Path = ManagedPolicyPath },
		"previous-epoch": func(s *PolicySupersession) { s.PreviousIntent.ExpectedRevision++ }, "previous-request": func(s *PolicySupersession) { s.PreviousIntent.RequestID = strings.Repeat("f", 32) }, "previous-old": func(s *PolicySupersession) { s.PreviousIntent.OldPayloadSHA256 = strings.Repeat("f", 64) },
		"recovery-wrong-kind": func(s *PolicySupersession) { s.RecoverySHA256 = strings.Repeat("f", 64) }, "recovery-hash": func(s *PolicySupersession) { s.RecoverySHA256 = "bad" },
	} {
		t.Run(name, func(t *testing.T) {
			v := s
			mutate(&v)
			if _, e := DecodePolicySupersession(c, base, recoveryBytes(v)); e == nil {
				t.Fatal("invalid record admitted")
			}
		})
	}
	for _, b := range [][]byte{bytes.TrimSpace(raw), append([]byte(" "), raw...), append(raw, []byte("{}")...), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"unknown":true`), 1), bytes.Repeat([]byte("x"), MaxPolicySupersession+1)} {
		if _, e := DecodePolicySupersession(c, base, b); e == nil {
			t.Fatal("noncanonical/unknown/unbounded record")
		}
	}
	for _, marker := range []string{"bad", s.RequestID} {
		p, e := DecodeManagedEnvelope(c, next, base)
		if e != nil {
			t.Fatal(e)
		}
		p.ReplacedPendingRequestID = marker
		b, _ := EncodePolicyEnvelope(p)
		if _, e = DecodeManagedEnvelope(c, b, base); e == nil {
			t.Fatal("invalid marker")
		}
	}
	p, _ := DecodeManagedEnvelope(c, next, base)
	p.SupersededRequestID = strings.Repeat("e", 32)
	b, _ := EncodePolicyEnvelope(p)
	if _, e := DecodeManagedEnvelope(c, b, base); e == nil {
		t.Fatal("conflicting recovery and replacement markers")
	}
}
func TestSupersessionRecoveryModeRequiresCommittedPreviousIntent(t *testing.T) {
	c, base, _, _, s, _ := supersessionRecordFixture(t)
	s.ExpectedRevision = 2
	s.RecoverySHA256 = strings.Repeat("a", 64)
	s.OldPayloadSHA256 = s.PreviousIntent.NewPayloadSHA256
	s.ReplacesRequestID = strings.Repeat("b", 32)
	if _, e := DecodePolicySupersession(c, base, recoveryBytes(s)); e != nil {
		t.Fatal(e)
	}
	s.PreviousIntent.ExpectedRevision = 2
	if _, e := DecodePolicySupersession(c, base, recoveryBytes(s)); e == nil {
		t.Fatal("future proposal admitted as committed predecessor")
	}
}
func TestConfirmExistingExactStateNeverCommitsCollectsOrServesExpiredPolicy(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s, auth := testSnapshot(t)
	s = snapshotWithValidity(t, s, now.Add(-48*time.Hour), now.Add(-24*time.Hour), nil)
	dir := t.TempDir()
	st, e := openPolicyState(dir, strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	if e = st.Commit(s); e != nil {
		t.Fatal(e)
	}
	st.Close()
	st, e = openExistingPolicyState(dir, strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	orphan, _ := json.Marshal(policyRecord{Version: 1, Revision: 2, SnapshotSHA256: strings.Repeat("b", 64)})
	if e = os.WriteFile(filepath.Join(dir, ".policy-123456789"), append(orphan, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	before := policyTreeImage(t, dir)
	if e = confirmPolicyState(st, s, auth); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, policyTreeImage(t, dir)) {
		t.Fatal("confirmation collected or rewrote state")
	}
	if _, e = NewPolicy(s, auth, now); e == nil {
		t.Fatal("confirmation revived serving validity")
	}
	for _, epoch := range []uint64{0, 2, 3, ^uint64(0)} {
		v := s
		v.Epoch = epoch
		if confirmPolicyState(st, v, auth) == nil {
			t.Fatal("non-exact epoch confirmed")
		}
	}
	v := s
	v.Keys = append([]ClientKey(nil), s.Keys...)
	v.Keys[0].TokenSHA256 = strings.Repeat("e", 64)
	if confirmPolicyState(st, v, auth) == nil || confirmPolicyState(st, s, nil) == nil || confirmPolicyState(nil, s, auth) == nil {
		t.Fatal("non-exact authority confirmed")
	}
	if !reflect.DeepEqual(before, policyTreeImage(t, dir)) {
		t.Fatal("rejected confirmation mutated state")
	}
	if e = os.WriteFile(filepath.Join(dir, "foreign"), []byte("test"), 0600); e != nil {
		t.Fatal(e)
	}
	before = policyTreeImage(t, dir)
	if confirmPolicyState(st, s, auth) == nil || !reflect.DeepEqual(before, policyTreeImage(t, dir)) {
		t.Fatal("foreign state repaired")
	}
}
