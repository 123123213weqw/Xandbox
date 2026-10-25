//go:build linux

package gateway

import (
	"bytes"
	"strings"
	"testing"
)

func recoveryRecordFixture(t *testing.T) (Config, string, []byte, []byte, []byte, PolicyRecovery) {
	t.Helper()
	c, initial, raw1 := managedTestConfig(t)
	p2 := rotatedEnvelope(t, c, initial)
	raw2, e := EncodePolicyEnvelope(p2)
	if e != nil {
		t.Fatal(e)
	}
	i2 := PolicyIntent{Version: 1, ExpectedRevision: 1, RequestID: p2.RequestID, BaseCommitSHA256: p2.BaseCommitSHA256, ConfigSHA256: p2.ConfigSHA256, InitialPolicySHA256: c.InitialPolicySHA256, OldPayloadSHA256: policyBytesDigest(raw1), NewPayloadSHA256: policyBytesDigest(raw2), Source: p2.Source}
	p3 := p2
	p3.Revision = 3
	p3.ExpectedRevision = 2
	p3.Snapshot.Epoch = 3
	p3.RequestID = strings.Repeat("d", 32)
	p3.SupersededRequestID = p2.RequestID
	p3.Source = PolicySource{Path: "/bootstrap/third.json", SHA256: strings.Repeat("e", 64)}
	raw3, e := EncodePolicyEnvelope(p3)
	if e != nil {
		t.Fatal(e)
	}
	d2, e := SnapshotDigest(p2.Snapshot)
	if e != nil {
		t.Fatal(e)
	}
	r := PolicyRecovery{Version: 1, ExpectedRevision: 2, RequestID: p3.RequestID, SupersedesRequestID: p2.RequestID, BaseCommitSHA256: p2.BaseCommitSHA256, ConfigSHA256: p2.ConfigSHA256, InitialPolicySHA256: c.InitialPolicySHA256, OldPayloadSHA256: policyBytesDigest(raw2), PreviousSnapshotSHA256: d2, NewPayloadSHA256: policyBytesDigest(raw3), Source: p3.Source, PreviousIntent: i2}
	return c, p2.BaseCommitSHA256, raw2, raw3, recoveryBytes(i2), r
}
func TestRecoveryRecordFencesPredecessorAndOldIntentUntilExactNewAuthority(t *testing.T) {
	c, base, old, next, intent, r := recoveryRecordFixture(t)
	raw := recoveryBytes(r)
	if _, e := DecodePolicyRecovery(c, base, raw); e != nil {
		t.Fatal(e)
	}
	if _, e := ValidateRecoveryPredecessor(c, base, old, intent, raw); e != nil {
		t.Fatal(e)
	}
	if _, e := ValidateVisiblePolicyRecovery(c, base, old, intent, raw, false); e == nil {
		t.Fatal("journal revived predecessor")
	}
	if _, e := ValidateVisiblePolicyRecovery(c, base, next, intent, raw, false); e == nil {
		t.Fatal("serving accepted old-intent/new-file window")
	}
	if _, e := ValidateVisiblePolicyRecovery(c, base, next, intent, raw, true); e != nil {
		t.Fatal("exact maintenance window", e)
	}
	if _, e := ValidateVisiblePolicyRecovery(c, base, next, recoveryBytes(r.NextIntent()), raw, false); e != nil {
		t.Fatal(e)
	}
	if _, e := ValidateRecoveryPredecessor(c, base, next, intent, raw); e == nil {
		t.Fatal("successor used as predecessor")
	}
	if _, e := ValidateVisiblePolicyRecovery(c, base, next, nil, raw, true); e == nil {
		t.Fatal("missing intent authorized")
	}
}
func TestRecoveryRecordClosedSchemaBindingCanonicalAndBounded(t *testing.T) {
	c, base, old, next, intent, r := recoveryRecordFixture(t)
	for name, mutate := range map[string]func(*PolicyRecovery){
		"version": func(r *PolicyRecovery) { r.Version++ }, "initial": func(r *PolicyRecovery) { r.ExpectedRevision = 1 }, "max": func(r *PolicyRecovery) { r.ExpectedRevision = ^uint64(0) },
		"request": func(r *PolicyRecovery) { r.RequestID = "invalid" }, "same-request": func(r *PolicyRecovery) { r.RequestID = r.SupersedesRequestID }, "old-request": func(r *PolicyRecovery) { r.SupersedesRequestID = strings.Repeat("f", 32) },
		"base": func(r *PolicyRecovery) { r.BaseCommitSHA256 = strings.Repeat("f", 64) }, "config": func(r *PolicyRecovery) { r.ConfigSHA256 = strings.Repeat("f", 64) }, "anchor": func(r *PolicyRecovery) { r.InitialPolicySHA256 = strings.Repeat("f", 64) },
		"old-hash": func(r *PolicyRecovery) { r.OldPayloadSHA256 = strings.Repeat("f", 64) }, "snapshot": func(r *PolicyRecovery) { r.PreviousSnapshotSHA256 = strings.Repeat("f", 64) }, "new-hash": func(r *PolicyRecovery) { r.NewPayloadSHA256 = strings.Repeat("f", 64) },
		"source": func(r *PolicyRecovery) { r.Source.Path = ManagedPolicyPath }, "previous-epoch": func(r *PolicyRecovery) { r.PreviousIntent.ExpectedRevision++ }, "previous-hash": func(r *PolicyRecovery) { r.PreviousIntent.NewPayloadSHA256 = strings.Repeat("f", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			mutate(&bad)
			raw := recoveryBytes(bad)
			_, pre := ValidateRecoveryPredecessor(c, base, old, intent, raw)
			_, visible := ValidateVisiblePolicyRecovery(c, base, next, recoveryBytes(r.NextIntent()), raw, false)
			if pre == nil && visible == nil {
				t.Fatal("invalid metadata accepted everywhere")
			}
		})
	}
	raw := recoveryBytes(r)
	for _, bad := range [][]byte{bytes.TrimSpace(raw), append([]byte(" "), raw...), append(raw, []byte("{}")...), append(bytes.TrimSuffix(raw, []byte("}\n")), []byte(",\"unknown\":1}\n")...), bytes.Repeat([]byte("x"), MaxPolicyRecovery+1)} {
		if _, e := DecodePolicyRecovery(c, base, bad); e == nil {
			t.Fatal("noncanonical/oversize record accepted")
		}
	}
	p, e := DecodeManagedEnvelope(c, next, base)
	if e != nil {
		t.Fatal(e)
	}
	for _, marker := range []string{"invalid", p.RequestID, strings.Repeat("A", 32)} {
		bad := p
		bad.SupersededRequestID = marker
		b, _ := EncodePolicyEnvelope(bad)
		if _, e = DecodeManagedEnvelope(c, b, base); e == nil {
			t.Fatal("unbound marker accepted")
		}
	}
}
