//go:build linux

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// One bounded recovery declaration, not a snapshot chain or a second current
// authority. No certificate/key is copied into this metadata record.
const MaxPolicyRecovery = 2 * MaxPolicyIntent

type PolicyRecovery struct {
	Version                int          `json:"version"`
	ExpectedRevision       uint64       `json:"expected_revision"`
	RequestID              string       `json:"request_id"`
	SupersedesRequestID    string       `json:"supersedes_request_id"`
	BaseCommitSHA256       string       `json:"base_commit_sha256"`
	ConfigSHA256           string       `json:"config_sha256"`
	InitialPolicySHA256    string       `json:"initial_policy_sha256"`
	OldPayloadSHA256       string       `json:"old_payload_sha256"`
	PreviousSnapshotSHA256 string       `json:"previous_snapshot_sha256"`
	NewPayloadSHA256       string       `json:"new_payload_sha256"`
	Source                 PolicySource `json:"source"`
	PreviousIntent         PolicyIntent `json:"previous_intent"`
}

func recoveryBytes(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		return nil
	}
	return append(b, '\n')
}
func DecodePolicyRecovery(c Config, base string, raw []byte) (PolicyRecovery, error) {
	var p PolicyRecovery
	bad := errors.New("invalid managed policy recovery")
	if len(raw) == 0 || len(raw) > MaxPolicyRecovery || strictjson.Decode(raw, &p) != nil || !bytes.Equal(raw, recoveryBytes(p)) {
		return p, bad
	}
	binding, e := ManagedConfigDigest(c)
	if e != nil || p.Version != 1 || p.ExpectedRevision < 2 || p.ExpectedRevision == ^uint64(0) || !policyRequest.MatchString(p.RequestID) || !policyRequest.MatchString(p.SupersedesRequestID) || p.RequestID == p.SupersedesRequestID || !policySHA(base) || p.BaseCommitSHA256 != base || p.ConfigSHA256 != binding || p.InitialPolicySHA256 != c.InitialPolicySHA256 || !policySHA(p.OldPayloadSHA256) || !policySHA(p.NewPayloadSHA256) || p.OldPayloadSHA256 == p.NewPayloadSHA256 || !policySHA(p.PreviousSnapshotSHA256) || !policySourceValid(p.Source) {
		return p, bad
	}
	i, e := DecodePolicyIntent(c, base, recoveryBytes(p.PreviousIntent))
	if e != nil || i.ExpectedRevision+1 != p.ExpectedRevision || i.RequestID != p.SupersedesRequestID || i.NewPayloadSHA256 != p.OldPayloadSHA256 {
		return p, bad
	}
	return p, nil
}
func (p PolicyRecovery) NextIntent() PolicyIntent {
	return PolicyIntent{Version: 1, ExpectedRevision: p.ExpectedRevision, RequestID: p.RequestID, BaseCommitSHA256: p.BaseCommitSHA256, ConfigSHA256: p.ConfigSHA256, InitialPolicySHA256: p.InitialPolicySHA256, OldPayloadSHA256: p.OldPayloadSHA256, NewPayloadSHA256: p.NewPayloadSHA256, Source: p.Source}
}
func ValidateRecoveryPredecessor(c Config, base string, payload, intent, record []byte) (PolicyRecovery, error) {
	r, e := DecodePolicyRecovery(c, base, record)
	if e != nil {
		return r, e
	}
	p, e := DecodeManagedEnvelope(c, payload, base)
	digest, de := SnapshotDigest(p.Snapshot)
	if e != nil || de != nil || p.Revision != r.ExpectedRevision || p.RequestID != r.SupersedesRequestID || policyBytesDigest(payload) != r.OldPayloadSHA256 || digest != r.PreviousSnapshotSHA256 || !bytes.Equal(intent, recoveryBytes(r.PreviousIntent)) {
		return r, errors.New("managed recovery predecessor mismatch")
	}
	return r, nil
}

// Normal serving/startup requires the new intent too. Maintenance recovery may
// observe the precise old intent during the one-file publication/intent-update
// window, but that is never permission to spawn a serving child.
func ValidateVisiblePolicyRecovery(c Config, base string, payload, intent, record []byte, maintenance bool) (PolicyRecovery, error) {
	r, e := DecodePolicyRecovery(c, base, record)
	if e != nil {
		return r, e
	}
	p, e := DecodeManagedEnvelope(c, payload, base)
	if e != nil || p.Revision != r.ExpectedRevision+1 || p.RequestID != r.RequestID || p.SupersededRequestID != r.SupersedesRequestID || p.Source != r.Source || policyBytesDigest(payload) != r.NewPayloadSHA256 {
		return r, errors.New("managed recovery uncommitted")
	}
	if bytes.Equal(intent, recoveryBytes(r.NextIntent())) || maintenance && bytes.Equal(intent, recoveryBytes(r.PreviousIntent)) {
		return r, nil
	}
	return r, errors.New("managed recovery intent mismatch")
}
