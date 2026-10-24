//go:build linux

package gateway

import (
	"bytes"
	"errors"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// One bounded declaration for replacing an UNCONSUMED proposal. No snapshot,
// key, previous supersession or recursive journal is embedded here.
const MaxPolicySupersession = 2 * MaxPolicyIntent

type PolicySupersession struct {
	Version                int          `json:"version"`
	ExpectedRevision       uint64       `json:"expected_revision"`
	RequestID              string       `json:"request_id"`
	ReplacesRequestID      string       `json:"replaces_request_id"`
	BaseCommitSHA256       string       `json:"base_commit_sha256"`
	ConfigSHA256           string       `json:"config_sha256"`
	InitialPolicySHA256    string       `json:"initial_policy_sha256"`
	OldPayloadSHA256       string       `json:"old_payload_sha256"`
	PreviousSnapshotSHA256 string       `json:"previous_snapshot_sha256"`
	NewPayloadSHA256       string       `json:"new_payload_sha256"`
	Source                 PolicySource `json:"source"`
	PreviousIntent         PolicyIntent `json:"previous_intent"`
	RecoverySHA256         string       `json:"recovery_sha256,omitempty"`
}

func (p PolicySupersession) NextIntent() PolicyIntent {
	return PolicyIntent{Version: 1, ExpectedRevision: p.ExpectedRevision, RequestID: p.RequestID, BaseCommitSHA256: p.BaseCommitSHA256, ConfigSHA256: p.ConfigSHA256, InitialPolicySHA256: p.InitialPolicySHA256, OldPayloadSHA256: p.OldPayloadSHA256, NewPayloadSHA256: p.NewPayloadSHA256, Source: p.Source}
}
func DecodePolicySupersession(c Config, base string, raw []byte) (PolicySupersession, error) {
	var s PolicySupersession
	bad := errors.New("invalid managed proposal supersession")
	if len(raw) == 0 || len(raw) > MaxPolicySupersession || strictjson.Decode(raw, &s) != nil || !bytes.Equal(raw, recoveryBytes(s)) {
		return s, bad
	}
	b, e := ManagedConfigDigest(c)
	if e != nil || s.Version != 1 || s.ExpectedRevision == 0 || s.ExpectedRevision == ^uint64(0) || !policyRequest.MatchString(s.RequestID) || !policyRequest.MatchString(s.ReplacesRequestID) || s.RequestID == s.ReplacesRequestID || !policySHA(base) || s.BaseCommitSHA256 != base || s.ConfigSHA256 != b || s.InitialPolicySHA256 != c.InitialPolicySHA256 || !policySHA(s.OldPayloadSHA256) || !policySHA(s.PreviousSnapshotSHA256) || !policySHA(s.NewPayloadSHA256) || s.NewPayloadSHA256 == s.OldPayloadSHA256 || !policySourceValid(s.Source) {
		return s, bad
	}
	i, e := DecodePolicyIntent(c, base, recoveryBytes(s.PreviousIntent))
	if e != nil {
		return s, bad
	}
	if s.RecoverySHA256 == "" {
		if i.ExpectedRevision != s.ExpectedRevision || i.OldPayloadSHA256 != s.OldPayloadSHA256 || i.RequestID != s.ReplacesRequestID {
			return s, bad
		}
	} else if !policySHA(s.RecoverySHA256) || i.ExpectedRevision+1 != s.ExpectedRevision || i.NewPayloadSHA256 != s.OldPayloadSHA256 || i.RequestID == s.ReplacesRequestID {
		return s, bad
	}
	if s.RequestID == i.RequestID {
		return s, bad
	}
	return s, nil
}

// Only maintenance may admit this view. Either the old intent or the fully
// synced FUTURE replacement intent fences the still-installed predecessor.
func ValidateSupersessionPredecessor(c Config, base string, payload, intent, record []byte) (PolicySupersession, error) {
	s, e := DecodePolicySupersession(c, base, record)
	if e != nil {
		return s, e
	}
	p, e := DecodeManagedEnvelope(c, payload, base)
	d, de := SnapshotDigest(p.Snapshot)
	if e != nil || de != nil || p.Revision != s.ExpectedRevision || p.RequestID == s.RequestID || policyBytesDigest(payload) != s.OldPayloadSHA256 || d != s.PreviousSnapshotSHA256 || (!bytes.Equal(intent, recoveryBytes(s.PreviousIntent)) && !bytes.Equal(intent, recoveryBytes(s.NextIntent()))) {
		return s, errors.New("managed supersession predecessor mismatch")
	}
	return s, nil
}
func ValidateVisiblePolicySupersession(c Config, base string, payload, intent, record []byte) (PolicySupersession, error) {
	s, e := DecodePolicySupersession(c, base, record)
	if e != nil {
		return s, e
	}
	p, e := DecodeManagedEnvelope(c, payload, base)
	if e != nil || p.Revision != s.ExpectedRevision+1 || p.RequestID != s.RequestID || p.ReplacedPendingRequestID != s.ReplacesRequestID || p.SupersededRequestID != "" || p.Source != s.Source || policyBytesDigest(payload) != s.NewPayloadSHA256 || !bytes.Equal(intent, recoveryBytes(s.NextIntent())) {
		return s, errors.New("managed supersession uncommitted")
	}
	return s, nil
}
