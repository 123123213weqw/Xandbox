//go:build linux

package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/123123213weqw/Xandbox/internal/access"
)

// validatePolicyForDurableAdvance checks a previously committed payload at the
// leaf's validity boundary, not at wall-clock time. This is only a persistence
// primitive for a future explicit maintenance transaction: no Policy escapes,
// no child descriptor/listener/ACK is produced, and no serving validator uses
// this function. Normal startup and new candidate admission use actual time.
func validatePolicyForDurableAdvance(s Snapshot, authority *access.Authenticator) error {
	if authority == nil {
		return errors.New("managed advance authority required")
	}
	if _, e := SnapshotDigest(s); e != nil {
		return e
	}
	pair, e := tls.X509KeyPair([]byte(s.CertificatePEM), []byte(s.PrivateKeyPEM))
	if e != nil || len(pair.Certificate) == 0 {
		return errors.New("invalid managed advance policy")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || !leaf.NotBefore.Before(leaf.NotAfter) {
		return errors.New("invalid managed advance policy")
	}
	_, e = NewPolicy(s, authority, leaf.NotBefore)
	return e
}

// advancePolicyState only raises (or confirms) an existing durable high-water
// mark. It is intentionally private and NOT wired into RunRoot or an operator
// command yet. A complete installer maintenance/old-file proof is still needed
// before an operational caller can be added. Commit retains exact/+1 CAS and
// its ordinary inventory/binding checks; there is no reset, skip or bootstrap.
func advancePolicyState(state *policyState, s Snapshot, authority *access.Authenticator) error {
	if state == nil || state.record.Revision == 0 || s.Epoch < 2 {
		return errors.New("managed advance requires existing policy state")
	}
	if e := validatePolicyForDurableAdvance(s, authority); e != nil {
		return e
	}
	return state.Commit(s)
}
