//go:build linux

package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"os"

	"github.com/123123213weqw/Xandbox/internal/access"
)

// validatePolicyForDurableAdvance checks a previously committed payload at the
// leaf's validity boundary, not at wall-clock time. This is only a persistence
// primitive for an explicit maintenance transaction: no Policy escapes,
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
// mark. Only the fixed-path installer maintenance wrapper may use this; it is
// never a RunRoot/serving validator. Commit retains exact/+1 CAS and
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

// AdvanceManagedPolicyState is a fixed-path root installer maintenance primitive.
// The caller holds operation EX and install EX after ingress has been stopped,
// and proves the exact committed envelope plus the full immutable installation.
// The existing state EX lock independently excludes a surviving supervisor.
// No fresh state, listener, child descriptor or ACK is created here.
func AdvanceManagedPolicyState(c Config, authorityRaw, payload []byte, base string) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || c.Version != 2 || c.StateDir != "/srv/xi/p" || c.EmptyRoot != "/srv/xi/g/root" || c.TenantSocket != "/srv/xi/s/api.sock" || c.BackendAuthFile != "/run/xandbox-inputs/auth.json" {
		return errors.New("root fixed managed maintenance required")
	}
	p, e := DecodeManagedEnvelope(c, payload, base)
	if e != nil {
		return e
	}
	var config access.Config
	if strictjson.Decode(authorityRaw, &config) != nil {
		return errors.New("invalid managed maintenance authority")
	}
	authority, e := access.New(config)
	if e != nil {
		return e
	}
	if e = validatePolicyForDurableAdvance(p.Snapshot, authority); e != nil {
		return e
	}
	state, e := openExistingPolicyState(c.StateDir, gatewayBinding(c, authorityRaw))
	if e != nil {
		return e
	}
	defer state.Close()
	return advancePolicyState(state, p.Snapshot, authority)
}
