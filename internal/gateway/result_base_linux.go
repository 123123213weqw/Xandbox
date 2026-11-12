//go:build linux

package gateway

import (
	"encoding/json"
	"errors"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// Immutable gateway/policy base ONLY, not complete file/artifact/config/ABI or
// install authority. Version2 is a NEW cold genesis, NEVER an existing-base
// rewrite. The full versioned installer startup verifier remains mandatory.
func ValidateManagedResultBase(c Config, configRaw, commitRaw []byte) (string, error) {
	bad := errors.New("invalid managed gateway base commit")
	var config Config
	if strictjson.Decode(configRaw, &config) != nil {
		return "", bad
	}
	a, e := ManagedConfigDigest(c)
	b, be := ManagedConfigDigest(config)
	if e != nil || be != nil || a != b {
		return "", bad
	}
	var top map[string]json.RawMessage
	if len(commitRaw) == 0 || len(commitRaw) > 65536 || strictjson.Decode(commitRaw, &top) != nil || len(top) != 6 {
		return "", bad
	}
	for _, key := range []string{"version", "revision", "request_id", "plan", "release", "files"} {
		if _, ok := top[key]; !ok {
			return "", bad
		}
	}
	var ref struct {
		Version   int    `json:"version"`
		Revision  uint64 `json:"revision"`
		RequestID string `json:"request_id"`
		Plan      struct {
			Version int           `json:"version"`
			Gateway PolicySource  `json:"gateway"`
			Policy  *PolicySource `json:"policy"`
		} `json:"plan"`
		Files []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Bytes  int64  `json:"bytes"`
			Mode   uint32 `json:"mode"`
		} `json:"files"`
	}
	if json.Unmarshal(commitRaw, &ref) != nil || ref.Version != 2 || ref.Revision != 1 || !policyRequest.MatchString(ref.RequestID) || ref.Plan.Version != 2 || ref.Plan.Policy == nil || ref.Plan.Policy.SHA256 != c.InitialPolicySHA256 || ref.Plan.Gateway.SHA256 != policyBytesDigest(configRaw) || len(ref.Files) != 24 {
		return "", bad
	}
	seen := map[string]bool{}
	gateway, policy := false, false
	for _, f := range ref.Files {
		if seen[f.Path] || !canonicalPolicyPath(f.Path) || f.Bytes <= 0 || !policySHA(f.SHA256) {
			return "", bad
		}
		seen[f.Path] = true
		if f.Path == managedRoot+"/gateway.json" {
			gateway = f.SHA256 == ref.Plan.Gateway.SHA256 && f.Mode == 0600 && f.Bytes == int64(len(configRaw))
		}
		if f.Path == ManagedPolicyPath {
			policy = f.SHA256 == c.InitialPolicySHA256 && f.Mode == 0600
		}
	}
	if !gateway || !policy {
		return "", bad
	}
	return policyBytesDigest(commitRaw), nil
}

// Actual gateway startup accepts two DISJOINT strict base versions. Legacy
// callers of ValidateManagedBase still reject Version2 exactly as before.
func ValidateManagedBaseReference(c Config, configRaw, commitRaw []byte) (string, error) {
	if base, e := ValidateManagedBase(c, configRaw, commitRaw); e == nil {
		return base, nil
	}
	return ValidateManagedResultBase(c, configRaw, commitRaw)
}
