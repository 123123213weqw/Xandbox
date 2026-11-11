package installtxn

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

const runtimeProgramApprovalDomain = "Xandbox runtime program approval v1\x00"

// Administrative approval of EXACT program bytes, not a claim about their
// compiler, ABI, supported state formats, health or safety to execute.
type runtimeApprovedProgram struct {
	Role   string `json:"role"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}
type runtimeProgramClaim struct {
	Version  int                      `json:"version"`
	Epoch    uint64                   `json:"authority_epoch"`
	Programs []runtimeApprovedProgram `json:"programs"`
}
type runtimeProgramCertificate struct {
	Version   int                 `json:"version"`
	KeyID     string              `json:"key_id"`
	Claim     runtimeProgramClaim `json:"claim"`
	Signature string              `json:"signature"`
}
type runtimeProgramKey struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
}
type runtimeProgramAuthority struct {
	Version int                 `json:"version"`
	Epoch   uint64              `json:"epoch"`
	Keys    []runtimeProgramKey `json:"keys"`
}

func runtimeProgramRoles() [8]string {
	return [8]string{"daemon", "gateway", "ingress", "installer", "launcher", "node", "ready", "template"}
}
func runtimeProgramBase64(text string, size int) ([]byte, bool) {
	raw, e := base64.StdEncoding.Strict().DecodeString(text)
	return raw, e == nil && len(raw) == size && base64.StdEncoding.EncodeToString(raw) == text
}
func (p runtimeProgramAuthority) valid() bool {
	if p.Version != 1 || p.Epoch == 0 || len(p.Keys) < 1 || len(p.Keys) > 4 {
		return false
	}
	last := ""
	for _, k := range p.Keys {
		raw, ok := runtimeProgramBase64(k.PublicKey, ed25519.PublicKeySize)
		if !ok || bytes.Equal(raw, make([]byte, ed25519.PublicKeySize)) || !digestPattern.MatchString(k.ID) || k.ID != digest(raw) || k.ID <= last {
			return false
		}
		last = k.ID
	}
	return true
}
func validRuntimeApprovedPrograms(programs []runtimeApprovedProgram) bool {
	roles := runtimeProgramRoles()
	if len(programs) != len(roles) {
		return false
	}
	for i, p := range programs {
		if p.Role != roles[i] || !digestPattern.MatchString(p.SHA256) || p.Bytes < 1 || p.Bytes > 64<<20 {
			return false
		}
	}
	return true
}
func decodeRuntimeProgramAuthority(raw []byte) (runtimeProgramAuthority, error) {
	var p runtimeProgramAuthority
	if len(raw) == 0 || len(raw) > MaxPlan || strictjson.Decode(raw, &p) != nil || !p.valid() || !bytes.Equal(raw, encode(p)) {
		return runtimeProgramAuthority{}, ErrInventory
	}
	return p, nil
}
func decodeRuntimeProgramCertificate(raw []byte, authority runtimeProgramAuthority, programs []runtimeApprovedProgram) (runtimeProgramCertificate, error) {
	var c runtimeProgramCertificate
	if !authority.valid() || !validRuntimeApprovedPrograms(programs) || len(raw) == 0 || len(raw) > MaxPlan || strictjson.Decode(raw, &c) != nil || !bytes.Equal(raw, encode(c)) || c.Version != 1 || !digestPattern.MatchString(c.KeyID) || c.Claim.Version != 1 || c.Claim.Epoch != authority.Epoch || !validRuntimeApprovedPrograms(c.Claim.Programs) {
		return runtimeProgramCertificate{}, ErrInventory
	}
	for i, p := range programs {
		if c.Claim.Programs[i] != p {
			return runtimeProgramCertificate{}, ErrInventory
		}
	}
	sig, ok := runtimeProgramBase64(c.Signature, ed25519.SignatureSize)
	if !ok {
		return runtimeProgramCertificate{}, ErrInventory
	}
	for _, k := range authority.Keys {
		if k.ID != c.KeyID {
			continue
		}
		pub, ok := runtimeProgramBase64(k.PublicKey, ed25519.PublicKeySize)
		if ok && ed25519.Verify(ed25519.PublicKey(pub), append([]byte(runtimeProgramApprovalDomain), encode(c.Claim)...), sig) {
			return c, nil
		}
		break
	}
	return runtimeProgramCertificate{}, ErrInventory
}
