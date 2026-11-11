package installtxn

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Real ephemeral TEST keys, never a deployed trust root or repository secret.
// Fixture bytes are DATA, not ELF/source/ABI/execution qualification.
func programApprovalFixture(t *testing.T) (runtimeProgramAuthority, runtimeProgramCertificate, ed25519.PrivateKey, map[string][]byte) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("ephemeral fixture key")
	}
	h := sha256.Sum256(pub)
	policy := runtimeProgramAuthority{Version: 1, Epoch: 1, Keys: []runtimeProgramKey{{ID: hex.EncodeToString(h[:]), PublicKey: base64.StdEncoding.EncodeToString(pub)}}}
	cert := runtimeProgramCertificate{Version: 1, KeyID: policy.Keys[0].ID, Claim: runtimeProgramClaim{Version: 1, Epoch: 1}}
	data := map[string][]byte{}
	for _, role := range []string{"daemon", "gateway", "ingress", "installer", "launcher", "node", "ready", "template"} {
		raw := []byte("TEST DATA ONLY: " + role)
		h := sha256.Sum256(raw)
		cert.Claim.Programs = append(cert.Claim.Programs, runtimeApprovedProgram{Role: role, SHA256: hex.EncodeToString(h[:]), Bytes: int64(len(raw))})
		data[role] = raw
	}
	programApprovalSign(t, &cert, key, "Xandbox runtime program approval v1\x00")
	return policy, cert, key, data
}
func programApprovalWire(t *testing.T, value any) []byte {
	t.Helper()
	raw, e := json.Marshal(value)
	if e != nil {
		t.Fatal("fixture marshal")
	}
	return append(raw, '\n')
}
func programApprovalSign(t *testing.T, cert *runtimeProgramCertificate, key ed25519.PrivateKey, domain string) {
	t.Helper()
	// Independent literal domain and encoding/json, not candidate signing code.
	cert.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(domain), programApprovalWire(t, cert.Claim)...)))
}

func TestRuntimeFileProgramApprovalCanonicalKeysAndClaims(t *testing.T) {
	for _, kind := range []string{"valid", "two-keys", "four-keys", "metadata-max-size", "unsorted-keys", "policy-version", "policy-epoch", "empty-keys", "too-many-keys", "duplicate-key", "key-id", "key-length", "key-zero", "key-noncanonical-base64", "certificate-version", "claim-version", "claim-epoch", "unknown-key", "signature-length", "wrong-domain", "wrong-signature", "role", "program-count", "size-zero", "size-over", "sha-syntax", "signed-other-programs"} {
		t.Run(kind, func(t *testing.T) {
			policy, cert, key, _ := programApprovalFixture(t)
			expected := append([]runtimeApprovedProgram(nil), cert.Claim.Programs...)
			if kind == "two-keys" || kind == "four-keys" || kind == "unsorted-keys" {
				count := 2
				if kind == "four-keys" {
					count = 4
				}
				for len(policy.Keys) < count {
					pub, _, e := ed25519.GenerateKey(rand.Reader)
					if e != nil {
						t.Fatal("fixture key")
					}
					h := sha256.Sum256(pub)
					policy.Keys = append(policy.Keys, runtimeProgramKey{hex.EncodeToString(h[:]), base64.StdEncoding.EncodeToString(pub)})
				}
				sort.Slice(policy.Keys, func(i, j int) bool {
					if kind == "unsorted-keys" {
						return policy.Keys[i].ID > policy.Keys[j].ID
					}
					return policy.Keys[i].ID < policy.Keys[j].ID
				})
			}
			switch kind {
			case "metadata-max-size":
				cert.Claim.Programs[0].Bytes = 64 << 20
				expected[0].Bytes = 64 << 20
				programApprovalSign(t, &cert, key, "Xandbox runtime program approval v1\x00")
			case "policy-version":
				policy.Version = 2
			case "policy-epoch":
				policy.Epoch = 0
			case "empty-keys":
				policy.Keys = nil
			case "too-many-keys":
				policy.Keys = make([]runtimeProgramKey, 5)
			case "duplicate-key":
				policy.Keys = append(policy.Keys, policy.Keys[0])
			case "key-id":
				policy.Keys[0].ID = strings.Repeat("f", 64)
			case "key-length":
				policy.Keys[0].PublicKey = base64.StdEncoding.EncodeToString([]byte{1})
			case "key-zero":
				policy.Keys[0].PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
			case "key-noncanonical-base64":
				policy.Keys[0].PublicKey += "\n"
			case "certificate-version":
				cert.Version = 2
			case "claim-version":
				cert.Claim.Version = 2
			case "claim-epoch":
				cert.Claim.Epoch++
			case "unknown-key":
				cert.KeyID = strings.Repeat("f", 64)
			case "signature-length":
				cert.Signature = base64.StdEncoding.EncodeToString([]byte{1})
			case "wrong-domain":
				programApprovalSign(t, &cert, key, "another protocol\x00")
			case "wrong-signature":
				cert.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
			case "role":
				cert.Claim.Programs[0].Role = "warden"
			case "program-count":
				cert.Claim.Programs = cert.Claim.Programs[:7]
			case "size-zero":
				cert.Claim.Programs[0].Bytes = 0
			case "size-over":
				cert.Claim.Programs[0].Bytes = 64<<20 + 1
			case "sha-syntax":
				cert.Claim.Programs[0].SHA256 = strings.Repeat("F", 64)
			case "signed-other-programs":
				cert.Claim.Programs[0].SHA256 = strings.Repeat("a", 64)
				programApprovalSign(t, &cert, key, "Xandbox runtime program approval v1\x00")
			}
			decoded, e := decodeRuntimeProgramAuthority(programApprovalWire(t, policy))
			badPolicy := false
			switch kind {
			case "unsorted-keys", "policy-version", "policy-epoch", "empty-keys", "too-many-keys", "duplicate-key", "key-id", "key-length", "key-zero", "key-noncanonical-base64":
				badPolicy = true
			}
			if badPolicy {
				if e == nil || !reflect.DeepEqual(decoded, runtimeProgramAuthority{}) {
					t.Fatal("malformed authority accepted or partial returned", kind)
				}
				return
			}
			if e != nil {
				t.Fatal("valid authority unexpectedly refused", kind, e)
			}
			out, e := decodeRuntimeProgramCertificate(programApprovalWire(t, cert), decoded, expected)
			if (e == nil) != (kind == "valid" || kind == "two-keys" || kind == "four-keys" || kind == "metadata-max-size") || e != nil && !reflect.DeepEqual(out, runtimeProgramCertificate{}) {
				t.Fatal("signature/closed policy decision differs", kind, e)
			}
		})
	}
}

func TestRuntimeFileProgramApprovalRawWireNeverBecomesAuthority(t *testing.T) {
	for _, kind := range []string{"valid", "empty", "missing-lf", "space", "unknown-field", "duplicate-key", "folded-key", "reordered", "escaped-key", "trailing-object", "partial", "invalid-utf8", "over-limit", "signature-newline"} {
		t.Run(kind, func(t *testing.T) {
			policy, cert, _, _ := programApprovalFixture(t)
			raw := programApprovalWire(t, cert)
			switch kind {
			case "empty":
				raw = nil
			case "missing-lf":
				raw = bytes.TrimSuffix(raw, []byte{'\n'})
			case "space":
				raw = append([]byte{' '}, raw...)
			case "unknown-field":
				raw = bytes.Replace(raw, []byte(`{"version":1,`), []byte(`{"extra":0,"version":1,`), 1)
			case "duplicate-key":
				raw = bytes.Replace(raw, []byte(`{"version":1,`), []byte(`{"version":1,"version":1,`), 1)
			case "folded-key":
				raw = bytes.Replace(raw, []byte(`"key_id"`), []byte(`"KEY_ID"`), 1)
			case "reordered":
				raw = bytes.Replace(raw, []byte(`{"version":1,"key_id":`), []byte(`{"key_id":`), 1)
				raw = bytes.Replace(raw, []byte(`,"claim":`), []byte(`,"version":1,"claim":`), 1)
			case "escaped-key":
				raw = bytes.Replace(raw, []byte(`"key_id"`), []byte(`"\u006bey_id"`), 1)
			case "trailing-object":
				raw = append(raw, []byte("{}\n")...)
			case "partial":
				raw = raw[:len(raw)/2]
			case "invalid-utf8":
				raw = append([]byte{0xff}, raw...)
			case "over-limit":
				raw = make([]byte, MaxPlan+1)
			case "signature-newline":
				cert.Signature += "\n"
				raw = programApprovalWire(t, cert)
			}
			out, e := decodeRuntimeProgramCertificate(raw, policy, cert.Claim.Programs)
			if (e == nil) != (kind == "valid") || e != nil && !reflect.DeepEqual(out, runtimeProgramCertificate{}) {
				t.Fatal("noncanonical certificate accepted or partial returned", kind, e)
			}
		})
	}
}

func TestRuntimeFileProgramApprovalSignatureDomainAndEveryByte(t *testing.T) {
	policy, cert, _, _ := programApprovalFixture(t)
	sig, e := base64.StdEncoding.DecodeString(cert.Signature)
	if e != nil {
		t.Fatal(e)
	}
	for _, pos := range []int{0, len(sig) / 2, len(sig) - 1} {
		for b := 0; b < 256; b++ {
			copyCert := cert
			raw := append([]byte(nil), sig...)
			raw[pos] = byte(b)
			copyCert.Signature = base64.StdEncoding.EncodeToString(raw)
			_, e := decodeRuntimeProgramCertificate(programApprovalWire(t, copyCert), policy, cert.Claim.Programs)
			if (e == nil) != (byte(b) == sig[pos]) {
				t.Fatal("signature mutation decision", pos, b)
			}
		}
	}
	// Correct signatures do not repair an unsupported domain, role or epoch.
	if _, e = decodeRuntimeProgramCertificate(programApprovalWire(t, cert), runtimeProgramAuthority{}, cert.Claim.Programs); e == nil {
		t.Fatal("zero report became authority")
	}
}

func TestRuntimeFileProgramApprovalFreshConcurrentSignatures(t *testing.T) {
	var wg sync.WaitGroup
	failures := make(chan bool, 4)
	for n := 0; n < 4; n++ {
		// Each worker owns independently generated key/certificate/decoded bytes.
		policy, cert, _, _ := programApprovalFixture(t)
		raw := programApprovalWire(t, cert)
		policyRaw := programApprovalWire(t, policy)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 32; k++ {
				p, e := decodeRuntimeProgramAuthority(append([]byte(nil), policyRaw...))
				if e != nil {
					failures <- true
					return
				}
				if _, e = decodeRuntimeProgramCertificate(append([]byte(nil), raw...), p, append([]runtimeApprovedProgram(nil), cert.Claim.Programs...)); e != nil {
					failures <- true
					return
				}
			}
		}()
	}
	wg.Wait()
	close(failures)
	for range failures {
		t.Fatal("fresh independent signature verification failed")
	}
}
