//go:build linux

package gateway

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Synthetic PKI only. No installed paths, root maintenance, serving child or
// systemd/KVM acceptance. The real persistence primitive is intentionally not
// exposed by a CLI/RunRoot caller until its complete maintenance proof exists.
func snapshotWithValidity(t *testing.T, s Snapshot, before, after time.Time, change func(*x509.Certificate)) Snapshot {
	t.Helper()
	pair, e := tls.X509KeyPair([]byte(s.CertificatePEM), []byte(s.PrivateKeyPEM))
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	leaf.NotBefore, leaf.NotAfter = before, after
	if change != nil {
		change(leaf)
	}
	der, e := x509.CreateCertificate(rand.Reader, leaf, leaf, leaf.PublicKey, pair.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	s.CertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return s
}

type policyFileImage struct {
	Bytes             string
	Mode              os.FileMode
	Size              int64
	ModTime           time.Time
	Dev, Inode, Links uint64
}

func policyTreeImage(t *testing.T, dir string) map[string]policyFileImage {
	t.Helper()
	entries, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	out := make(map[string]policyFileImage)
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		st, e := os.Lstat(path)
		if e != nil {
			t.Fatal(e)
		}
		var raw unix.Stat_t
		if e = unix.Lstat(path, &raw); e != nil {
			t.Fatal(e)
		}
		b := []byte(nil)
		if st.Mode().IsRegular() {
			b, e = os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
		}
		out[entry.Name()] = policyFileImage{string(b), st.Mode(), st.Size(), st.ModTime(), uint64(raw.Dev), raw.Ino, uint64(raw.Nlink)}
	}
	return out
}

func TestAdvanceExpiredOrFuturePolicyPersistsOnlyExactNextAndServingStillRejects(t *testing.T) {
	for _, future := range []bool{false, true} {
		t.Run(map[bool]string{false: "expired", true: "not-yet-valid"}[future], func(t *testing.T) {
			c, initial, _ := managedTestConfig(t)
			_, authority := testSnapshot(t)
			now := time.Now().UTC().Truncate(time.Second)
			before, after := now.Add(-48*time.Hour), now.Add(-24*time.Hour)
			if future {
				before, after = now.Add(24*time.Hour), now.Add(48*time.Hour)
			}
			p := rotatedEnvelope(t, c, initial)
			p.Snapshot = snapshotWithValidity(t, p.Snapshot, before, after, nil)
			raw, e := EncodePolicyEnvelope(p)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = ValidateManagedSnapshot(c, raw, p.BaseCommitSHA256, authority, now); e == nil {
				t.Fatal("non-current certificate admitted for serving")
			}
			dir, binding := t.TempDir(), strings.Repeat("a", 64)
			state, e := openPolicyState(dir, binding)
			if e != nil {
				t.Fatal(e)
			}
			if e = state.Commit(initial.Snapshot); e != nil {
				t.Fatal(e)
			}
			state.Close()
			state, e = openExistingPolicyState(dir, binding)
			if e != nil {
				t.Fatal(e)
			}
			if e = advancePolicyState(state, p.Snapshot, authority); e != nil {
				t.Fatal(e)
			}
			if state.record.Revision != 2 {
				t.Fatal("advance did not persist exact next epoch")
			}
			state.Close()
			cold, e := openExistingPolicyState(dir, binding)
			if e != nil {
				t.Fatal(e)
			}
			defer cold.Close()
			beforeImage := policyTreeImage(t, dir)
			if e = advancePolicyState(cold, p.Snapshot, authority); e != nil {
				t.Fatal("lost-response exact retry", e)
			}
			if !reflect.DeepEqual(beforeImage, policyTreeImage(t, dir)) {
				t.Fatal("exact retry rewrote authority")
			}
			if _, e = ValidateManagedSnapshot(c, raw, p.BaseCommitSHA256, authority, now); e == nil {
				t.Fatal("durable advance weakened serving validation")
			}
			// Ordinary Commit must now accept the next CURRENT policy, not skip
			// or replay the expired payload. No child is spawned by this test.
			next := initial.Snapshot
			next.Epoch = 3
			if _, e = NewPolicy(next, authority, now); e != nil {
				t.Fatal(e)
			}
			if e = cold.Commit(next); e != nil {
				t.Fatal("ordinary next commit", e)
			}
			if e = advancePolicyState(cold, p.Snapshot, authority); e == nil {
				t.Fatal("durable epoch rolled back")
			}
		})
	}
}

func TestAdvanceInvalidPolicyOrCASNeverCollectsOrRewrites(t *testing.T) {
	mutations := map[string]func(*Snapshot){
		"zero-epoch":          func(s *Snapshot) { s.Epoch = 0 },
		"initial-reused":      func(s *Snapshot) { s.Epoch = 1 },
		"skip":                func(s *Snapshot) { s.Epoch = 3 },
		"zero-uid":            func(s *Snapshot) { s.UID = 0 },
		"wrong-gid":           func(s *Snapshot) { s.GID++ },
		"wrong-sni":           func(s *Snapshot) { s.ServerName = "foreign.test" },
		"invalid-key":         func(s *Snapshot) { s.PrivateKeyPEM = "invalid" },
		"invalid-certificate": func(s *Snapshot) { s.CertificatePEM = "invalid" },
		"backend-owner":       func(s *Snapshot) { s.Keys[0].TenantID = "beta" },
		"backend-quota":       func(s *Snapshot) { s.Keys[0].MaxInstances++ },
		"backend-missing":     func(s *Snapshot) { s.Keys[0].BackendToken = strings.Repeat("z", 40) },
		"backend-as-external": func(s *Snapshot) { s.Keys[0].TokenSHA256 = tokenHash(testBackend) },
		"duplicate-external":  func(s *Snapshot) { s.Keys = append(s.Keys, s.Keys[0]) },
		"marshal-time":        func(s *Snapshot) { s.Keys[0].ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		"oversize":            func(s *Snapshot) { s.CertificatePEM = strings.Repeat("x", MaxSnapshotBytes) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s, authority := testSnapshot(t)
			dir := t.TempDir()
			state, e := openPolicyState(dir, strings.Repeat("a", 64))
			if e != nil {
				t.Fatal(e)
			}
			defer state.Close()
			if e = state.Commit(s); e != nil {
				t.Fatal(e)
			}
			// Recognized orphan bytes must also survive rejected admission/CAS:
			// checking only policy.json would miss a premature collect().
			orphan, e := json.Marshal(policyRecord{Version: 1, Revision: 2, SnapshotSHA256: strings.Repeat("e", 64)})
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(dir, ".policy-1234567890"), append(orphan, '\n'), 0600); e != nil {
				t.Fatal(e)
			}
			if orphans, e := state.inventory(); e != nil || len(orphans) != 1 {
				t.Fatal("orphan must be admissible before rejection", e)
			}
			before := policyTreeImage(t, dir)
			valid := s
			valid.Epoch = 2
			s.Epoch = 2
			s.Keys = append([]ClientKey(nil), s.Keys...)
			mutate(&s)
			if advancePolicyState(state, s, authority) == nil {
				t.Fatal("invalid advance accepted")
			}
			if !reflect.DeepEqual(before, policyTreeImage(t, dir)) || state.record.Revision != 1 {
				t.Fatal("rejected advance mutated state")
			}
			if e = advancePolicyState(state, valid, authority); e != nil {
				t.Fatal("positive control could not advance/collect", e)
			}
			if _, e = os.Lstat(filepath.Join(dir, ".policy-1234567890")); !os.IsNotExist(e) {
				t.Fatal("positive control did not collect valid orphan")
			}
		})
	}
}

func TestAdvanceStillValidatesTLSShapeAndRequiresAuthority(t *testing.T) {
	s, authority := testSnapshot(t)
	now := time.Now().UTC().Truncate(time.Second)
	for name, change := range map[string]func(*x509.Certificate){
		"empty-interval":    func(c *x509.Certificate) { c.NotAfter = c.NotBefore },
		"reversed-interval": func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(-time.Hour) },
		"ca":                func(c *x509.Certificate) { c.IsCA = true; c.BasicConstraintsValid = true },
		"client-only":       func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} },
		"wrong-dns":         func(c *x509.Certificate) { c.DNSNames = []string{"other.test"} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := snapshotWithValidity(t, s, now.Add(-48*time.Hour), now.Add(-24*time.Hour), change)
			if validatePolicyForDurableAdvance(bad, authority) == nil {
				t.Fatal("invalid TLS shape accepted")
			}
		})
	}
	if validatePolicyForDurableAdvance(s, nil) == nil || advancePolicyState(nil, s, authority) == nil || advancePolicyState(&policyState{}, s, authority) == nil {
		t.Fatal("missing authority/state bootstrapped")
	}
}

func TestExistingPolicyStateNeverCreatesRepairsOrBootstraps(t *testing.T) {
	for _, kind := range []string{"fresh", "no-lock", "no-record", "no-identity", "both-records-lost", "wrong-binding", "used-lock-only", "nonempty-lock", "lock-hardlink", "lock-symlink", "lock-fifo", "unknown-inventory"} {
		t.Run(kind, func(t *testing.T) {
			dir, binding := t.TempDir(), strings.Repeat("a", 64)
			if kind != "fresh" && kind != "lock-symlink" && kind != "lock-fifo" {
				state, e := openPolicyState(dir, binding)
				if e != nil {
					t.Fatal(e)
				}
				if kind != "used-lock-only" {
					s, _ := testSnapshot(t)
					if e = state.Commit(s); e != nil {
						t.Fatal(e)
					}
				}
				state.Close()
			}
			remove := func(name string) {
				t.Helper()
				if e := os.Remove(filepath.Join(dir, name)); e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "no-lock":
				remove("gateway.lock")
			case "no-record":
				remove("policy.json")
			case "no-identity":
				remove("policy.identity")
			case "both-records-lost":
				remove("policy.json")
				remove("policy.identity")
			case "wrong-binding":
				binding = strings.Repeat("b", 64)
			case "nonempty-lock":
				if e := os.WriteFile(filepath.Join(dir, "gateway.lock"), []byte("foreign"), 0600); e != nil {
					t.Fatal(e)
				}
			case "lock-hardlink":
				if e := os.Link(filepath.Join(dir, "gateway.lock"), filepath.Join(dir, "second")); e != nil {
					t.Fatal(e)
				}
			case "lock-symlink":
				if e := os.Symlink("missing", filepath.Join(dir, "gateway.lock")); e != nil {
					t.Fatal(e)
				}
			case "lock-fifo":
				if e := unix.Mkfifo(filepath.Join(dir, "gateway.lock"), 0600); e != nil {
					t.Fatal(e)
				}
			case "unknown-inventory":
				if e := os.WriteFile(filepath.Join(dir, "foreign"), []byte("preserve"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			before := policyTreeImage(t, dir)
			state, e := openExistingPolicyState(dir, binding)
			if e == nil {
				defer state.Close()
				// The shared opener reads authorities; closed inventory is
				// checked by Commit before collecting recognized scratch.
				if kind != "unknown-inventory" {
					t.Fatal("invalid existing state opened")
				}
				s, authority := testSnapshot(t)
				s.Epoch = 2
				if advancePolicyState(state, s, authority) == nil {
					t.Fatal("unknown inventory adopted")
				}
			} else if kind == "unknown-inventory" {
				t.Fatal("fixture did not reach inventory check", e)
			}
			if !reflect.DeepEqual(before, policyTreeImage(t, dir)) {
				t.Fatal("existing-only refusal created/repaired/collected state")
			}
			if kind == "nonempty-lock" || kind == "lock-hardlink" || kind == "lock-symlink" || kind == "lock-fifo" {
				if ordinary, e := openPolicyState(dir, binding); e == nil {
					ordinary.Close()
					t.Fatal("ordinary opener accepted invalid lock")
				}
				if !reflect.DeepEqual(before, policyTreeImage(t, dir)) {
					t.Fatal("ordinary invalid-lock refusal mutated state")
				}
			}
		})
	}
}

func TestExistingPolicyStateExclusiveLockColdBindingAndNoBootstrap(t *testing.T) {
	dir, binding := t.TempDir(), strings.Repeat("a", 64)
	state, e := openPolicyState(dir, binding)
	if e != nil {
		t.Fatal(e)
	}
	s, authority := testSnapshot(t)
	if advancePolicyState(state, s, authority) == nil {
		t.Fatal("fresh state advanced")
	}
	if e = state.Commit(s); e != nil {
		t.Fatal(e)
	}
	if other, e := openExistingPolicyState(dir, binding); e == nil {
		other.Close()
		t.Fatal("live supervisor not excluded")
	}
	state.Close()
	state, e = openExistingPolicyState(dir, binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	if e = state.Commit(s); e != nil {
		t.Fatal("exact initial cold state", e)
	}
}

func TestAdvanceSameRevisionDigestConflictAndGapPreserveAdmissibleOrphan(t *testing.T) {
	s, authority := testSnapshot(t)
	dir := t.TempDir()
	state, e := openPolicyState(dir, strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	if e = state.Commit(s); e != nil {
		t.Fatal(e)
	}
	s.Epoch = 2
	if e = advancePolicyState(state, s, authority); e != nil {
		t.Fatal(e)
	}
	orphan, e := json.Marshal(policyRecord{Version: 1, Revision: 3, SnapshotSHA256: strings.Repeat("e", 64)})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, ".policy-1234567890"), append(orphan, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	if found, e := state.inventory(); e != nil || len(found) != 1 {
		t.Fatal("positive inventory", e)
	}
	before := policyTreeImage(t, dir)
	for _, kind := range []string{"different-digest", "rollback", "skip", "overflow"} {
		bad := s
		bad.Keys = append([]ClientKey(nil), s.Keys...)
		switch kind {
		case "different-digest":
			bad.Keys[0].TokenSHA256 = tokenHash(strings.Repeat("d", 40))
		case "rollback":
			bad.Epoch = 1
		case "skip":
			bad.Epoch = 4
		case "overflow":
			bad.Epoch = ^uint64(0)
		}
		if advancePolicyState(state, bad, authority) == nil {
			t.Fatal("bad CAS accepted", kind)
		}
		if !reflect.DeepEqual(before, policyTreeImage(t, dir)) || state.record.Revision != 2 {
			t.Fatal("bad CAS collected/wrote state", kind)
		}
	}
	s.Epoch = 3
	if e = advancePolicyState(state, s, authority); e != nil {
		t.Fatal("positive advance/collection", e)
	}
}
