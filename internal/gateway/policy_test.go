package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
)

// Synthetic unit credentials, not generated deployment tokens or fixtures.
var testExternal = strings.Repeat("a", 40)
var testBackend = strings.Repeat("b", 40)

func tokenHash(s string) string { x := sha256.Sum256([]byte(s)); return hex.EncodeToString(x[:]) }
func testSnapshot(t *testing.T) (Snapshot, *access.Authenticator) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gateway.test"}, DNSNames: []string{"gateway.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	s := Snapshot{Version: 1, Epoch: 1, UID: 60001, GID: 60001, Listen: "127.0.0.1:9443", ServerName: "gateway.test", CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), Keys: []ClientKey{{TokenSHA256: tokenHash(testExternal), TenantID: "alpha", MaxInstances: 2, BackendToken: testBackend, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}}}
	auth, e := access.New(access.Config{Version: 1, Keys: []access.Key{{TokenSHA256: tokenHash(testBackend), TenantID: "alpha", MaxInstances: 2}, {TokenSHA256: tokenHash(strings.Repeat("c", 40)), TenantID: "beta", MaxInstances: 2}}})
	if e != nil {
		t.Fatal(e)
	}
	return s, auth
}
func TestPolicyRequiresCoherentBoundedTLSAndBackendOwner(t *testing.T) {
	s, authority := testSnapshot(t)
	now := time.Now()
	p, e := NewPolicy(s, authority, now)
	if e != nil {
		t.Fatal(e)
	}
	c, ok := p.authenticate("Bearer "+testExternal, now)
	if !ok || c.tenant != "alpha" || c.backend != testBackend {
		t.Fatal("wrong mapped backend authority")
	}
	if _, ok = p.authenticate("Bearer "+testBackend, now); ok {
		t.Fatal("private credential accepted as external")
	}
	for _, mutate := range []func(*Snapshot){
		func(s *Snapshot) { s.Version++ }, func(s *Snapshot) { s.Epoch = 0 }, func(s *Snapshot) { s.UID = 0 }, func(s *Snapshot) { s.GID = 1 }, func(s *Snapshot) { s.UID = 400000; s.GID = s.UID },
		func(s *Snapshot) { s.Listen = ":443" }, func(s *Snapshot) { s.Listen = "localhost:9443" }, func(s *Snapshot) { s.Listen = "127.0.0.1:443" }, func(s *Snapshot) { s.Listen = "224.0.0.1:9443" },
		func(s *Snapshot) { s.ServerName = "other.test" }, func(s *Snapshot) { s.ServerName = "Gateway.test" }, func(s *Snapshot) { s.ServerName = "gateway.test." }, func(s *Snapshot) { s.ServerName = "127.0.0.1" }, func(s *Snapshot) { s.ServerName = "*.test" },
		func(s *Snapshot) { s.CertificatePEM = "invalid" }, func(s *Snapshot) { s.PrivateKeyPEM = "invalid" }, func(s *Snapshot) { s.Keys[0].BackendToken = testExternal }, func(s *Snapshot) { s.Keys[0].TenantID = "beta" }, func(s *Snapshot) { s.Keys[0].MaxInstances = 3 },
		func(s *Snapshot) { s.Keys[0].TokenSHA256 = tokenHash(testBackend) }, func(s *Snapshot) { s.Keys[0].TokenSHA256 = "invalid" }, func(s *Snapshot) { s.Keys = append(s.Keys, s.Keys[0]) }, func(s *Snapshot) { s.Keys[0].NotBefore = time.Time{} }, func(s *Snapshot) { s.Keys[0].ExpiresAt = s.Keys[0].NotBefore }, func(s *Snapshot) { s.Keys[0].ExpiresAt = s.Keys[0].NotBefore.Add(91 * 24 * time.Hour) },
	} {
		bad := s
		bad.Keys = append([]ClientKey(nil), s.Keys...)
		mutate(&bad)
		if _, e := NewPolicy(bad, authority, now); e == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	if _, e = NewPolicy(s, authority, now.Add(25*time.Hour)); e == nil {
		t.Fatal("expired server certificate")
	}
	if _, e = NewPolicy(s, authority, now.Add(-2*time.Hour)); e == nil {
		t.Fatal("future server certificate")
	}
	s.Keys[0].BackendToken = "changed caller memory"
	if c, ok := p.authenticate("Bearer "+testExternal, now); !ok || c.backend != testBackend {
		t.Fatal("published policy borrowed mutable input")
	}
}
func TestExternalValidityAndAtomicRevocationWithoutControllerRestart(t *testing.T) {
	s, auth := testSnapshot(t)
	p, e := NewPolicy(s, auth, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	if _, ok := p.authenticate("Bearer "+testExternal, s.Keys[0].NotBefore.Add(-time.Nanosecond)); ok {
		t.Fatal("future key accepted")
	}
	if _, ok := p.authenticate("Bearer "+testExternal, s.Keys[0].ExpiresAt); ok {
		t.Fatal("expired key accepted")
	}
	store := &Store{}
	if store.Publish(p) != nil {
		t.Fatal("first policy")
	}
	next := s
	next.Epoch = 2
	next.Keys = append([]ClientKey(nil), s.Keys...)
	rotated := strings.Repeat("d", 40)
	next.Keys[0].TokenSHA256 = tokenHash(rotated)
	q, e := NewPolicy(next, auth, now)
	if e != nil || store.Publish(q) != nil {
		t.Fatal("rotation")
	}
	if _, ok := store.Current().authenticate("Bearer "+testExternal, now); ok {
		t.Fatal("revoked key survived publication")
	}
	if c, ok := store.Current().authenticate("Bearer "+rotated, now); !ok || c.backend != testBackend {
		t.Fatal("transport identity changed with external rotation")
	}
	// Already-admitted requests may retain their old snapshot; not cancellation.
	if _, ok := p.authenticate("Bearer "+testExternal, now); !ok {
		t.Fatal("immutable old snapshot mutated")
	}
	empty := next
	empty.Epoch = 3
	empty.Keys = nil
	closed, e := NewPolicy(empty, auth, now)
	if e != nil || store.Publish(closed) != nil {
		t.Fatal("explicit revoke all")
	}
	if _, ok := store.Current().authenticate("Bearer "+rotated, now); ok {
		t.Fatal("empty policy became unauthenticated access")
	}
	if store.Publish(q) == nil {
		t.Fatal("policy rollback allowed")
	}
	for _, field := range []string{"listen", "name", "uid"} {
		bad := empty
		bad.Epoch = 4
		switch field {
		case "listen":
			bad.Listen = "127.0.0.1:9444"
		case "name":
			bad.ServerName = "other.test"
		case "uid":
			bad.UID++
			bad.GID = bad.UID
		}
		r := Policy{snapshot: bad, cert: closed.cert}
		if store.Publish(&r) == nil {
			t.Fatal("immutable process binding changed")
		}
	}
}
func TestPolicySingleAtomicPublisherAndBoundedTenantBudgets(t *testing.T) {
	s, a := testSnapshot(t)
	p, e := NewPolicy(s, a, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	store := &Store{}
	store.Publish(p)
	next := s
	next.Epoch = 2
	q, e := NewPolicy(next, a, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan bool, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- store.Publish(q) == nil }()
	}
	wg.Wait()
	close(results)
	n := 0
	for ok := range results {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatal("same epoch published twice")
	}
	now := time.Now()
	accepted := 0
	for i := 0; i < 100; i++ {
		if q.tenantRate("alpha", now) {
			accepted++
		}
	}
	if accepted != 64 {
		t.Fatal("tenant burst unbounded")
	}
	if !q.tenantRate("alpha", now.Add(time.Second)) {
		t.Fatal("tenant rate did not recover")
	}
}
