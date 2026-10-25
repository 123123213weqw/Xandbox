//go:build linux && xandbox_deploy_fixture

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/gateway"
)

func TestMaterialIsActuallyAcceptedByOrdinaryGatewayPolicy(t *testing.T) {
	now := time.Now()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	cert, priv, e := material(now, ca, key)
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(cert)
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: sni, CurrentTime: now}); e != nil {
		t.Fatal(e)
	}
	backend, external := strings.Repeat("backend-fixture-", 4), strings.Repeat("client-fixture-", 4)
	authority, e := access.New(access.Config{Version: 1, Keys: []access.Key{{TenantID: "alpha", MaxInstances: 3, TokenSHA256: digest([]byte(backend))}}})
	if e != nil {
		t.Fatal(e)
	}
	s := gateway.Snapshot{Version: 1, Epoch: 1, UID: 65530, GID: 65530, Listen: "127.0.0.1:18443", ServerName: sni, CertificatePEM: string(cert), PrivateKeyPEM: string(priv), Keys: []gateway.ClientKey{{TokenSHA256: digest([]byte(external)), TenantID: "alpha", MaxInstances: 3, BackendToken: backend, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}}}
	if _, e = gateway.NewPolicy(s, authority, now); e != nil {
		t.Fatal(e)
	}
}
func TestSetupCannotRunOnUnmarkedL0(t *testing.T) {
	if e := configure(1); e == nil {
		t.Fatal("setup escaped owned L1 guard")
	}
}
func TestBudgetIncludesIngressAndHostReserve(t *testing.T) {
	in, res, cap := envelope()
	if in.MemoryMax != 512<<20 || res.MemoryMax != 2<<30 || cap.MemoryMax != 12<<30 || in.CPUQuota+res.CPUQuota+800000 != cap.CPUQuota || in.PidsMax != 64 {
		t.Fatal("fixed profile budget drift")
	}
}
func TestReadinessSetupCannotRunOnUnmarkedL0(t *testing.T) {
	if e := setupReadiness(); e == nil {
		t.Fatal("readiness setup escaped owned L1 guard")
	}
}
