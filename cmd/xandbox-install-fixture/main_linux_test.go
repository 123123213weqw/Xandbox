//go:build linux && xandbox_install_fixture

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/gateway"
)

func TestEphemeralMaterialHasRealTrustAndDistinctAuthorities(t *testing.T) {
	now := time.Now().UTC()
	f, e := material(now)
	if e != nil {
		t.Fatal(e)
	}
	if len(f) != 6 {
		t.Fatal("closed fixture inventory")
	}
	var a access.Config
	var g gateway.Config
	if json.Unmarshal(f["input/auth.json"], &a) != nil || json.Unmarshal(f["input/gateway.json"], &g) != nil {
		t.Fatal("schema")
	}
	auth, e := access.New(a)
	if e != nil {
		t.Fatal(e)
	}
	for _, key := range g.Keys {
		if hash([]byte(key.BackendToken)) == key.TokenSHA256 {
			t.Fatal("credential boundary")
		}
	}
	if _, e = gateway.NewPolicy(gateway.Snapshot{Version: 1, Epoch: 1, UID: g.UID, GID: g.GID, Listen: g.Listen, ServerName: g.ServerName, CertificatePEM: string(f["input/tls.pem"]), PrivateKeyPEM: string(f["input/tls.key"]), Keys: g.Keys}, auth, now); e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair(f["input/tls.pem"], f["input/tls.key"])
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(f["ca.pem"]) {
		t.Fatal("CA")
	}
	if _, e = leaf.Verify(x509.VerifyOptions{DNSName: sni, Roots: pool, CurrentTime: now}); e != nil {
		t.Fatal(e)
	}
	other, e := material(now)
	if e != nil {
		t.Fatal(e)
	}
	if hash(other["input/tls.key"]) == hash(f["input/tls.key"]) {
		t.Fatal("key reuse")
	}
}
