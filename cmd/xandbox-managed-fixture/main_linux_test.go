//go:build linux && xandbox_managed_fixture

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

func fixture(t *testing.T, now time.Time) (map[string][]byte, gateway.Config, gateway.PolicyEnvelope, *access.Authenticator) {
	t.Helper()
	f, e := initial(now)
	if e != nil {
		t.Fatal("initial fixture rejected")
	}
	var c gateway.Config
	var a access.Config
	if strictjson.Decode(f["input/gateway.json"], &c) != nil || strictjson.Decode(f["input/auth.json"], &a) != nil {
		t.Fatal("initial schema")
	}
	auth, e := access.New(a)
	if e != nil {
		t.Fatal("initial authority")
	}
	p, e := gateway.DecodeManagedEnvelope(c, f["input/policy-initial.json"], "")
	if e != nil {
		t.Fatal("initial envelope")
	}
	return f, c, p, auth
}

func checkMaterial(t *testing.T, s gateway.Snapshot, c client, ca []byte, now time.Time, auth *access.Authenticator) *x509.Certificate {
	t.Helper()
	if _, e := gateway.NewPolicy(s, auth, now); e != nil {
		t.Fatal("fresh policy rejected")
	}
	if c.Revision != s.Epoch || c.CAFile != root+"/ca.pem" || c.ServerName != sni || len(c.Tokens) != 2 {
		t.Fatal("client binding")
	}
	for _, k := range s.Keys {
		if hash([]byte(c.Tokens[k.TenantID])) != k.TokenSHA256 || c.Tokens[k.TenantID] == k.BackendToken || !k.NotBefore.Equal(now.Add(-time.Minute)) || !k.ExpiresAt.Equal(now.Add(24*time.Hour)) {
			t.Fatal("separate bounded external credentials")
		}
	}
	pair, e := tls.X509KeyPair([]byte(s.CertificatePEM), []byte(s.PrivateKeyPEM))
	if e != nil {
		t.Fatal("TLS pair")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || c.LeafSHA != hash(pair.Certificate[0]) {
		t.Fatal("TLS leaf binding")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("CA")
	}
	if _, e := leaf.Verify(x509.VerifyOptions{DNSName: sni, Roots: pool, CurrentTime: now}); e != nil {
		t.Fatal("real TLS trust")
	}
	return leaf
}

func TestManagedFixtureInitialAndExpiredCommittedPredecessor(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	f, c, p, auth := fixture(t, now)
	want := []string{"ca.pem", "ca.key", "input/auth.json", "input/gateway.json", "input/policy-initial.json", "client-1.json"}
	if len(f) != len(want) {
		t.Fatal("closed initial inventory")
	}
	for _, n := range want {
		if len(f[n]) == 0 {
			t.Fatal("missing initial file")
		}
	}
	var cl client
	if strictjson.Decode(f["client-1.json"], &cl) != nil {
		t.Fatal("initial client")
	}
	checkMaterial(t, p.Snapshot, cl, f["ca.pem"], now, auth)
	if c.InitialPolicySHA256 != hash(f["input/policy-initial.json"]) {
		t.Fatal("raw initial pin")
	}
	old, _ := gateway.EncodePolicyEnvelope(p)
	for epoch := uint64(2); epoch <= 3; epoch++ {
		next := now
		if epoch == 3 {
			next = now.Add(pendingLifetime + time.Second)
		}
		out, e := rotation(next, epoch, c, p, f["input/auth.json"], f["ca.pem"], f["ca.key"])
		if e != nil || len(out) != 3 {
			t.Fatal("rotation fixture rejected")
		}
		n := "2"
		if epoch == 3 {
			n = "3"
		}
		var s gateway.Snapshot
		var fresh client
		var plan struct {
			Version int                  `json:"version"`
			Policy  gateway.PolicySource `json:"policy"`
		}
		raw := out["sources/snapshot-"+n+".json"]
		if strictjson.Decode(raw, &s) != nil || strictjson.Decode(out["client-"+n+".json"], &fresh) != nil || strictjson.Decode(out["rotation-"+n+".json"], &plan) != nil {
			t.Fatal("rotation schema")
		}
		if plan.Version != 1 || plan.Policy.Path != root+"/sources/snapshot-"+n+".json" || plan.Policy.SHA256 != hash(raw) || s.Epoch != epoch {
			t.Fatal("fixed plan and source pin")
		}
		leaf := checkMaterial(t, s, fresh, f["ca.pem"], next, auth)
		lifetime := 24 * time.Hour
		if epoch == 2 {
			lifetime = pendingLifetime
		}
		if !leaf.NotAfter.Equal(next.Add(lifetime)) {
			t.Fatal("bounded fixture lifetime")
		}
		for i, k := range s.Keys {
			before := p.Snapshot.Keys[i]
			if k.TenantID != before.TenantID || k.BackendToken != before.BackendToken || k.MaxInstances != before.MaxInstances || k.TokenSHA256 == before.TokenSHA256 {
				t.Fatal("stable backend and fresh external authority")
			}
		}
		if s.CertificatePEM == p.Snapshot.CertificatePEM || s.PrivateKeyPEM == p.Snapshot.PrivateKeyPEM {
			t.Fatal("leaf pair reuse")
		}
		if epoch == 3 {
			if _, e := gateway.NewPolicy(p.Snapshot, auth, next); e == nil {
				t.Fatal("expired old policy must not serve")
			}
		}
		p.Revision, p.Snapshot = epoch, s
	}
	// The producer cannot change the old envelope or backend input in place.
	_, _, initialP, _ := fixture(t, now)
	if bytes.Equal(old, mustEnvelope(t, initialP)) {
		t.Fatal("independent fixture must use fresh secrets")
	}
	var original gateway.PolicyEnvelope
	if json.Unmarshal(f["input/policy-initial.json"], &original) != nil || !bytes.Equal(old, mustEnvelope(t, original)) {
		t.Fatal("initial bytes mutated")
	}
}

func mustEnvelope(t *testing.T, p gateway.PolicyEnvelope) []byte {
	t.Helper()
	b, e := gateway.EncodePolicyEnvelope(p)
	if e != nil {
		t.Fatal("envelope")
	}
	return b
}

func TestManagedFixtureRejectsForeignAndMalformedAuthority(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	f, c, p, _ := fixture(t, now)
	other, _, _, _ := fixture(t, now)
	type args struct {
		epoch         uint64
		c             gateway.Config
		p             gateway.PolicyEnvelope
		auth, ca, key []byte
		now           time.Time
	}
	base := args{2, c, p, f["input/auth.json"], f["ca.pem"], f["ca.key"], now}
	cases := map[string]func(*args){
		"epoch1": func(a *args) { a.epoch = 1 }, "epoch4": func(a *args) { a.epoch = 4 },
		"skip": func(a *args) { a.epoch = 3 }, "overflow": func(a *args) { a.p.Revision = ^uint64(0) },
		"envelope-version": func(a *args) { a.p.Version = 2 }, "snapshot-epoch": func(a *args) { a.p.Snapshot.Epoch = 2 },
		"config-v1": func(a *args) { a.c.Version = 1 }, "config-binding": func(a *args) { a.c.UID++ },
		"snapshot-binding": func(a *args) { a.p.Snapshot.ServerName = "other.fixture" },
		"backend":          func(a *args) { a.auth = other["input/auth.json"] },
		"unknown-auth":     func(a *args) { a.auth = []byte(`{"version":1,"unknown":true}`) },
		"malformed-ca":     func(a *args) { a.ca = []byte("bad") }, "trailing-ca": func(a *args) { a.ca = append(append([]byte{}, a.ca...), 'x') },
		"mismatched-key":  func(a *args) { a.key = other["ca.key"] },
		"foreign-pair":    func(a *args) { a.ca, a.key = other["ca.pem"], other["ca.key"] },
		"bad-key":         func(a *args) { a.key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad")}) },
		"bad-predecessor": func(a *args) { a.p.Snapshot.CertificatePEM = "bad" },
		"expired-ca":      func(a *args) { a.now = now.Add(49 * time.Hour) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := base
			mutate(&a)
			if _, e := rotation(a.now, a.epoch, a.c, a.p, a.auth, a.ca, a.key); e == nil {
				t.Fatal("invalid fixture admitted")
			}
		})
	}
	if !reflect.DeepEqual(base.p, p) {
		t.Fatal("input mutated")
	}
}

func TestManagedFixtureUnknownOperationAndEscapeRefusedBeforeIO(t *testing.T) {
	for _, arg := range []string{"", "setup extra", "rotation1", "rotation4", "/bin/sh", "--root=/tmp"} {
		if e := run(arg); e == nil || !strings.Contains(e.Error(), "fixed fixture operation") {
			t.Fatal("unknown operation")
		}
	}
	for _, path := range []string{"", "/tmp/x", "../x", "input/../x", "sources/../../x", "subdir/x"} {
		if writeFiles(map[string][]byte{path: []byte("test")}) == nil {
			t.Fatal("escaping output")
		}
	}
}
