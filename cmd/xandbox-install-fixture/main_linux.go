//go:build linux && xandbox_install_fixture

// TEST ONLY ephemeral PKI/credentials for the marked, owned installer L1.
// No service activation, installer hook, task execution or production entry.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/gateway"
)

const root = "/etc/xandbox-install-fixture"
const marker = "Xandbox owned initial installer fixture v1\n"
const sni = "xandbox.fixture"

func hash(b []byte) string { x := sha256.Sum256(b); return hex.EncodeToString(x[:]) }
func token() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func encode(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic("fixed fixture schema")
	}
	return append(b, '\n')
}
func material(now time.Time) (map[string][]byte, error) {
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned installer fixture CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		return nil, e
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{sni}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if e != nil {
		return nil, e
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	auth := access.Config{Version: 1}
	g := gateway.Config{Version: 1, PolicyRevision: 1, StateDir: "/srv/xi/p", UID: 65530, GID: 65530, Listen: "127.0.0.1:18443", ServerName: sni, EmptyRoot: "/srv/xi/g/root", TenantSocket: "/srv/xi/s/api.sock", BackendAuthFile: "/run/xandbox-inputs/auth.json", CertificateFile: "/etc/xandbox-install/tls.pem", PrivateKeyFile: "/etc/xandbox-install/tls.key"}
	external, backend := map[string]string{}, map[string]string{}
	for _, tenant := range []string{"alpha", "beta"} {
		external[tenant], e = token()
		if e != nil {
			return nil, e
		}
		backend[tenant], e = token()
		if e != nil {
			return nil, e
		}
		auth.Keys = append(auth.Keys, access.Key{TokenSHA256: hash([]byte(backend[tenant])), TenantID: tenant, MaxInstances: 3})
		g.Keys = append(g.Keys, gateway.ClientKey{TokenSHA256: hash([]byte(external[tenant])), TenantID: tenant, MaxInstances: 3, BackendToken: backend[tenant], NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(24 * time.Hour)})
	}
	files := map[string][]byte{"ca.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), "input/tls.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "input/tls.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), "input/auth.json": encode(auth), "input/gateway.json": encode(g)}
	files["client.json"] = encode(struct {
		Revision   uint64            `json:"revision"`
		Tokens     map[string]string `json:"tokens"`
		Backend    map[string]string `json:"backend"`
		CAFile     string            `json:"ca_file"`
		ServerName string            `json:"server_name"`
		LeafSHA    string            `json:"leaf_sha256"`
	}{1, external, backend, root + "/ca.pem", sni, hash(der)})
	a, e := access.New(auth)
	if e != nil {
		return nil, e
	}
	_, e = gateway.NewPolicy(gateway.Snapshot{Version: 1, Epoch: 1, UID: g.UID, GID: g.GID, Listen: g.Listen, ServerName: g.ServerName, CertificatePEM: string(files["input/tls.pem"]), PrivateKeyPEM: string(files["input/tls.key"]), Keys: g.Keys}, a, now)
	return files, e
}
func setup() error {
	b, e := os.ReadFile("/etc/xandbox-systemd-install-fixture")
	if e != nil || string(b) != marker || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("owned root marker required")
	}
	b, e = os.ReadFile("/proc/1/comm")
	if e != nil || string(b) != "systemd\n" {
		return errors.New("owned PID1 required")
	}
	st, e := os.Lstat(root)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return errors.New("private fixture root required")
	}
	if e = os.Mkdir(root+"/input", 0700); e != nil {
		return e
	}
	files, e := material(time.Now().UTC())
	if e != nil {
		return e
	}
	for name, b := range files {
		f, e := os.OpenFile(root+"/"+name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(b)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		d, e := os.Open(filepath.Dir(root + "/" + name))
		if e != nil {
			return e
		}
		e = d.Sync()
		d.Close()
		if e != nil {
			return e
		}
	}
	return nil
}
func main() {
	if len(os.Args) != 2 || os.Args[1] != "setup" {
		os.Exit(1)
	}
	if setup() != nil {
		os.Stderr.WriteString("owned installer fixture setup failed\n")
		os.Exit(1)
	}
}
