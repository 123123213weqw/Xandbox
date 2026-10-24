//go:build linux && xandbox_managed_fixture

// TEST ONLY PKI/input producer for an independently marked, owned managed L1.
// No service activation, signal, task argv or alternate output-root selection.
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
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const root = "/etc/xandbox-managed-fixture"
const marker = "Xandbox owned managed policy fixture v1\n"
const sni = "xandbox.fixture"
const pendingLifetime = time.Minute

func hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func encode(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic("fixed fixture value")
	}
	return append(b, '\n')
}
func token() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func pemKey(key *ecdsa.PrivateKey) ([]byte, error) {
	b, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
}

type client struct {
	Revision   uint64            `json:"revision"`
	Tokens     map[string]string `json:"tokens"`
	CAFile     string            `json:"ca_file"`
	ServerName string            `json:"server_name"`
	LeafSHA    string            `json:"leaf_sha256"`
}

func leaf(now time.Time, epoch uint64, ca *x509.Certificate, caKey *ecdsa.PrivateKey, s gateway.Snapshot, a *access.Authenticator) (gateway.Snapshot, client, error) {
	lifetime := 24 * time.Hour
	if epoch == 2 {
		lifetime = pendingLifetime
	}
	return leafLifetime(now, epoch, lifetime, ca, caKey, s, a)
}
func leafLifetime(now time.Time, epoch uint64, lifetime time.Duration, ca *x509.Certificate, caKey *ecdsa.PrivateKey, s gateway.Snapshot, a *access.Authenticator) (gateway.Snapshot, client, error) {
	var zero client
	if epoch < 1 || epoch > 3 || (lifetime != 24*time.Hour && (epoch != 2 || lifetime != pendingLifetime)) {
		return s, zero, errors.New("fixed fixture leaf lifetime required")
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return s, zero, e
	}
	cert := &x509.Certificate{SerialNumber: new(big.Int).SetUint64(epoch + 10), DNSNames: []string{sni}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(lifetime), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
	if e != nil {
		return s, zero, e
	}
	pk, e := pemKey(key)
	if e != nil {
		return s, zero, e
	}
	s.Epoch = epoch
	s.CertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	s.PrivateKeyPEM = string(pk)
	s.Keys = append([]gateway.ClientKey(nil), s.Keys...)
	c := client{Revision: epoch, Tokens: map[string]string{}, CAFile: root + "/ca.pem", ServerName: sni, LeafSHA: hash(der)}
	for i := range s.Keys {
		t, e := token()
		if e != nil {
			return s, zero, e
		}
		s.Keys[i].TokenSHA256 = hash([]byte(t))
		s.Keys[i].NotBefore = now.Add(-time.Minute)
		s.Keys[i].ExpiresAt = now.Add(24 * time.Hour)
		c.Tokens[s.Keys[i].TenantID] = t
	}
	_, e = gateway.NewPolicy(s, a, now)
	return s, c, e
}
func initial(now time.Time) (map[string][]byte, error) {
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned managed fixture CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		return nil, e
	}
	ca, e = x509.ParseCertificate(der)
	if e != nil {
		return nil, e
	}
	caPrivate, e := pemKey(caKey)
	if e != nil {
		return nil, e
	}
	auth := access.Config{Version: 1}
	c := gateway.Config{Version: 2, PolicyRevision: 1, StateDir: "/srv/xi/p", UID: 65530, GID: 65530, Listen: "127.0.0.1:18443", ServerName: sni, EmptyRoot: "/srv/xi/g/root", TenantSocket: "/srv/xi/s/api.sock", BackendAuthFile: "/run/xandbox-inputs/auth.json", ManagedPolicyFile: gateway.ManagedPolicyPath}
	s := gateway.Snapshot{Version: 1, UID: c.UID, GID: c.GID, Listen: c.Listen, ServerName: sni}
	for _, tenant := range []string{"alpha", "beta"} {
		t, e := token()
		if e != nil {
			return nil, e
		}
		auth.Keys = append(auth.Keys, access.Key{TokenSHA256: hash([]byte(t)), TenantID: tenant, MaxInstances: 3})
		s.Keys = append(s.Keys, gateway.ClientKey{TenantID: tenant, MaxInstances: 3, BackendToken: t})
	}
	authority, e := access.New(auth)
	if e != nil {
		return nil, e
	}
	s, cl, e := leaf(now, 1, ca, caKey, s, authority)
	if e != nil {
		return nil, e
	}
	raw, e := gateway.EncodePolicyEnvelope(gateway.PolicyEnvelope{Version: 1, Revision: 1, Snapshot: s})
	if e != nil {
		return nil, e
	}
	c.InitialPolicySHA256 = hash(raw)
	if _, e = gateway.ValidateManagedSnapshot(c, raw, "", authority, now); e != nil {
		return nil, e
	}
	return map[string][]byte{"ca.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "ca.key": caPrivate, "input/auth.json": encode(auth), "input/gateway.json": encode(c), "input/policy-initial.json": raw, "client-1.json": encode(cl)}, nil
}

type materialSpec struct {
	epoch    uint64
	stem     string
	lifetime time.Duration
}

func materialOperation(operation string) (materialSpec, bool) {
	switch operation {
	case "rotation2":
		return materialSpec{2, "2", pendingLifetime}, true
	case "rotation2long":
		return materialSpec{2, "2", 24 * time.Hour}, true
	case "rotation3":
		return materialSpec{3, "3", 24 * time.Hour}, true
	case "replacement2a":
		return materialSpec{2, "replacement-2a", 24 * time.Hour}, true
	case "replacement2b":
		return materialSpec{2, "replacement-2b", 24 * time.Hour}, true
	}
	return materialSpec{}, false
}

func rotation(now time.Time, epoch uint64, c gateway.Config, current gateway.PolicyEnvelope, authRaw, caRaw, keyRaw []byte) (map[string][]byte, error) {
	operation := ""
	if epoch == 2 {
		operation = "rotation2"
	} else if epoch == 3 {
		operation = "rotation3"
	}
	return material(now, operation, c, current, authRaw, caRaw, keyRaw)
}

func material(now time.Time, operation string, c gateway.Config, current gateway.PolicyEnvelope, authRaw, caRaw, keyRaw []byte) (map[string][]byte, error) {
	spec, ok := materialOperation(operation)
	if !ok || current.Version != 1 || current.Revision+1 != spec.epoch || current.Snapshot.Epoch != current.Revision || c.Version != 2 || c.ValidateShape() != nil || current.Snapshot.UID != c.UID || current.Snapshot.GID != c.GID || current.Snapshot.Listen != c.Listen || current.Snapshot.ServerName != c.ServerName || c.ServerName != sni {
		return nil, errors.New("fixture next epoch required")
	}
	var auth access.Config
	if strictjson.Decode(authRaw, &auth) != nil {
		return nil, errors.New("fixture authority required")
	}
	authority, e := access.New(auth)
	if e != nil {
		return nil, e
	}
	block, rest := pem.Decode(caRaw)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, errors.New("fixture CA required")
	}
	ca, e := x509.ParseCertificate(block.Bytes)
	if e != nil || !ca.IsCA || now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return nil, errors.New("fixture CA required")
	}
	block, rest = pem.Decode(keyRaw)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, errors.New("fixture CA key required")
	}
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, e
	}
	caKey, ok := key.(*ecdsa.PrivateKey)
	if !ok || !caKey.PublicKey.Equal(ca.PublicKey) {
		return nil, errors.New("fixture CA pair required")
	}
	block, rest = pem.Decode([]byte(current.Snapshot.CertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, errors.New("fixture predecessor required")
	}
	previous, e := x509.ParseCertificate(block.Bytes)
	if e != nil || previous.CheckSignatureFrom(ca) != nil {
		return nil, errors.New("fixture predecessor CA required")
	}
	// The predecessor's certificate may already be expired. Only decode its
	// installed authority; validate the fresh NEW candidate at actual now.
	s, cl, e := leafLifetime(now, spec.epoch, spec.lifetime, ca, caKey, current.Snapshot, authority)
	if e != nil {
		return nil, e
	}
	name := spec.stem
	path := root + "/sources/snapshot-" + name + ".json"
	raw := encode(s)
	plan := struct {
		Version int `json:"version"`
		Policy  struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"policy"`
	}{Version: 1}
	plan.Policy.Path = path
	plan.Policy.SHA256 = hash(raw)
	return map[string][]byte{"sources/snapshot-" + name + ".json": raw, "rotation-" + name + ".json": encode(plan), "client-" + name + ".json": encode(cl)}, nil
}
func guard() error {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("owned root fixture required")
	}
	if e := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); e != nil {
		return e
	}
	b, e := os.ReadFile("/etc/xandbox-systemd-managed-fixture")
	if e != nil || string(b) != marker {
		return errors.New("owned marker required")
	}
	b, e = os.ReadFile("/proc/1/comm")
	if e != nil || string(b) != "systemd\n" {
		return errors.New("owned PID1 required")
	}
	_, e = privatefile.ExistingDirectory(root)
	return e
}
func writeFiles(files map[string][]byte) error {
	for name, b := range files {
		path := filepath.Join(root, name)
		if name == "" || filepath.Clean(name) != name || filepath.IsAbs(name) || (filepath.Dir(path) != root && filepath.Dir(path) != root+"/input" && filepath.Dir(path) != root+"/sources") {
			return errors.New("fixed fixture paths required")
		}
		if _, e := privatefile.ExistingDirectory(filepath.Dir(path)); e != nil {
			return e
		}
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
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
		d, e := os.Open(filepath.Dir(path))
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
func run(arg string) error {
	_, supported := materialOperation(arg)
	if arg != "setup" && !supported {
		return errors.New("fixed fixture operation required")
	}
	if e := guard(); e != nil {
		return e
	}
	now := time.Now().UTC().Truncate(time.Second)
	if arg == "setup" {
		if e := os.Mkdir(root+"/input", 0700); e != nil {
			return e
		}
		files, e := initial(now)
		if e != nil {
			return e
		}
		return writeFiles(files)
	}
	if e := os.Mkdir(root+"/sources", 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return e
	}
	read := func(path string, max int64) ([]byte, error) { return privatefile.Read(path, max) }
	raw, e := read("/etc/xandbox-install/gateway.json", gateway.MaxSnapshotBytes)
	if e != nil {
		return e
	}
	var c gateway.Config
	if strictjson.Decode(raw, &c) != nil {
		return errors.New("installed managed config required")
	}
	commit, e := read("/etc/xandbox-install/commit.json", 65536)
	if e != nil {
		return e
	}
	base, e := gateway.ValidateManagedBase(c, raw, commit)
	if e != nil {
		return e
	}
	raw, e = read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes)
	if e != nil {
		return e
	}
	current, e := gateway.DecodeManagedEnvelope(c, raw, base)
	if e != nil {
		return e
	}
	auth, e := read("/etc/xandbox-install/auth.json", 65536)
	if e != nil {
		return e
	}
	ca, e := read(root+"/ca.pem", 65536)
	if e != nil {
		return e
	}
	key, e := read(root+"/ca.key", 65536)
	if e != nil {
		return e
	}
	files, e := material(now, arg, c, current, auth, ca, key)
	if e != nil {
		return e
	}
	return writeFiles(files)
}
func main() {
	if len(os.Args) != 2 || run(os.Args[1]) != nil {
		os.Stderr.WriteString("xandbox-managed-fixture: owned fixed fixture refused\n")
		os.Exit(1)
	}
}
