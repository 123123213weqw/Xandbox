//go:build linux && xandbox_deploy_fixture

// TEST ONLY: fixed owned-L1 setup/rotation. Never installed as production tooling.
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
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/ingresslaunch"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const configDir = "/etc/xandbox"
const marker = "Xandbox owned systemd ingress fixture v1\n"
const manifestPath = configDir + "/ingress-launch.json"
const gatewayConfig = configDir + "/gateway.json"
const policyDir = "/srv/xb/policy"
const childRoot = "/srv/xb/gwroot/root"
const serviceRoot = "/sys/fs/cgroup/system.slice/xandbox-ingress.service"
const sni = "xandbox.fixture"

type client struct {
	Revision   uint64            `json:"revision"`
	Tokens     map[string]string `json:"tokens"`
	OldTokens  map[string]string `json:"old_tokens"`
	CAFile     string            `json:"ca_file"`
	ServerName string            `json:"server_name"`
	LeafSHA256 string            `json:"leaf_sha256"`
}

func guard() error {
	if os.Geteuid() != 0 {
		return errors.New("owned L1 root required")
	}
	b, e := os.ReadFile("/etc/xandbox-systemd-ingress-fixture")
	if e != nil || string(b) != marker {
		return errors.New("owned ingress L1 marker required")
	}
	b, e = os.ReadFile("/proc/1/comm")
	if e != nil || string(b) != "systemd\n" {
		return errors.New("owned systemd L1 required")
	}
	return nil
}
func digest(b []byte) string                        { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func read(path string, limit int64) ([]byte, error) { return privatefile.Read(path, limit) }
func put(path string, b []byte) error {
	tmp := path + ".new"
	fd, e := unix.Open(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), "fixture-private-input")
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func save(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return put(path, append(b, '\n'))
}
func load(path string, out any, limit int64) error {
	b, e := read(path, limit)
	if e != nil {
		return e
	}
	return strictjson.Decode(b, out)
}
func newToken() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func material(now time.Time, ca *x509.Certificate, caKey *ecdsa.PrivateKey) ([]byte, []byte, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if e != nil {
		return nil, nil, e
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: sni}, DNSNames: []string{sni}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if e != nil {
		return nil, nil, e
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), nil
}
func envelope() (launch.ParentEnvelope, launch.ParentEnvelope, launch.ParentEnvelope) {
	return launch.ParentEnvelope{MemoryMax: 512 << 20, PidsMax: 64, CPUQuota: 200000, IOBytesPerSecond: 64 << 20, IOOperationsPerSecond: 2048}, launch.ParentEnvelope{MemoryMax: 2 << 30, PidsMax: 64, CPUQuota: 200000, IOBytesPerSecond: 128 << 20, IOOperationsPerSecond: 4096}, launch.ParentEnvelope{MemoryMax: 12 << 30, PidsMax: 1024, CPUQuota: 1200000, IOBytesPerSecond: 1 << 30, IOOperationsPerSecond: 32768}
}

type fixtureFailure struct{ stage string }

func (f *fixtureFailure) Error() string {
	return "owned ingress fixture setup failed (" + f.stage + ")"
}
func configure(revision uint64) (ret error) {
	stage := "guard"
	defer func() {
		if ret != nil {
			ret = &fixtureFailure{stage: stage}
		}
	}()

	if e := guard(); e != nil {
		return e
	}
	stage = "assets"
	var assets map[string]firecracker.Asset
	if e := load(configDir+"/ingress-assets.json", &assets, 16384); e != nil {
		return e
	}
	if len(assets) != 3 {
		return errors.New("exact ingress fixture assets required")
	}
	for _, n := range []string{"gateway", "ingress", "helper"} {
		a, ok := assets[n]
		if !ok {
			return errors.New("missing ingress asset")
		}
		b, e := os.ReadFile(a.Path)
		if e != nil || len(b) > 64<<20 || digest(b) != a.SHA256 {
			return errors.New("fixed ingress asset mismatch")
		}
	}
	stage = "node"
	nodeBytes, e := read(configDir+"/launch.json", 16384)
	if e != nil {
		return e
	}
	n, e := launch.Decode(nodeBytes)
	if e != nil {
		return e
	}
	var backend firecracker.Config
	if e = load(configDir+"/backend.json", &backend, 16384); e != nil || backend.IO == nil {
		return errors.New("fixed backend required")
	}
	if b, e := read(manifestPath, 16384); e == nil {
		m, e := ingresslaunch.Decode(b)
		if e != nil || m.NodeLaunch.SHA256 != digest(nodeBytes) || m.Config.Path != gatewayConfig {
			return errors.New("saved manifest binding mismatch")
		}
		if revision == 1 {
			var c gateway.Config
			if e = load(gatewayConfig, &c, gateway.MaxSnapshotBytes); e != nil {
				return e
			}
			cb, e := read(gatewayConfig, gateway.MaxSnapshotBytes)
			if e != nil || digest(cb) != m.Config.SHA256 || c.PolicyRevision < 1 || c.PolicyRevision > 2 {
				return errors.New("saved policy rejected")
			}
			return nil
		}
	} else if !os.IsNotExist(e) {
		return e
	} else if revision != 1 {
		return errors.New("rotation requires original manifest")
	}
	stage = "authority"
	var backendTokens map[string]string
	if e = load(configDir+"/client-fixture.json", &backendTokens, 4096); e != nil || len(backendTokens) != 2 {
		return errors.New("two private backend credentials required")
	}
	stage = "certificate"
	now := time.Now()
	var ca *x509.Certificate
	var caKey *ecdsa.PrivateKey
	if revision == 1 {
		for _, p := range []string{configDir + "/ingress-client-fixture.json", configDir + "/gateway-ca.pem", gatewayConfig} {
			if _, e := os.Lstat(p); !os.IsNotExist(e) {
				return errors.New("used partial fixture input cannot bootstrap")
			}
		}
		caKey, e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return e
		}
		tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Xandbox isolated TEST CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &caKey.PublicKey, caKey)
		if e != nil {
			return e
		}
		ca, e = x509.ParseCertificate(der)
		if e != nil {
			return e
		}
		pk, e := x509.MarshalPKCS8PrivateKey(caKey)
		if e != nil {
			return e
		}
		if e = put(configDir+"/gateway-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); e != nil {
			return e
		}
		if e = put(configDir+"/gateway-ca.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})); e != nil {
			return e
		}
		stage = "child_root"
		if e = os.Mkdir(policyDir, 0700); e != nil {
			return e
		}
		if e = os.Mkdir("/srv/xb/gwroot", 0700); e != nil {
			return e
		}
		if e = os.Mkdir(childRoot, 0755); e != nil {
			return e
		}
		b, e := os.ReadFile(assets["gateway"].Path)
		if e != nil {
			return e
		}
		if e = os.WriteFile(childRoot+"/gateway", b, 0555); e != nil {
			return e
		}
		if e = os.Chmod(childRoot+"/gateway", 0555); e != nil {
			return e
		}
		if e = os.Chmod(childRoot, 0555); e != nil {
			return e
		}
	} else {
		var old client
		if e = load(configDir+"/ingress-client-fixture.json", &old, 8192); e != nil || old.Revision != 1 {
			return errors.New("fixed first rotation only")
		}
		b, e := read(configDir+"/gateway-ca.pem", 65536)
		if e != nil {
			return e
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return errors.New("CA PEM required")
		}
		ca, e = x509.ParseCertificate(block.Bytes)
		if e != nil {
			return e
		}
		b, e = read(configDir+"/gateway-ca.key", 65536)
		if e != nil {
			return e
		}
		block, _ = pem.Decode(b)
		if block == nil {
			return errors.New("CA key required")
		}
		key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return e
		}
		var ok bool
		caKey, ok = key.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("fixed CA key required")
		}
	}
	stage = "policy"
	cert, key, e := material(now, ca, caKey)
	if e != nil {
		return e
	}
	certPath := fmt.Sprintf("%s/gateway-leaf%d.pem", configDir, revision)
	keyPath := fmt.Sprintf("%s/gateway-leaf%d.key", configDir, revision)
	if e = put(certPath, cert); e != nil {
		return e
	}
	if e = put(keyPath, key); e != nil {
		return e
	}
	c := gateway.Config{Version: 1, PolicyRevision: revision, UID: 65530, GID: 65530, StateDir: policyDir, Listen: "127.0.0.1:18443", ServerName: sni, EmptyRoot: childRoot, TenantSocket: n.StateDir + "/api.sock", BackendAuthFile: n.InputDir + "/auth.json", CertificateFile: certPath, PrivateKeyFile: keyPath}
	cli := client{Revision: revision, Tokens: map[string]string{}, CAFile: configDir + "/gateway-ca.pem", ServerName: sni}
	if revision == 2 {
		var old client
		if e = load(configDir+"/ingress-client-fixture.json", &old, 8192); e != nil {
			return e
		}
		cli.OldTokens = old.Tokens
	}
	for _, tenant := range []string{"alpha", "beta"} {
		token, e := newToken()
		if e != nil {
			return e
		}
		cli.Tokens[tenant] = token
		c.Keys = append(c.Keys, gateway.ClientKey{TokenSHA256: digest([]byte(token)), TenantID: tenant, MaxInstances: 3, BackendToken: backendTokens[tenant], NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(24 * time.Hour)})
	}
	block, _ := pem.Decode(cert)
	cli.LeafSHA256 = digest(block.Bytes)
	if e = save(gatewayConfig, c); e != nil {
		return e
	}
	configBytes, e := read(gatewayConfig, gateway.MaxSnapshotBytes)
	if e != nil {
		return e
	}
	in, res, cap := envelope()
	m := ingresslaunch.Manifest{Version: 1, UnitRoot: serviceRoot, PolicyStateDir: policyDir, Gateway: assets["gateway"], Config: firecracker.Asset{Path: gatewayConfig, SHA256: digest(configBytes)}, NodeLaunch: firecracker.Asset{Path: configDir + "/launch.json", SHA256: digest(nodeBytes)}, Device: backend.IO.Device, Ingress: in, Reserve: res, Capacity: cap}
	stage = "unit"
	unit, e := m.Unit(n, manifestPath, "/dev/vda")
	if e != nil {
		return e
	}
	if e = save(manifestPath, m); e != nil {
		return e
	}
	if e = put("/etc/systemd/system/xandbox-ingress.service", []byte(unit)); e != nil {
		return e
	}
	return save(configDir+"/ingress-client-fixture.json", cli)
}
func main() {
	if len(os.Args) != 2 || (os.Args[1] != "setup" && os.Args[1] != "rotate") {
		os.Exit(1)
	}
	r := uint64(1)
	if os.Args[1] == "rotate" {
		r = 2
	}
	if e := configure(r); e != nil {
		fmt.Fprintln(os.Stderr, e.Error())
		os.Exit(1)
	}
}
