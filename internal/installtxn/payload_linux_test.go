//go:build linux

package installtxn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// Real policy/PKI validation, but no guest, block device, systemd or root CLI.
// The tokens are synthetic and the generated private key never leaves TempDir.
func inputFixture(t *testing.T) (Plan, map[string][]byte, map[string]Artifact, time.Time) {
	t.Helper()
	p := samplePlan()
	art := map[string]Artifact{}
	for _, role := range roles {
		art[role] = Artifact{role, digest([]byte(role)), 152}
	}
	b := firecracker.Config{Version: 3, RuntimeRoot: runtimeDir, CgroupRoot: unitRoot + "/node/instances", UIDStart: 400000, UIDCount: 4, ReservedUIDRange: true,
		Quota: &firecracker.QuotaPolicy{Version: 1, FilesystemUUID: strings.Repeat("a", 32), ProjectStart: 1300000, MaxBytes: 192 << 20, MaxInodes: 128},
		IO:    &firecracker.IOPolicy{Version: 1, FilesystemDevice: "1:1", Device: "1:1", BytesPerSecond: 16 << 20, OperationsPerSecond: 1024},
		Node: &firecracker.NodePolicy{Version: 1, CgroupRoot: unitRoot + "/node", MaxInstances: 4, MaxRecords: 1024, MaxSessions: 32, PrepareWorkers: 1,
			MemoryMax: 7 << 30, ControllerMemoryMax: 1 << 30, HostMemoryReserve: 512 << 20, PidsMax: 384, ControllerPidsMax: 128, CPUQuota: 800000,
			IOBytesPerSecond: 256 << 20, IOOperationsPerSecond: 8192, DiskBytes: 10 << 30, DiskInodes: 100000, ExternalDiskBytes: 2 << 30, ExternalInodes: 32768, MinFreeBytes: 256 << 20, MinFreeInodes: 2048}}
	for role, a := range map[string]*firecracker.Asset{"firecracker": &b.Firecracker, "jailer": &b.Jailer, "warden": &b.Warden, "kernel": &b.Kernel, "initrd": &b.Initrd, "workspace": &b.Workspace} {
		*a = firecracker.Asset{Path: rolePath(role), SHA256: art[role].SHA256}
	}
	now := time.Now().UTC().Truncate(time.Second)
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"xandbox.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	backendToken := strings.Repeat("b", 40)
	auth := access.Config{Version: 1, Keys: []access.Key{{TokenSHA256: digest([]byte(backendToken)), TenantID: "alpha", MaxInstances: 3}}}
	g := gateway.Config{Version: 1, PolicyRevision: 1, StateDir: policyDir, UID: 65530, GID: 65530, Listen: "127.0.0.1:18443", ServerName: "xandbox.test", EmptyRoot: childRoot, TenantSocket: stateDir + "/api.sock", BackendAuthFile: inputDir + "/auth.json", CertificateFile: Root + "/tls.pem", PrivateKeyFile: Root + "/tls.key",
		Keys: []gateway.ClientKey{{TokenSHA256: digest([]byte(strings.Repeat("c", 40))), TenantID: "alpha", MaxInstances: 3, BackendToken: backendToken, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}}}
	input := map[string][]byte{"backend.json": encode(b), "auth.json": encode(auth), "gateway.json": encode(g), "tls.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "tls.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})}
	p.Backend.SHA256, p.Auth.SHA256, p.Gateway.SHA256, p.Certificate.SHA256, p.PrivateKey.SHA256 = digest(input["backend.json"]), digest(input["auth.json"]), digest(input["gateway.json"]), digest(input["tls.pem"]), digest(input["tls.key"])
	return p, input, art, now
}
func TestInitialInputCoherenceBeforeMaterialization(t *testing.T) {
	for _, kind := range []string{"valid", "snapshot", "runtime-binding", "quota-missing", "admission", "asset-path", "asset-digest", "gateway-binding", "gateway-revision", "backend-identity", "credential-reuse", "bad-certificate", "bad-private-key", "expired-certificate", "unknown-json", "invalid-auth", "source-admission-diff"} {
		t.Run(kind, func(t *testing.T) {
			p, input, art, now := inputFixture(t)
			var b firecracker.Config
			var g gateway.Config
			if strictjson.Decode(input["backend.json"], &b) != nil || strictjson.Decode(input["gateway.json"], &g) != nil {
				t.Fatal("fixture schema")
			}
			switch kind {
			case "snapshot":
				b.Snapshot = &firecracker.SnapshotPolicy{}
			case "runtime-binding":
				b.RuntimeRoot = "/srv/another"
			case "quota-missing":
				b.Quota = nil
			case "admission":
				b.Node.MaxInstances--
			case "asset-path":
				b.Kernel.Path = "/srv/foreign/kernel"
			case "asset-digest":
				b.Kernel.SHA256 = strings.Repeat("f", 64)
			case "gateway-binding":
				g.TenantSocket = "/srv/foreign/api.sock"
			case "gateway-revision":
				g.PolicyRevision++
			case "backend-identity":
				g.Keys[0].TenantID = "beta"
			case "credential-reuse":
				g.Keys[0].TokenSHA256 = digest([]byte(g.Keys[0].BackendToken))
			case "bad-certificate":
				input["tls.pem"] = []byte("invalid")
			case "bad-private-key":
				input["tls.key"] = []byte("invalid")
			case "expired-certificate":
				now = now.Add(25 * time.Hour)
			case "invalid-auth":
				input["auth.json"] = encode(access.Config{Version: 1})
			}
			input["backend.json"], input["gateway.json"] = encode(b), encode(g)
			if kind == "unknown-json" {
				input["gateway.json"] = []byte(`{"version":1,"unexpected":true}`)
			}
			path := t.TempDir() + "/backend.json"
			source := input["backend.json"]
			if kind == "source-admission-diff" {
				b.Node.MaxInstances--
				source = encode(b)
			}
			if e := os.WriteFile(path, source, 0600); e != nil {
				t.Fatal(e)
			}
			e := validateInputs(p, input, art, now, path)
			if (e == nil) != (kind == "valid") {
				t.Fatal("initial input validation mismatch", e)
			}
		})
	}
}
