// Package gateway contains the bounded tenant-only TLS frontend. It never
// opens a state directory or chooses an upstream path from an HTTP request.
package gateway

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

const MaxSnapshotBytes = 512 << 10
const MaxBodyBytes = 64 << 10
const MaxResponseBytes = 8 << 20
const MaxConnections = 32
const MaxInflight = 8
const MaxLeases = 16
const LeaseLifetime = 45 * time.Second
const RequestTimeout = 40 * time.Second
const ConnectionLifetime = 90 * time.Second

// ClientKey is operator input. BackendToken is a different, private credential
// of the existing controller; external keys can rotate without restarting VMs.
// Never log or return this object, even on validation errors.
type ClientKey struct {
	TokenSHA256  string    `json:"token_sha256"`
	TenantID     string    `json:"tenant_id"`
	MaxInstances int       `json:"max_instances"`
	BackendToken string    `json:"backend_token"`
	NotBefore    time.Time `json:"not_before"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Snapshot is transferred only through a sealed private descriptor. Disk paths
// and all choices of upstream socket are absent from the child protocol.
type Snapshot struct {
	Version        int         `json:"version"`
	Epoch          uint64      `json:"epoch"`
	UID            uint32      `json:"uid"`
	GID            uint32      `json:"gid"`
	Listen         string      `json:"listen"`
	ServerName     string      `json:"server_name"`
	CertificatePEM string      `json:"certificate_pem"`
	PrivateKeyPEM  string      `json:"private_key_pem"`
	Keys           []ClientKey `json:"keys"`
}
type credential struct {
	digest               [32]byte
	tenant, backend      string
	notBefore, expiresAt time.Time
}
type Policy struct {
	snapshot    Snapshot
	cert        tls.Certificate
	credentials []credential
	ratesMu     sync.Mutex
	rates       map[string]*bucket
	tenants     map[string]chan struct{}
}

func serverNameValid(s string) bool {
	if len(s) < 1 || len(s) > 253 || s != strings.ToLower(s) || strings.HasSuffix(s, ".") {
		return false
	}
	if _, e := netip.ParseAddr(s); e == nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func validToken(s string) bool {
	if len(s) < 32 || len(s) > 512 {
		return false
	}
	for _, r := range s {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}

// NewPolicy validates a complete immutable certificate/key/authorization unit.
// backend, when non-nil in the root supervisor, is the startup controller auth
// authority. A child revalidates syntax/certificates without reading root files.
func NewPolicy(s Snapshot, backend *access.Authenticator, now time.Time) (*Policy, error) {
	bad := errors.New("invalid gateway policy")
	addr, e := netip.ParseAddrPort(s.Listen)
	if e != nil || addr.Port() < 1024 || addr.Addr().IsMulticast() || s.Version != 1 || s.Epoch == 0 || s.UID < 1000 || s.UID > 65534 || s.GID != s.UID || !serverNameValid(s.ServerName) || len(s.Keys) > 256 || len(s.CertificatePEM) > 65536 || len(s.PrivateKeyPEM) > 65536 {
		return nil, bad
	}
	cert, e := tls.X509KeyPair([]byte(s.CertificatePEM), []byte(s.PrivateKeyPEM))
	if e != nil || len(cert.Certificate) == 0 || len(cert.Certificate) > 8 {
		return nil, bad
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil || leaf.VerifyHostname(s.ServerName) != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, bad
	}
	serverUsage := len(leaf.ExtKeyUsage) == 0
	for _, v := range leaf.ExtKeyUsage {
		if v == x509.ExtKeyUsageServerAuth || v == x509.ExtKeyUsageAny {
			serverUsage = true
		}
	}
	if !serverUsage || leaf.IsCA {
		return nil, bad
	}
	cert.Leaf = leaf
	authKeys := make([]access.Key, 0, len(s.Keys))
	privateDigests := make(map[[32]byte]bool)
	tenantBackend := make(map[string]string)
	backendTenant := make(map[string]string)
	for _, key := range s.Keys {
		if !validToken(key.BackendToken) || key.NotBefore.IsZero() || !key.ExpiresAt.After(key.NotBefore) || key.ExpiresAt.Sub(key.NotBefore) > 90*24*time.Hour {
			return nil, bad
		}
		owner := sandbox.Owner{TenantID: key.TenantID, MaxInstances: key.MaxInstances}
		if !owner.Valid() {
			return nil, bad
		}
		if backend != nil {
			actual, e := backend.Authenticate("Bearer " + key.BackendToken)
			if e != nil || actual != owner {
				return nil, bad
			}
		}
		if prior, ok := tenantBackend[key.TenantID]; ok && prior != key.BackendToken {
			return nil, bad
		}
		tenantBackend[key.TenantID] = key.BackendToken
		if prior, ok := backendTenant[key.BackendToken]; ok && prior != key.TenantID {
			return nil, bad
		}
		backendTenant[key.BackendToken] = key.TenantID
		privateDigests[sha256.Sum256([]byte(key.BackendToken))] = true
		authKeys = append(authKeys, access.Key{TokenSHA256: key.TokenSHA256, TenantID: key.TenantID, MaxInstances: key.MaxInstances})
	}
	if _, e := access.New(access.Config{Version: 1, Keys: authKeys}); len(authKeys) > 0 && e != nil {
		return nil, bad
	}
	p := &Policy{snapshot: s, cert: cert, rates: make(map[string]*bucket), tenants: make(map[string]chan struct{})}
	// Copy the caller's slice; a policy is never modified after publication.
	p.snapshot.Keys = append([]ClientKey(nil), s.Keys...)
	for _, key := range s.Keys {
		b, _ := hex.DecodeString(key.TokenSHA256)
		var digest [32]byte
		copy(digest[:], b)
		if privateDigests[digest] {
			return nil, bad
		}
		p.credentials = append(p.credentials, credential{digest: digest, tenant: key.TenantID, backend: key.BackendToken, notBefore: key.NotBefore, expiresAt: key.ExpiresAt})
		p.rates[key.TenantID] = &bucket{tokens: 64, last: now}
		p.tenants[key.TenantID] = make(chan struct{}, 2)
	}
	return p, nil
}
func (p *Policy) validAt(now time.Time) bool {
	return !now.Before(p.cert.Leaf.NotBefore) && now.Before(p.cert.Leaf.NotAfter)
}
func (p *Policy) authenticate(header string, now time.Time) (credential, bool) {
	if !strings.HasPrefix(header, "Bearer ") || len(header) > 520 || !validToken(strings.TrimPrefix(header, "Bearer ")) {
		return credential{}, false
	}
	digest := sha256.Sum256([]byte(strings.TrimPrefix(header, "Bearer ")))
	var found credential
	ok := false
	for _, c := range p.credentials {
		if subtle.ConstantTimeCompare(digest[:], c.digest[:]) == 1 && !now.Before(c.notBefore) && now.Before(c.expiresAt) {
			found, ok = c, true
		}
	}
	return found, ok
}

type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) allow(now time.Time, rate, burst float64) bool {
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rate
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
func (p *Policy) tenantRate(tenant string, now time.Time) bool {
	p.ratesMu.Lock()
	defer p.ratesMu.Unlock()
	return p.rates[tenant].allow(now, 32, 64)
}

type Store struct {
	current   atomic.Pointer[Policy]
	publishMu sync.Mutex
}

func (s *Store) Current() *Policy { return s.current.Load() }
func (s *Store) Publish(p *Policy) error {
	s.publishMu.Lock()
	defer s.publishMu.Unlock()
	if p == nil {
		return errors.New("gateway policy missing")
	}
	old := s.Current()
	if old != nil && (p.snapshot.Epoch <= old.snapshot.Epoch || p.snapshot.Listen != old.snapshot.Listen || p.snapshot.ServerName != old.snapshot.ServerName || p.snapshot.UID != old.snapshot.UID || p.snapshot.GID != old.snapshot.GID) {
		return errors.New("immutable gateway binding or policy sequence changed")
	}
	s.current.Store(p)
	return nil
}
func (s *Store) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true, GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		p := s.Current()
		if p == nil || h.ServerName != p.snapshot.ServerName || !p.validAt(time.Now()) {
			return nil, errors.New("TLS identity unavailable")
		}
		return &p.cert, nil
	}}
}
func (p *Policy) hostValid(host string) bool {
	addr, _ := netip.ParseAddrPort(p.snapshot.Listen)
	return host == p.snapshot.ServerName || host == p.snapshot.ServerName+":"+strconv.Itoa(int(addr.Port()))
}
