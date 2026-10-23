//go:build linux && xandbox_host_fixture

package main

// TEST ONLY fixed owned-L1 TLS gateway qualification. No path, UID, command,
// network address, credential or resource budget is accepted from fixture RPC.
import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

func gatewayLoopback() error {
	if e := requireNode(); e != nil {
		return e
	}
	interfaces, e := net.Interfaces()
	if e != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		return errors.New("owned L1 must have loopback only")
	}
	fd, e := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	request, e := unix.NewIfreq("lo")
	if e != nil {
		return e
	}
	if e = unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, request); e != nil {
		return e
	}
	request.SetUint16(request.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, request)
}

const gatewayDir = "/srv/fixture/gateway"
const gatewayConfig = gatewayDir + "/config.json"
const gatewayReceipt = gatewayDir + "/receipt.json"
const gatewayBeta = "gateway-beta"
const gatewayUID = 60001

type gatewayTLSRoundTripper struct {
	transport *http.Transport
	mu        sync.Mutex
	last      time.Time
	serial    atomic.Int64
	reused    atomic.Bool
}

func (t *gatewayTLSRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "http" || r.URL.Host != "fixture.local" {
		return nil, errors.New("fixed fixture TLS target required")
	}
	// TEST request sampling only:20req/s, not production rate/latency evidence.
	t.mu.Lock()
	delay := time.Until(t.last.Add(50 * time.Millisecond))
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			t.mu.Unlock()
			return nil, r.Context().Err()
		}
	}
	t.last = time.Now()
	t.mu.Unlock()
	out := r.Clone(r.Context())
	url := *r.URL
	url.Scheme = "https"
	url.Host = "gateway.test:9443"
	out.URL = &url
	out.Host = "gateway.test"
	if out.ContentLength == 0 {
		out.Header.Del("Content-Type")
	}
	trace := &httptrace.ClientTrace{GotConn: func(c httptrace.GotConnInfo) { t.reused.Store(c.Reused) }}
	out = out.WithContext(httptrace.WithClientTrace(out.Context(), trace))
	response, e := t.transport.RoundTrip(out)
	if e == nil {
		if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || len(response.TLS.VerifiedChains) == 0 || response.TLS.DidResume || len(response.TLS.PeerCertificates) == 0 {
			response.Body.Close()
			return nil, errors.New("verified non-resumed TLS1.3 required")
		}
		t.serial.Store(response.TLS.PeerCertificates[0].SerialNumber.Int64())
	}
	return response, e
}
func (t *gatewayTLSRoundTripper) CloseIdleConnections() { t.transport.CloseIdleConnections() }
func gatewayAPI(ca []byte, token string) (*switchAPI, *gatewayTLSRoundTripper, error) {
	if e := requireNode(); e != nil {
		return nil, nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, nil, errors.New("fixed fixture CA required")
	}
	t := &gatewayTLSRoundTripper{transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "gateway.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}, DisableCompression: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "gateway.test:9443" {
			return nil, errors.New("fixture TLS cannot fall back")
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", "127.0.0.1:9443")
	}}}
	return &switchAPI{http: &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, token: token}, t, nil
}
func gatewayHashToken(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
func gatewaySecret(name string, data []byte) error {
	if e := requireNode(); e != nil {
		return e
	}
	if name != "ca.pem" && name != "server1.pem" && name != "server1.key" && name != "server2.pem" && name != "server2.key" {
		return errors.New("fixed private certificate file required")
	}
	f, e := os.OpenFile(gatewayDir+"/"+name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(data); e != nil {
		return e
	}
	return f.Sync()
}
func gatewayPrepare(alphaBackend, betaBackend, alphaExternal, betaExternal string) (gateway.Config, []byte, error) {
	var zero gateway.Config
	if e := requireNode(); e != nil {
		return zero, nil, e
	}
	for _, dir := range []string{gatewayDir, gatewayDir + "/root", gatewayDir + "/policy"} {
		if e := os.Mkdir(dir, 0700); e != nil {
			return zero, nil, e
		}
	}
	src, e := os.Open("/srv/assets/xandbox-gateway")
	if e != nil {
		return zero, nil, e
	}
	defer src.Close()
	dest, e := os.OpenFile(gatewayDir+"/root/gateway", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0555)
	if e != nil {
		return zero, nil, e
	}
	if _, e = io.Copy(dest, src); e == nil {
		e = dest.Chmod(0555)
	}
	if e == nil {
		e = dest.Sync()
	}
	dest.Close()
	if e != nil {
		return zero, nil, e
	}
	if e = os.Chmod(gatewayDir+"/root", 0555); e != nil {
		return zero, nil, e
	}
	dir, e := os.Open(gatewayDir + "/root")
	if e != nil {
		return zero, nil, e
	}
	e = dir.Sync()
	dir.Close()
	if e != nil {
		return zero, nil, e
	}
	now := time.Now().UTC().Truncate(time.Second)
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return zero, nil, e
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "Xandbox ephemeral TEST CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if e != nil {
		return zero, nil, e
	}
	ca, e := x509.ParseCertificate(der)
	if e != nil {
		return zero, nil, e
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if e = gatewaySecret("ca.pem", caPEM); e != nil {
		return zero, nil, e
	}
	for serial := 1; serial <= 2; serial++ {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return zero, nil, e
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(int64(serial)), DNSNames: []string{"gateway.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, e := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
		if e != nil {
			return zero, nil, e
		}
		raw, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return zero, nil, e
		}
		if e = gatewaySecret(fmt.Sprintf("server%d.pem", serial), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); e != nil {
			return zero, nil, e
		}
		if e = gatewaySecret(fmt.Sprintf("server%d.key", serial), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})); e != nil {
			return zero, nil, e
		}
	}
	c := gateway.Config{Version: 1, PolicyRevision: 1, StateDir: gatewayDir + "/policy", UID: gatewayUID, GID: gatewayUID, Listen: "127.0.0.1:9443", ServerName: "gateway.test", EmptyRoot: gatewayDir + "/root", TenantSocket: "/srv/state/api.sock", BackendAuthFile: "/srv/config/auth.json", CertificateFile: gatewayDir + "/server1.pem", PrivateKeyFile: gatewayDir + "/server1.key", Keys: []gateway.ClientKey{{TokenSHA256: gatewayHashToken(alphaExternal), TenantID: "nested-fixture", MaxInstances: 2, BackendToken: alphaBackend, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}, {TokenSHA256: gatewayHashToken(betaExternal), TenantID: gatewayBeta, MaxInstances: 2, BackendToken: betaBackend, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}}}
	if e = privateWrite(gatewayConfig, c); e != nil {
		return zero, nil, e
	}
	return c, caPEM, nil
}

type gatewayProcess struct {
	cmd   *exec.Cmd
	done  chan struct{}
	err   error
	child int
}

func startGateway(ctx context.Context, label int) (*gatewayProcess, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if label < 1 || label > 5 {
		return nil, errors.New("fixed gateway launch label required")
	}
	log, e := os.OpenFile(fmt.Sprintf(gatewayDir+"/role-%d.log", label), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	defer log.Close()
	cg, e := os.Open(nodeGroup + "/control")
	if e != nil {
		return nil, e
	}
	defer cg.Close()
	cmd := exec.Command("/srv/assets/xandbox-gateway", "-config", gatewayConfig)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GOMAXPROCS=2"}
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	if e = cmd.Start(); e != nil {
		return nil, e
	}
	p := &gatewayProcess{cmd: cmd, done: make(chan struct{})}
	go func() { p.err = cmd.Wait(); close(p.done) }()
	return p, nil
}
func (p *gatewayProcess) wait(ctx context.Context, code int) error {
	select {
	case <-p.done:
		if code == 0 {
			return p.err
		}
		var ex *exec.ExitError
		if !errors.As(p.err, &ex) || ex.ExitCode() != code {
			return errors.New("gateway unexpected exit status")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *gatewayProcess) kill() {
	if p == nil {
		return
	}
	select {
	case <-p.done:
		return
	default:
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}
func (p *gatewayProcess) stop(ctx context.Context) error {
	if e := p.cmd.Process.Signal(syscall.SIGTERM); e != nil {
		return e
	}
	return p.wait(ctx, 0)
}
func (p *gatewayProcess) ready(ctx context.Context, api *switchAPI) error {
	return waitNode(ctx, func() (bool, error) {
		select {
		case <-p.done:
			return false, errors.New("gateway exited before ready")
		default:
		}
		e := api.call(ctx, "GET", "/healthz", "", nil, nil, 200)
		return e == nil, nil
	})
}
func gatewayChild(pid int) (int, error) {
	if e := requireNode(); e != nil {
		return 0, e
	}
	tasks, e := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if e != nil || len(tasks) > 128 {
		return 0, errors.New("bounded gateway tasks required")
	}
	children := make(map[int]bool)
	for _, task := range tasks {
		b, e := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/children", pid, task.Name()))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return 0, e
		}
		for _, name := range strings.Fields(string(b)) {
			id, e := strconv.Atoi(name)
			if e != nil {
				return 0, e
			}
			children[id] = true
		}
	}
	if len(children) != 1 {
		return 0, errors.New("exactly one gateway network child required")
	}
	for id := range children {
		return id, nil
	}
	return 0, errors.New("gateway child missing")
}
func gatewayRoles(p *gatewayProcess) error {
	if e := requireNode(); e != nil {
		return e
	}
	child, e := gatewayChild(p.cmd.Process.Pid)
	if e != nil {
		return e
	}
	p.child = child
	root, e := os.Stat(fmt.Sprintf("/proc/%d/root", child))
	want, e2 := os.Stat(gatewayDir + "/root")
	if e != nil || e2 != nil || !os.SameFile(root, want) {
		return errors.New("real gateway child chroot differs")
	}
	cwd, e := os.Stat(fmt.Sprintf("/proc/%d/cwd", child))
	if e != nil || !os.SameFile(cwd, want) {
		return errors.New("actual gateway cwd outside executable-only root")
	}
	group, e := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", child))
	if e != nil || !operatorStoreControlMember(string(group)) {
		return errors.New("gateway child outside fixed control")
	}
	group, e = os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", p.cmd.Process.Pid))
	if e != nil || !operatorStoreControlMember(string(group)) {
		return errors.New("gateway supervisor outside fixed control")
	}
	tasks, e := os.ReadDir(fmt.Sprintf("/proc/%d/task", child))
	if e != nil || len(tasks) > 64 {
		return errors.New("bounded gateway thread count required")
	}
	for _, task := range tasks {
		b, e := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/status", child, task.Name()))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		value := string(b)
		seen := make(map[string]bool)
		for _, line := range strings.Split(value, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			switch fields[0] {
			case "Uid:", "Gid:":
				seen[fields[0]] = true
				if len(fields) != 5 || strings.Join(fields[1:], " ") != "60001 60001 60001 60001" {
					return errors.New("gateway thread retained privilege")
				}
			case "Groups:":
				seen[fields[0]] = true
				if len(fields) != 1 {
					return errors.New("gateway thread has supplemental groups")
				}
			case "CapEff:", "CapPrm:", "CapInh:", "CapAmb:":
				seen[fields[0]] = true
				if len(fields) != 2 || fields[1] != "0000000000000000" {
					return errors.New("gateway capability nonzero")
				}
			case "NoNewPrivs:":
				seen[fields[0]] = true
				if len(fields) != 2 || fields[1] != "1" {
					return errors.New("gateway thread missing NNP")
				}
			}
		}
		if len(seen) != 8 {
			return errors.New("gateway thread privilege fields missing")
		}
	}
	limits, e := os.ReadFile(fmt.Sprintf("/proc/%d/limits", child))
	if e != nil {
		return e
	}
	for _, row := range []struct {
		name string
		soft string
	}{{"Max open files", "192"}, {"Max processes", "64"}, {"Max core file size", "0"}} {
		found := false
		for _, line := range strings.Split(string(limits), "\n") {
			fields := strings.Fields(line)
			prefix := strings.Fields(row.name)
			if len(fields) < len(prefix)+2 {
				continue
			}
			if strings.Join(fields[:len(prefix)], " ") == row.name {
				found = true
				if fields[len(prefix)] != row.soft || fields[len(prefix)+1] != row.soft {
					return errors.New("gateway actual hard/soft rlimits differ")
				}
			}
		}
		if !found {
			return errors.New("gateway rlimit witness missing")
		}
	}

	// The network LISTEN inode belongs to the unprivileged child, never root.
	b, e := os.ReadFile("/proc/net/tcp")
	if e != nil {
		return e
	}
	inode := ""
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 9 && f[1] == "0100007F:24E3" && f[3] == "0A" {
			if inode != "" {
				return errors.New("duplicate TLS listener")
			}
			inode = "socket:[" + f[9] + "]"
		}
	}
	if inode == "" {
		return errors.New("actual loopback TLS listener missing")
	}
	for _, row := range []struct {
		pid  int
		want bool
	}{{p.cmd.Process.Pid, false}, {child, true}} {
		fds, e := os.ReadDir(fmt.Sprintf("/proc/%d/fd", row.pid))
		if e != nil || len(fds) > 192 {
			return errors.New("bounded gateway descriptors required")
		}
		found := false
		for _, fd := range fds {
			target, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", row.pid, fd.Name()))
			found = found || target == inode
		}
		if found != row.want {
			return errors.New("root/network listener ownership differs")
		}
	}
	return nil
}
func gatewayGone(p *gatewayProcess) error {
	select {
	case <-p.done:
	default:
		return errors.New("gateway supervisor not reaped")
	}
	if p.child != 0 {
		if _, e := os.Stat(fmt.Sprintf("/proc/%d", p.child)); !os.IsNotExist(e) {
			return errors.New("gateway child remained")
		}
	}
	return nil
}

type tlsGatewaySaved struct {
	Version                                                         int
	L1Boot, Config, Auth, Policy, CA, IngressConfig                 string
	Before                                                          nodecontrol.State
	Raw                                                             sandbox.Ref
	OldSession                                                      sandbox.Ref
	Binding                                                         session.Result
	RawKey, SessionKey, SwitchKey, AlphaOld, AlphaNew, BetaExternal string
	Boots                                                           [3]string
}

func gatewayNegativeTLS(ctx context.Context, ca []byte) error {
	if e := requireNode(); e != nil {
		return e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errors.New("test CA")
	}
	for _, cfg := range []*tls.Config{{RootCAs: roots, ServerName: "gateway.test", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}, {RootCAs: roots, ServerName: "other.test", MinVersion: tls.VersionTLS13}} {
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: cfg}
		short, cancel := context.WithTimeout(ctx, 2*time.Second)
		conn, e := d.DialContext(short, "tcp", "127.0.0.1:9443")
		cancel()
		if e == nil {
			conn.Close()
			return errors.New("TLS version or SNI negative accepted")
		}
	}
	return nil
}
func gatewayDaemonSame(n *node, pid int, identity string) error {
	if e := requireNode(); e != nil {
		return e
	}
	if n.process == nil || n.process.Process.Pid != pid {
		return errors.New("TLS lifecycle restarted ordinary controller")
	}
	now, e := processStart(pid)
	if e != nil || now != identity {
		return errors.New("ordinary controller incarnation changed")
	}
	return nil
}
func gatewayConfigRead() (gateway.Config, error) {
	var c gateway.Config
	if e := requireNode(); e != nil {
		return c, e
	}
	b, e := privatefile.Read(gatewayConfig, gateway.MaxSnapshotBytes)
	if e != nil {
		return c, e
	}
	e = strictjson.Decode(b, &c)
	return c, e
}
func gatewayAbsentListener() error {
	if e := requireNode(); e != nil {
		return e
	}
	conn, e := net.DialTimeout("tcp", "127.0.0.1:9443", 200*time.Millisecond)
	if e == nil {
		conn.Close()
		return errors.New("TLS listener remained after gateway exit")
	}
	return nil
}
func (n *node) nodeTLSGatewayCheckpoint(ctx context.Context) (out map[string]any, err error) {
	if e := n.operatorProfile(); e != nil {
		return nil, e
	}
	if e := gatewayLoopback(); e != nil {
		return nil, e
	}
	if _, e := os.Lstat(gatewayDir); !os.IsNotExist(e) {
		return nil, errors.New("fresh private gateway fixture required")
	}
	betaBackend, e := randomKey()
	if e != nil {
		return nil, e
	}
	alphaOld, e := randomKey()
	if e != nil {
		return nil, e
	}
	alphaNew, e := randomKey()
	if e != nil {
		return nil, e
	}
	betaExternal, e := randomKey()
	if e != nil {
		return nil, e
	}
	// Ordinary operator credential provisioning BEFORE the controller starts;
	// no lifecycle/admission/ownership metadata is edited by this fixture.
	auth := access.Config{Version: 1, Keys: []access.Key{{TokenSHA256: gatewayHashToken(n.token), TenantID: "nested-fixture", MaxInstances: 2}, {TokenSHA256: gatewayHashToken(betaBackend), TenantID: gatewayBeta, MaxInstances: 2}}}
	if e = privateWrite("/srv/config/auth.json", auth); e != nil {
		return nil, e
	}
	if e = n.start(ctx); e != nil {
		return nil, e
	}
	ordinaryPID := n.process.Process.Pid
	identity, e := processStart(ordinaryPID)
	if e != nil {
		return nil, e
	}
	control, e := nodecontrol.NewClient("/srv/state")
	if e != nil {
		return nil, e
	}
	defer control.Close()
	initial, e := control.Status(ctx)
	if e != nil || !initial.Control.AdmissionOpen || initial.Control.Committed.Revision != 1 || initial.ResourceObservation.Records != 0 {
		return nil, errors.New("fresh gateway controller required")
	}
	authSHA, e := fileHash("/srv/config/auth.json")
	if e != nil {
		return nil, e
	}
	cfg, ca, e := gatewayPrepare(n.token, betaBackend, alphaOld, betaExternal)
	if e != nil {
		return nil, e
	}
	original := cfg
	alpha, alphaTrace, e := gatewayAPI(ca, alphaOld)
	if e != nil {
		return nil, e
	}
	defer alpha.close()
	beta, _, e := gatewayAPI(ca, betaExternal)
	if e != nil {
		return nil, e
	}
	defer beta.close()
	processes := make([]*gatewayProcess, 0, 4)
	defer func() {
		for _, p := range processes {
			p.kill()
		}
	}()
	first, e := startGateway(ctx, 1)
	if e != nil {
		return nil, e
	}
	processes = append(processes, first)
	if e = first.ready(ctx, alpha); e != nil {
		return nil, e
	}
	if e = gatewayRoles(first); e != nil {
		return nil, e
	}
	if alphaTrace.serial.Load() != 1 {
		return nil, errors.New("initial verified leaf not observed")
	}
	if e = gatewayNegativeTLS(ctx, ca); e != nil {
		return nil, e
	}
	for _, backendToken := range []string{n.token, betaBackend} {
		wrong, _, e := gatewayAPI(ca, backendToken)
		if e != nil {
			return nil, e
		}
		e = wrong.call(ctx, "GET", "/healthz", "", nil, nil, 401)
		wrong.close()
		if e != nil {
			return nil, errors.New("private backend token accepted at TLS frontend")
		}
	}
	for _, path := range []string{"/metrics", "/v1/node", "/v1/node/resume"} {
		if e = alpha.call(ctx, "GET", path, "", nil, nil, 400); e != nil {
			return nil, e
		}
	}
	for _, header := range []string{"Authorization", "Forwarded", "X-Tenant-ID", "Origin"} {
		request, e := http.NewRequestWithContext(ctx, "GET", "http://fixture.local/healthz", nil)
		if e != nil {
			return nil, e
		}
		request.Header.Set("Authorization", "Bearer "+alphaOld)
		if header == "Authorization" {
			request.Header.Add(header, "Bearer "+betaExternal)
		} else {
			request.Header.Set(header, "TEST-REJECT")
		}
		reply, e := alpha.http.Do(request)
		if e != nil {
			return nil, e
		}
		io.Copy(io.Discard, io.LimitReader(reply.Body, 4096))
		reply.Body.Close()
		if reply.StatusCode != 400 {
			return nil, errors.New("ambiguous or forged actual TLS request accepted")
		}
	}
	rawKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	raw, e := alpha.create(ctx, rawKey)
	if e != nil {
		return nil, e
	}
	rawBoot, e := operatorGuest(ctx, n, alpha, raw.Ref, "raw", nil)
	if e != nil {
		return nil, e
	}
	sessionKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	bound, e := beta.openSession(ctx, sessionKey)
	if e != nil {
		return nil, e
	}
	oldBoot, e := operatorGuest(ctx, n, beta, bound.Current, "session", &bound)
	if e != nil || oldBoot == rawBoot {
		return nil, errors.New("TLS tenants must have independent KVM guests")
	}
	if e = alpha.call(ctx, "GET", switchPath(bound.Current), "", nil, nil, 404); e != nil {
		return nil, e
	}
	if e = beta.call(ctx, "GET", switchPath(raw.Ref), "", nil, nil, 404); e != nil {
		return nil, e
	}
	if e = alpha.call(ctx, "GET", "/v1/sessions/"+bound.ID, "", nil, nil, 404); e != nil {
		return nil, e
	}
	// Warm an external TLS connection immediately before atomic revocation.
	if e = alpha.call(ctx, "GET", "/healthz", "", nil, nil, 200); e != nil {
		return nil, e
	}
	cfg.PolicyRevision = 2
	cfg.Keys = append([]gateway.ClientKey(nil), cfg.Keys...)
	cfg.Keys[0].TokenSHA256 = gatewayHashToken(alphaNew)
	cfg.CertificateFile = gatewayDir + "/server2.pem"
	cfg.PrivateKeyFile = gatewayDir + "/server2.key"
	if e = privateWrite(gatewayConfig, cfg); e != nil {
		return nil, e
	}
	if e = first.cmd.Process.Signal(syscall.SIGHUP); e != nil {
		return nil, e
	}
	newAlpha, newTrace, e := gatewayAPI(ca, alphaNew)
	if e != nil {
		return nil, e
	}
	defer newAlpha.close()
	if e = first.ready(ctx, newAlpha); e != nil {
		return nil, e
	}
	// Key readiness can occur on a TLS connection handshaken before publication.
	// Force a genuinely NEW handshake before requiring the rotated certificate.
	newAlpha.close()
	if e = newAlpha.call(ctx, "GET", "/healthz", "", nil, nil, 200); e != nil {
		return nil, e
	}
	if newTrace.serial.Load() != 2 {
		return nil, errors.New("rotated certificate chain not observed")
	}
	if e = alpha.call(ctx, "GET", "/healthz", "", nil, nil, 401); e != nil || !alphaTrace.reused.Load() {
		return nil, errors.New("old key not revoked on already-established TLS connection")
	}
	if e = gatewayRoles(first); e != nil {
		return nil, e
	}
	if e = gatewayDaemonSame(n, ordinaryPID, identity); e != nil {
		return nil, e
	}
	if output, e := newAlpha.executeVM(ctx, raw.Ref, []string{"cat", "operator-marker"}); e != nil || output.Stdout != "raw" {
		return nil, errors.New("key/cert rotation interrupted existing guest")
	}
	if e = privateWrite(gatewayConfig, map[string]int{"version": 99}); e != nil {
		return nil, e
	}
	if e = first.cmd.Process.Signal(syscall.SIGHUP); e != nil {
		return nil, e
	}
	if e = first.wait(ctx, 1); e != nil {
		return nil, e
	}
	if e = waitNode(ctx, func() (bool, error) { return gatewayGone(first) == nil, nil }); e != nil {
		return nil, e
	}
	if e = gatewayAbsentListener(); e != nil {
		return nil, e
	}
	if e = gatewayDaemonSame(n, ordinaryPID, identity); e != nil {
		return nil, e
	}
	// An operator-only check, not a tenant-network fallback: the backend/guest
	// must survive ingress failure and retain its data and independent authority.
	if output, e := n.execute(ctx, raw.Ref, []string{"cat", "operator-marker"}); e != nil || output.Stdout != "raw" {
		return nil, errors.New("ingress failure killed or changed old guest")
	}
	if e = privateWrite(gatewayConfig, cfg); e != nil {
		return nil, e
	}
	second, e := startGateway(ctx, 2)
	if e != nil {
		return nil, e
	}
	processes = append(processes, second)
	if e = second.ready(ctx, newAlpha); e != nil {
		return nil, e
	}
	if e = gatewayRoles(second); e != nil {
		return nil, e
	}
	if e = second.stop(ctx); e != nil {
		return nil, e
	}
	if e = waitNode(ctx, func() (bool, error) { return gatewayGone(second) == nil, nil }); e != nil {
		return nil, e
	}
	// Actual production journal must refuse the old policy before opening TCP.
	if e = privateWrite(gatewayConfig, original); e != nil {
		return nil, e
	}
	rollback, e := startGateway(ctx, 3)
	if e != nil {
		return nil, e
	}
	processes = append(processes, rollback)
	if e = rollback.wait(ctx, 1); e != nil {
		return nil, e
	}
	if e = gatewayAbsentListener(); e != nil {
		return nil, e
	}
	if e = privateWrite(gatewayConfig, cfg); e != nil {
		return nil, e
	}
	active, e := startGateway(ctx, 4)
	if e != nil {
		return nil, e
	}
	processes = append(processes, active)
	if e = active.ready(ctx, newAlpha); e != nil {
		return nil, e
	}
	if e = gatewayRoles(active); e != nil {
		return nil, e
	}
	if e = alpha.call(ctx, "GET", "/healthz", "", nil, nil, 401); e != nil {
		return nil, e
	}
	if e = gatewayDaemonSame(n, ordinaryPID, identity); e != nil {
		return nil, e
	}
	owner, _, e := budgetOwner(bound.Current)
	if e != nil {
		return nil, e
	}
	job, e := beta.sessionJob(ctx, bound, []string{"sh", "-c", "i=0; while :; do i=$((i+1)); printf '%s' \"$i\" > tls-progress; sleep 0.05; done"})
	if e != nil {
		return nil, e
	}
	var running sandbox.Job
	if e = beta.call(ctx, "GET", switchPath(bound.Current)+"/executions/"+job.ID, "", nil, &running, 200); e != nil || running.Status != "RUNNING" {
		return nil, errors.New("actual old TLS session job not running")
	}
	if _, e = beta.sessionExec(ctx, bound, []string{"sh", "-c", "test -s tls-progress; cat operator-marker"}); e != nil {
		return nil, e
	}
	switchKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	observeCtx, cancelObserve := context.WithCancel(ctx)
	defer cancelObserve()
	began := time.Now()
	type observations struct {
		stop, reclaim float64
		err           error
	}
	observed := make(chan observations, 1)
	go func() {
		o := observations{}
		o.err = waitNode(observeCtx, func() (bool, error) {
			empty, e := nodePrepareGroupEmpty(bound.Current)
			if os.IsNotExist(e) {
				return true, nil
			}
			return empty, e
		})
		if o.err == nil {
			o.stop = switchMS(began)
			o.err = budgetDestroyed(observeCtx, beta, bound.Current)
		}
		if o.err == nil {
			q, e := driverQuotaRead(owner.ProjectID)
			if e != nil || !quotaEmpty(q) {
				o.err = errors.New("old switched TLS guest quota not zero")
			}
			o.reclaim = switchMS(began)
		}
		observed <- o
	}()
	var changed session.Result
	if e = beta.call(ctx, "POST", "/v1/sessions/"+bound.ID+"/switch", switchKey, session.SwitchRequest{ExpectedRevision: 1, Create: nodeSpec()}, &changed, 200); e != nil {
		return nil, e
	}
	bindingMS := switchMS(began)
	if changed.Revision != 2 || changed.Previous != bound.Current || changed.Current == bound.Current {
		return nil, errors.New("TLS switch generation/revision invalid")
	}
	newBoot, e := operatorGuest(ctx, n, beta, changed.Current, "switched", &changed)
	if e != nil || newBoot == oldBoot || newBoot == rawBoot {
		return nil, errors.New("TLS switch guest not independent")
	}
	newCommandMS := switchMS(began)
	var measured observations
	select {
	case measured = <-observed:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if measured.err != nil {
		return nil, measured.err
	}
	if e = beta.call(ctx, "POST", "/v1/sessions/"+bound.ID+"/exec", "", map[string]any{"revision": 1, "argv": []string{"true"}}, nil, 409); e != nil {
		return nil, e
	}
	if e = beta.revoke(ctx, changed); e != nil {
		return nil, e
	}
	if e = budgetDestroyed(ctx, beta, changed.Current); e != nil {
		return nil, e
	}
	if e = newAlpha.call(ctx, "DELETE", switchPath(raw.Ref), "", generationBody(raw.Ref), nil, 202); e != nil {
		return nil, e
	}
	if e = budgetDestroyed(ctx, newAlpha, raw.Ref); e != nil {
		return nil, e
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	if e = operatorIdle(ctx, control, 0, 3); e != nil {
		return nil, e
	}
	if e = active.stop(ctx); e != nil {
		return nil, e
	}
	if e = waitNode(ctx, func() (bool, error) { return gatewayGone(active) == nil, nil }); e != nil {
		return nil, e
	}
	if e = n.stopOperatorDaemon(ctx); e != nil {
		return nil, e
	}
	saved := tlsGatewaySaved{Version: 1, L1Boot: n.boot, Before: initial.Control.Committed, Raw: raw.Ref, OldSession: bound.Current, Binding: changed, RawKey: rawKey, SessionKey: sessionKey, SwitchKey: switchKey, AlphaOld: alphaOld, AlphaNew: alphaNew, BetaExternal: betaExternal, Boots: [3]string{rawBoot, oldBoot, newBoot}}
	saved.IngressConfig, e = fileHash(gatewayConfig)
	if e != nil {
		return nil, e
	}
	saved.Config, e = fileHash("/srv/config/backend.json")
	if e != nil {
		return nil, e
	}
	saved.Auth, e = fileHash("/srv/config/auth.json")
	if e != nil || saved.Auth != authSHA {
		return nil, errors.New("transport authority changed during ingress lifecycle")
	}
	saved.Policy, e = fileHash(gatewayDir + "/policy/policy.json")
	if e != nil {
		return nil, e
	}
	saved.CA, e = fileHash(gatewayDir + "/ca.pem")
	if e != nil {
		return nil, e
	}
	if e = privateWrite(gatewayReceipt, saved); e != nil {
		return nil, e
	}
	return map[string]any{"real_nested_kvm_through_verified_tls13": true, "root_broker_no_tcp_listener_child_uid_caps_nnp_chroot_cwd_rlimits_and_control_checked": true, "two_tenants_independent_real_guest_uid_boot_workspace_cross404": true, "private_backend_tokens401_at_external_frontend": true, "operator_metrics_routes_ambiguous_headers_and_tls12_wrong_sni_rejected": true, "durable_policy_revision2_key_and_leaf_rotation_without_controller_or_guest_restart": true, "old_external_key401_on_existing_tls_connection_new_key_and_leaf2_verified": true, "invalid_reload_closes_ingress_root_child_reaped_backend_guest_continue": true, "actual_old_policy_revision1_startup_refused_no_listener": true, "same_current_policy_gateway_restart_without_controller_restart": true, "session_switch_busy_old_job_new_real_guest_old_revision409": true, "old_execution_stop_private_quota0_and_durable_destroy_independent_observations": true, "all_three_generations_destroyed_all_four_projects_zero_pools_idle": true, "gateway_and_ordinary_controller_reaped_before_private_receipt_and_cold": true, "fixture_http_pacing_ms": 50, "verified_real_guest_generations_before_cold": 3, "policy_revision": 2, "switch_to_binding_observed_ms": bindingMS, "switch_to_first_validated_new_guest_observed_ms": newCommandMS, "switch_to_old_execution_empty_observed_ms": measured.stop, "switch_to_old_private_destroy_quota_zero_observed_ms": measured.reclaim, "production_slo_or_full_tls_qualification_claim": false, "physical_policy_media_fault_or_complete_dos_claim": false}, nil
}

func validateTLSGatewaySaved(s tlsGatewaySaved, boot string) error {
	if s.Version != 1 || !switchUUID(s.L1Boot) || s.L1Boot == boot || !switchRefValid(s.Raw) || !switchRefValid(s.OldSession) || !switchRefValid(s.Binding.Current) || s.Binding.Revision != 2 || s.Binding.Previous != s.OldSession || !hex32Pattern(s.Binding.ID) || s.Raw == s.OldSession || s.Raw == s.Binding.Current || s.OldSession == s.Binding.Current {
		return errors.New("invalid TLS gateway cold identity")
	}
	for _, h := range []string{s.Config, s.Auth, s.Policy, s.CA, s.IngressConfig} {
		if !hashPattern.MatchString(h) {
			return errors.New("invalid TLS gateway private config hash")
		}
	}
	seen := make(map[string]bool)
	for _, key := range []string{s.RawKey, s.SessionKey, s.SwitchKey, s.AlphaOld, s.AlphaNew, s.BetaExternal} {
		if !hashPattern.MatchString(key) || seen[key] {
			return errors.New("invalid or repeated private TLS request/key")
		}
		seen[key] = true
	}
	boots := make(map[string]bool)
	for _, b := range s.Boots {
		if !switchUUID(b) || boots[b] {
			return errors.New("old TLS boots not distinct")
		}
		boots[b] = true
	}
	before := s.Before
	if before.Version != 1 || before.Mode != nodecontrol.ModeOpen || before.Revision != 1 || !hex32Pattern(before.Epoch) || before.LastRequestID != "" || before.LastExpectedRevision != 0 {
		return errors.New("unexpected original TLS node authority")
	}
	return nil
}
func gatewayColdRecord(ref sandbox.Ref, tenant string) error {
	if e := requireNode(); e != nil {
		return e
	}
	if !switchRefValid(ref) || tenant != "nested-fixture" && tenant != gatewayBeta {
		return errors.New("known TLS cold record required")
	}
	b, e := privatefile.Read("/srv/state/ledger/"+ref.ID+".json", sandbox.MaxLedgerRecordBytes)
	if e != nil {
		return e
	}
	var env struct {
		Version int            `json:"version"`
		Record  sandbox.Record `json:"record"`
	}
	if strictjson.Decode(b, &env) != nil || env.Version != 1 || env.Record.Ref != ref || env.Record.TenantID != tenant || env.Record.Backend != "firecracker" || env.Record.State != sandbox.Destroyed || env.Record.DestroyedAt.IsZero() {
		return errors.New("original disk TLS record not destroyed")
	}
	return budgetAbsent(ref)
}
func (n *node) nodeTLSGatewayRecover(ctx context.Context) (map[string]any, error) {
	if e := n.operatorProfile(); e != nil {
		return nil, e
	}
	if e := gatewayLoopback(); e != nil {
		return nil, e
	}
	b, e := privatefile.Read(gatewayReceipt, 32768)
	if e != nil {
		return nil, e
	}
	var saved tlsGatewaySaved
	if strictjson.Decode(b, &saved) != nil {
		return nil, errors.New("invalid private TLS cold receipt")
	}
	if e = validateTLSGatewaySaved(saved, n.boot); e != nil {
		return nil, e
	}
	for _, v := range []struct{ path, hash string }{{"/srv/config/backend.json", saved.Config}, {"/srv/config/auth.json", saved.Auth}, {gatewayDir + "/policy/policy.json", saved.Policy}, {gatewayConfig, saved.IngressConfig}, {gatewayDir + "/ca.pem", saved.CA}} {
		h, e := fileHash(v.path)
		if e != nil || h != v.hash {
			return nil, errors.New("TLS original disk policy/config changed")
		}
	}
	disk, e := operatorState()
	if e != nil || disk != saved.Before {
		return nil, errors.New("TLS cold ordinary authority changed")
	}
	for _, v := range []struct {
		ref    sandbox.Ref
		tenant string
	}{{saved.Raw, "nested-fixture"}, {saved.OldSession, gatewayBeta}, {saved.Binding.Current, gatewayBeta}} {
		if e = gatewayColdRecord(v.ref, v.tenant); e != nil {
			return nil, e
		}
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	cfg, e := gatewayConfigRead()
	if e != nil || cfg.PolicyRevision != 2 || cfg.Version != 1 || len(cfg.Keys) != 2 || cfg.Keys[0].TokenSHA256 != gatewayHashToken(saved.AlphaNew) || cfg.Keys[1].TokenSHA256 != gatewayHashToken(saved.BetaExternal) {
		return nil, errors.New("TLS cold external key policy differs")
	}
	if e = n.start(ctx); e != nil {
		return nil, e
	}
	control, e := nodecontrol.NewClient("/srv/state")
	if e != nil {
		return nil, e
	}
	defer control.Close()
	view, e := control.Status(ctx)
	if e != nil || view.Control.Committed != saved.Before || !view.Control.AdmissionOpen || view.Control.PendingSessionReservations != 0 {
		return nil, errors.New("TLS cold ordinary startup mismatch")
	}
	if e = operatorIdle(ctx, control, 0, 3); e != nil {
		return nil, e
	}
	ca, e := privatefile.Read(gatewayDir+"/ca.pem", 65536)
	if e != nil {
		return nil, e
	}
	alpha, trace, e := gatewayAPI(ca, saved.AlphaNew)
	if e != nil {
		return nil, e
	}
	defer alpha.close()
	old, _, e := gatewayAPI(ca, saved.AlphaOld)
	if e != nil {
		return nil, e
	}
	defer old.close()
	beta, _, e := gatewayAPI(ca, saved.BetaExternal)
	if e != nil {
		return nil, e
	}
	defer beta.close()
	ingress, e := startGateway(ctx, 5)
	if e != nil {
		return nil, e
	}
	defer ingress.kill()
	if e = ingress.ready(ctx, alpha); e != nil {
		return nil, e
	}
	if e = gatewayRoles(ingress); e != nil {
		return nil, e
	}
	if trace.serial.Load() != 2 {
		return nil, errors.New("cold TLS verified rotated leaf missing")
	}
	if h, e := fileHash(gatewayDir + "/policy/policy.json"); e != nil || h != saved.Policy {
		return nil, errors.New("exact policy replay rewrote durable root authority")
	}
	if e = old.call(ctx, "GET", "/healthz", "", nil, nil, 401); e != nil {
		return nil, e
	}
	if e = alpha.call(ctx, "POST", "/v1/sandboxes", saved.RawKey, nodeSpec(), nil, 410); e != nil {
		return nil, e
	}
	if e = beta.call(ctx, "POST", "/v1/sessions", saved.SessionKey, nodeSpec(), nil, 410); e != nil {
		return nil, e
	}
	if e = beta.call(ctx, "POST", "/v1/sessions/"+saved.Binding.ID+"/exec", "", map[string]any{"revision": saved.Binding.Revision, "argv": []string{"true"}}, nil, 410); e != nil {
		return nil, e
	}
	key, e := randomKey()
	if e != nil {
		return nil, e
	}
	fresh, e := alpha.create(ctx, key)
	if e != nil {
		return nil, e
	}
	boot, e := operatorGuest(ctx, n, alpha, fresh.Ref, "cold", nil)
	if e != nil {
		return nil, e
	}
	for _, oldBoot := range saved.Boots {
		if oldBoot == boot {
			return nil, errors.New("old TLS guest revived")
		}
	}
	if e = alpha.call(ctx, "DELETE", switchPath(fresh.Ref), "", generationBody(fresh.Ref), nil, 202); e != nil {
		return nil, e
	}
	if e = budgetDestroyed(ctx, alpha, fresh.Ref); e != nil {
		return nil, e
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	if e = operatorIdle(ctx, control, 0, 4); e != nil {
		return nil, e
	}
	if e = ingress.stop(ctx); e != nil {
		return nil, e
	}
	if e = waitNode(ctx, func() (bool, error) { return gatewayGone(ingress) == nil, nil }); e != nil {
		return nil, e
	}
	if e = n.stopOperatorDaemon(ctx); e != nil {
		return nil, e
	}
	for _, path := range []string{nodeBudgetInstances, nodeGroup + "/control", nodeGroup} {
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	}
	return map[string]any{"l1_boot_changed_original_policy_config_auth_and_destroyed_records_before_daemon": true, "ordinary_no_test_notification_restart_open_pending0": true, "durable_gateway_revision2_reused_without_journal_rewrite_or_key_rollback": true, "rotated_verified_tls_leaf2_and_current_key_work_old_key401_after_cold": true, "old_raw_session_keys410_and_old_closed_route410_no_guest_revival": true, "fresh_independent_real_kvm_guest_uid_workspace_through_tls_and_full_gc": true, "all_four_projects_zero_pools_idle_all_processes_reaped_node_subtree_removed": true}, nil
}
