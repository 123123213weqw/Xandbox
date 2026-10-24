// Package installtxn materializes a committed artifact release and reconciles a
// fixed systemd composition. This is an initial-install transaction, not an
// upgrade, a backend binding migration, a task runner or a root adversary boundary.
package installtxn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/ingresslaunch"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"github.com/123123213weqw/Xandbox/internal/releasestore"
	"github.com/123123213weqw/Xandbox/internal/serviceready"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

const Root = "/etc/xandbox-install"
const DataRoot = "/srv/xi"
const SelfPath = "/usr/libexec/xandbox-install"
const MainUnit = "xandbox.service"
const IngressUnit = "xandbox-ingress.service"
const UnitDir = "/etc/systemd/system"
const MaxPlan = 16384
const unitRoot = "/sys/fs/cgroup/system.slice/" + MainUnit
const inputDir = "/run/xandbox-inputs"
const launchPath = Root + "/launch.json"
const ingressPath = Root + "/ingress.json"
const readyPath = Root + "/readiness.json"
const stateDir = DataRoot + "/s"
const runtimeDir = DataRoot + "/r"
const policyDir = DataRoot + "/p"
const childRoot = DataRoot + "/g/root"
const assetDir = DataRoot + "/a"

var ErrPolicy = errors.New("invalid initial installation policy")
var ErrInventory = errors.New("unrecognized installation inventory")
var ErrConflict = errors.New("installation request conflict")
var ErrPlatform = errors.New("root Linux systemd initial installer required")
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var requestPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var pathPattern = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)
var devicePattern = regexp.MustCompile(`^/dev/(vd[a-z]|sd[a-z]|nvme[0-9]+n[0-9]+)$`)
var roles = []string{"daemon", "firecracker", "gateway", "ingress", "initrd", "jailer", "kernel", "launcher", "node", "ready", "template", "warden", "workspace"}

type Plan struct {
	Version         int                   `json:"version"`
	ReleaseRevision uint64                `json:"release_revision"`
	Release         string                `json:"release"`
	Self            firecracker.Asset     `json:"self"`
	Backend         firecracker.Asset     `json:"backend"`
	Auth            firecracker.Asset     `json:"auth"`
	Gateway         firecracker.Asset     `json:"gateway"`
	Certificate     firecracker.Asset     `json:"certificate"`
	PrivateKey      firecracker.Asset     `json:"private_key"`
	DevicePath      string                `json:"device_path"`
	Frontend        launch.Frontend       `json:"frontend"`
	Parent          launch.ParentEnvelope `json:"parent"`
	Ingress         launch.ParentEnvelope `json:"ingress"`
	Reserve         launch.ParentEnvelope `json:"reserve"`
	Capacity        launch.ParentEnvelope `json:"capacity"`
}
type Artifact struct {
	Role   string `json:"role"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}
type Release struct {
	Version        int        `json:"version"`
	SourceRevision string     `json:"source_revision"`
	Toolchain      string     `json:"toolchain"`
	GOARCH         string     `json:"goarch"`
	Files          []Artifact `json:"files"`
}
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Mode   uint32 `json:"mode"`
}
type transaction struct {
	Version   int     `json:"version"`
	Revision  uint64  `json:"revision"`
	RequestID string  `json:"request_id"`
	Plan      Plan    `json:"plan"`
	Release   Release `json:"release"`
	Files     []File  `json:"files"`
}

type Result struct {
	Version           int    `json:"version"`
	Revision          uint64 `json:"revision"`
	FilesCommitted    bool   `json:"files_committed"`
	ManagerReconciled bool   `json:"manager_reconciled"`
	ProductionReady   bool   `json:"production_ready"`
}

func encode(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic("fixed install schema not encodable")
	}
	return append(b, '\n')
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func canonical(p string) bool {
	return pathPattern.MatchString(p) && filepath.Clean(p) == p && p != "/"
}
func inside(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }
func Decode(raw []byte) (Plan, error) {
	var p Plan
	if len(raw) == 0 || len(raw) > MaxPlan || strictjson.Decode(raw, &p) != nil || p.Version != 1 || p.ReleaseRevision == 0 || !digestPattern.MatchString(p.Release) || !devicePattern.MatchString(p.DevicePath) {
		return p, ErrPolicy
	}
	paths := map[string]bool{}
	for i, a := range []firecracker.Asset{p.Self, p.Backend, p.Auth, p.Gateway, p.Certificate, p.PrivateKey} {
		if !canonical(a.Path) || !digestPattern.MatchString(a.SHA256) || paths[a.Path] || inside(a.Path, Root) || inside(a.Path, DataRoot) || inside(a.Path, UnitDir) || (i != 0 && inside(a.Path, "/usr/libexec")) {
			return p, ErrPolicy
		}
		paths[a.Path] = true
	}
	// Reuse the existing strict budget/serialization rules, not a looser unit template.
	n := nodeManifest(p, map[string]Artifact{"daemon": {SHA256: strings.Repeat("0", 64)}})
	if _, e := launch.Decode(encode(n)); e != nil {
		return p, ErrPolicy
	}
	g := ingressManifest(p, n, "1:1", map[string]Artifact{"gateway": {SHA256: strings.Repeat("0", 64)}})
	if g.CheckComposition(n) != nil {
		return p, ErrPolicy
	}
	return p, nil
}
func rolePath(role string) string {
	switch role {
	case "launcher":
		return "/usr/libexec/xandbox-launch"
	case "ready":
		return serviceready.HelperPath
	case "ingress":
		return "/usr/libexec/xandbox-ingress-launch"
	case "daemon":
		return assetDir + "/sandboxd"
	case "gateway":
		return assetDir + "/xandbox-gateway"
	case "template":
		return assetDir + "/xandbox-template"
	default:
		return assetDir + "/" + role
	}
}
func executable(role string) bool { return role != "kernel" && role != "initrd" && role != "workspace" }
func nodeManifest(p Plan, art map[string]Artifact) launch.Manifest {
	return launch.Manifest{Version: 1, UnitRoot: unitRoot, InputDir: inputDir, StateDir: stateDir, Daemon: firecracker.Asset{Path: rolePath("daemon"), SHA256: art["daemon"].SHA256}, Backend: firecracker.Asset{Path: Root + "/backend.json", SHA256: p.Backend.SHA256}, Auth: firecracker.Asset{Path: Root + "/auth.json", SHA256: p.Auth.SHA256}, Frontend: p.Frontend, Parent: p.Parent}
}
func ingressManifest(p Plan, n launch.Manifest, device string, art map[string]Artifact) ingresslaunch.Manifest {
	return ingresslaunch.Manifest{Version: 1, UnitRoot: "/sys/fs/cgroup/system.slice/" + IngressUnit, PolicyStateDir: policyDir, Gateway: firecracker.Asset{Path: rolePath("gateway"), SHA256: art["gateway"].SHA256}, Config: firecracker.Asset{Path: Root + "/gateway.json", SHA256: p.Gateway.SHA256}, NodeLaunch: firecracker.Asset{Path: launchPath, SHA256: digest(encode(n))}, Device: device, Ingress: p.Ingress, Reserve: p.Reserve, Capacity: p.Capacity}
}

// render uses the production generators unchanged. Only this installer's main
// candidate adds a fixed read-only commit gate BEFORE the original launcher.
func render(p Plan, device string, art map[string]Artifact) (map[string][]byte, error) {
	n := nodeManifest(p, art)
	g := ingressManifest(p, n, device, art)
	r := serviceready.Manifest{Version: 1, NodeLaunch: g.NodeLaunch, Helper: firecracker.Asset{Path: serviceready.HelperPath, SHA256: art["ready"].SHA256}, Device: device}
	main, e := r.DaemonUnit(n, readyPath, p.DevicePath)
	if e != nil {
		return nil, ErrPolicy
	}
	ingress, e := g.Unit(n, ingressPath, p.DevicePath)
	if e != nil {
		return nil, ErrPolicy
	}
	needle := "Type=exec\nExecStart="
	if strings.Count(main, needle) != 1 {
		return nil, ErrPolicy
	}
	main = strings.Replace(main, needle, "Type=exec\nExecStartPre="+SelfPath+" verify\nExecStart=", 1)
	return map[string][]byte{launchPath: encode(n), ingressPath: encode(g), readyPath: encode(r), UnitDir + "/" + MainUnit: []byte(main), UnitDir + "/" + IngressUnit: []byte(ingress)}, nil
}

func descriptor(r Release) (map[string]Artifact, error) {
	m := releasestore.Manifest{Version: r.Version, SourceRevision: r.SourceRevision, Toolchain: r.Toolchain, GOARCH: r.GOARCH}
	for _, v := range r.Files {
		m.Files = append(m.Files, releasestore.File{Role: v.Role, Source: "/descriptor/" + v.Role, SHA256: v.SHA256, Bytes: v.Bytes})
	}
	normalized, e := releasestore.Decode(encode(m))
	if e != nil || len(normalized.Files) != len(roles) {
		return nil, ErrPolicy
	}
	out := map[string]Artifact{}
	for i, v := range r.Files {
		if v.Role != roles[i] {
			return nil, ErrPolicy
		}
		out[v.Role] = v
	}
	return out, nil
}
