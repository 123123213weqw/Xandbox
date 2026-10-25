// Package ingresslaunch starts only a pinned TLS gateway in a separately bounded
// systemd service. It never launches a tenant command or modifies node cgroups.
package ingresslaunch

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

type Manifest struct {
	Version        int                   `json:"version"`
	UnitRoot       string                `json:"unit_root"`
	PolicyStateDir string                `json:"policy_state_dir"`
	Gateway        firecracker.Asset     `json:"gateway"`
	Config         firecracker.Asset     `json:"config"`
	NodeLaunch     firecracker.Asset     `json:"node_launch"`
	Device         string                `json:"device"`
	Ingress        launch.ParentEnvelope `json:"ingress"`
	Reserve        launch.ParentEnvelope `json:"reserve"`
	Capacity       launch.ParentEnvelope `json:"capacity"`
}

var errPolicy = errors.New("invalid ingress service policy")
var unitName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}\.service$`)
var safePath = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)
var sha = regexp.MustCompile(`^[0-9a-f]{64}$`)
var device = regexp.MustCompile(`^(0|[1-9][0-9]{0,6}):(0|[1-9][0-9]{0,6})$`)

func canonical(p string) bool         { return safePath.MatchString(p) && filepath.Clean(p) == p && p != "/" }
func inside(parent, path string) bool { return parent == path || strings.HasPrefix(path, parent+"/") }
func validBudget(p launch.ParentEnvelope) bool {
	return p.MemoryMax >= 64<<20 && p.MemoryMax <= 1<<40 && p.PidsMax >= 16 && p.PidsMax <= 1<<24 && p.CPUQuota >= 1000 && p.CPUQuota <= 1000000000 && p.IOBytesPerSecond >= 1<<20 && p.IOBytesPerSecond <= 1<<30 && p.IOOperationsPerSecond >= 128 && p.IOOperationsPerSecond <= 65536
}
func Decode(data []byte) (Manifest, error) {
	var m Manifest
	if len(data) > 16384 || strictjson.Decode(data, &m) != nil {
		return m, errPolicy
	}
	if m.Version != 1 || !canonical(m.UnitRoot) || filepath.Dir(m.UnitRoot) != "/sys/fs/cgroup/system.slice" || !unitName.MatchString(filepath.Base(m.UnitRoot)) || !canonical(m.PolicyStateDir) || !strings.HasPrefix(m.PolicyStateDir, "/srv/") || !device.MatchString(m.Device) || m.Device == "0:0" || !validBudget(m.Ingress) || !validBudget(m.Reserve) || !validBudget(m.Capacity) {
		return m, errPolicy
	}
	paths := map[string]bool{}
	for _, a := range []firecracker.Asset{m.Gateway, m.Config, m.NodeLaunch} {
		if !canonical(a.Path) || !sha.MatchString(a.SHA256) || paths[a.Path] || inside(m.PolicyStateDir, a.Path) {
			return m, errPolicy
		}
		paths[a.Path] = true
	}
	if filepath.Base(m.Gateway.Path) != "xandbox-gateway" {
		return m, errPolicy
	}
	return m, nil
}

// CheckComposition counts the entire daemon parent, the entire separate ingress
// service, and explicit host/operator reserve. Capacity is an operator accounting
// ceiling, NOT a common kernel-enforced parent or proof of available host capacity.
func (m Manifest) CheckComposition(n launch.Manifest) error {
	raw, e := json.Marshal(m)
	if e != nil {
		return errPolicy
	}
	if _, e = Decode(raw); e != nil {
		return errPolicy
	}
	raw, e = json.Marshal(n)
	if e != nil {
		return errPolicy
	}
	if _, e = launch.Decode(raw); e != nil {
		return errPolicy
	}

	if m.UnitRoot == n.UnitRoot || inside(n.StateDir, m.PolicyStateDir) || inside(m.PolicyStateDir, n.StateDir) || inside(n.InputDir, m.PolicyStateDir) || inside(m.PolicyStateDir, n.InputDir) {
		return errPolicy
	}
	dimensions := func(p launch.ParentEnvelope) []uint64 {
		return []uint64{p.MemoryMax, p.PidsMax, p.CPUQuota, p.IOBytesPerSecond, p.IOOperationsPerSecond}
	}
	cap, ing, res, node := dimensions(m.Capacity), dimensions(m.Ingress), dimensions(m.Reserve), dimensions(n.Parent)
	for i, total := range cap {
		for _, used := range []uint64{ing[i], res[i], node[i]} {
			if used > total {
				return errPolicy
			}
			total -= used
		}
	}
	return nil
}
