// Package serviceready provides a fixed, read-only systemd ExecStartPost gate.
// It does not launch tasks, change admission or make health a KVM certification.
package serviceready

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

const HelperPath = "/usr/libexec/xandbox-ready"
const WaitSeconds = 30

type Manifest struct {
	Version    int               `json:"version"`
	NodeLaunch firecracker.Asset `json:"node_launch"`
	Helper     firecracker.Asset `json:"helper"`
	Device     string            `json:"device"`
}

var pathPattern = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)
var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var devicePattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,6}):(0|[1-9][0-9]{0,6})$`)
var blockPattern = regexp.MustCompile(`^/dev/(vd[a-z]|sd[a-z]|nvme[0-9]+n[0-9]+)$`)
var errPolicy = errors.New("invalid readiness policy")

func canonical(p string) bool {
	return pathPattern.MatchString(p) && filepath.Clean(p) == p && p != "/"
}
func Decode(data []byte) (Manifest, error) {
	var m Manifest
	if len(data) > 16384 || strictjson.Decode(data, &m) != nil || m.Version != 1 || !canonical(m.NodeLaunch.Path) || !shaPattern.MatchString(m.NodeLaunch.SHA256) || m.Helper.Path != HelperPath || !shaPattern.MatchString(m.Helper.SHA256) || m.NodeLaunch.Path == m.Helper.Path || !devicePattern.MatchString(m.Device) || m.Device == "0:0" {
		return m, errPolicy
	}
	return m, nil
}

// DaemonUnit renders a candidate composition, never writes/enables a host unit.
// ExecStartPost completion participates in After= ordering. Its main command is
// still the existing same-PID launcher; no wrapper/shell/tenant argv is added.
func (m Manifest) DaemonUnit(n launch.Manifest, manifestPath, devicePath string) (string, error) {
	b, e := json.Marshal(m)
	if e != nil {
		return "", errPolicy
	}
	if _, e = Decode(b); e != nil {
		return "", e
	}
	b, e = json.Marshal(n)
	if e != nil {
		return "", errPolicy
	}
	if _, e = launch.Decode(b); e != nil {
		return "", e
	}
	if !canonical(manifestPath) || manifestPath == m.NodeLaunch.Path || !blockPattern.MatchString(devicePath) || n.Parent.CPUQuota%10 != 0 {
		return "", errPolicy
	}
	p := n.Parent
	cpu := fmt.Sprintf("%d", p.CPUQuota/1000)
	if r := (p.CPUQuota % 1000) / 10; r != 0 {
		cpu += fmt.Sprintf(".%02d", r)
	}
	return fmt.Sprintf(`[Unit]
Description=Xandbox experimental pinned daemon with bounded startup readiness
After=local-fs.target
[Service]
Type=exec
ExecStart=/usr/libexec/xandbox-launch -manifest %s
ExecStartPost=/usr/libexec/xandbox-ready -manifest %s
Delegate=cpu io memory pids
DelegateSubgroup=bootstrap
RuntimeDirectory=%s
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=no
MemoryMax=%d
MemorySwapMax=0
TasksMax=%d
CPUQuota=%s%%
CPUQuotaPeriodSec=100ms
IOReadBandwidthMax=%s %d
IOWriteBandwidthMax=%s %d
IOReadIOPSMax=%s %d
IOWriteIOPSMax=%s %d
CapabilityBoundingSet=~CAP_SYS_RESOURCE
NoNewPrivileges=yes
UMask=0077
LimitCORE=0
StandardInput=null
StandardOutput=null
StandardError=journal
KillMode=mixed
TimeoutStartSec=45s
TimeoutStopSec=12s
Restart=no
[Install]
WantedBy=multi-user.target
`, m.NodeLaunch.Path, manifestPath, filepath.Base(n.InputDir), p.MemoryMax, p.PidsMax, cpu, devicePath, p.IOBytesPerSecond, devicePath, p.IOBytesPerSecond, devicePath, p.IOOperationsPerSecond, devicePath, p.IOOperationsPerSecond), nil
}

type failure struct{ stage string }

func (e *failure) Error() string { return "service readiness failed" }
func FailureStage(e error) string {
	if f, ok := e.(*failure); ok {
		return f.stage
	}
	return "platform"
}
