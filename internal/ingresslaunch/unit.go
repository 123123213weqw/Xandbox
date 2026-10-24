package ingresslaunch

import (
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/123123213weqw/Xandbox/internal/launch"
)

var blockPath = regexp.MustCompile(`^/dev/(vd[a-z]|sd[a-z]|nvme[0-9]+n[0-9]+)$`)

// Unit renders a candidate, not an installer. Startup checks the kernel-resolved
// device and every limit, so a device alias or dropped directive cannot waive it.
// The system manager defaults to root; do not enter its explicit User= setuid
// path, which can drop CAP_SETUID with implicit seccomp on systemd255. Runtime
// root/capability checks stay mandatory and unchanged.
// No shell expansion, caller environment, executable selection or reload helper
// is accepted. Rotation uses an authenticated operator's main-PID SIGHUP.
func (m Manifest) Unit(n launch.Manifest, manifestPath, devicePath string) (string, error) {
	if m.CheckComposition(n) != nil || !canonical(manifestPath) || !blockPath.MatchString(devicePath) {
		return "", errPolicy
	}
	p := m.Ingress
	// systemd255 parses percentages at most to hundredths: at a100ms period
	// that is 10us. Never round an operator's immutable budget or emit a value
	// the manager ignores. Runtime kernel readback remains exact.
	if p.CPUQuota%10 != 0 {
		return "", errPolicy
	}
	cpu := fmt.Sprintf("%d", p.CPUQuota/1000)
	if remainder := (p.CPUQuota % 1000) / 10; remainder != 0 {
		cpu += fmt.Sprintf(".%02d", remainder)
	}
	node := filepath.Base(n.UnitRoot)
	return fmt.Sprintf(`[Unit]
Description=Xandbox experimental separately bounded TLS ingress
BindsTo=%s
After=%s
PartOf=%s
[Service]
Type=exec
ExecStart=/usr/libexec/xandbox-ingress-launch -manifest %s
Delegate=no
MemoryMax=%d
MemorySwapMax=0
OOMPolicy=kill
TasksMax=%d
CPUQuota=%s%%
CPUQuotaPeriodSec=100ms
IOReadBandwidthMax=%s %d
IOWriteBandwidthMax=%s %d
IOReadIOPSMax=%s %d
IOWriteIOPSMax=%s %d
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_SYS_CHROOT
AmbientCapabilities=
NoNewPrivileges=yes
ProtectControlGroups=yes
ProtectSystem=strict
ReadWritePaths=%s
PrivateDevices=yes
PrivateTmp=yes
UMask=0077
LimitCORE=0
StandardInput=null
StandardOutput=null
StandardError=journal
KillMode=control-group
TimeoutStopSec=10s
Restart=no
[Install]
WantedBy=%s
`, node, node, node, manifestPath, p.MemoryMax, p.PidsMax, cpu, devicePath, p.IOBytesPerSecond, devicePath, p.IOBytesPerSecond, devicePath, p.IOOperationsPerSecond, devicePath, p.IOOperationsPerSecond, m.PolicyStateDir, node), nil
}
