//go:build linux

package ingresslaunch

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

// Only setuid/setgid/chroot are needed by the existing root connector. Unlike
// the daemon/jailer, it gets neither SYS_ADMIN nor SYS_RESOURCE nor DAC bypass.
const capabilityCeiling = uint64(1<<6 | 1<<7 | 1<<18)

type failure struct{ stage string }

func (e *failure) Error() string { return "ingress preflight failed" }
func FailureStage(e error) string {
	if f, ok := e.(*failure); ok {
		return f.stage
	}
	return "platform"
}
func (m Manifest) checkBinding(n launch.Manifest, c gateway.Config, b firecracker.Config) error {
	if m.CheckComposition(n) != nil || n.CheckServiceBackend(b) != nil || c.StateDir != m.PolicyStateDir || c.TenantSocket != filepath.Join(n.StateDir, "api.sock") || c.BackendAuthFile != n.InputDir+"/auth.json" || b.IO == nil || b.IO.Device != m.Device {
		return errPolicy
	}
	if inside(b.RuntimeRoot, m.PolicyStateDir) || inside(m.PolicyStateDir, b.RuntimeRoot) {
		return errPolicy
	}
	return nil
}
func Run(path string) (ret error) {
	stage := "platform"
	defer func() {
		if ret != nil {
			ret = &failure{stage: stage}
		}
	}()
	if e := launch.SystemdService(); e != nil {
		return e
	}
	stage = "manifest"
	data, e := launch.ServiceFile(path, 16384)
	if e != nil {
		return e
	}
	m, e := Decode(data)
	if e != nil {
		return e
	}
	stage = "placement"
	if e = launch.ServicePlacement(m.UnitRoot); e != nil {
		return e
	}
	if e = launch.ServiceCapabilities(capabilityCeiling); e != nil {
		return e
	}
	stage = "composition"
	data, e = launch.PinnedServiceFile(m.NodeLaunch, 16384)
	if e != nil {
		return e
	}
	n, e := launch.Decode(data)
	if e != nil {
		return e
	}
	data, e = launch.PinnedServiceFile(m.Config, gateway.MaxSnapshotBytes)
	if e != nil {
		return e
	}
	var c gateway.Config
	if e = strictjson.Decode(data, &c); e != nil {
		return e
	}
	data, e = launch.PinnedServiceFile(n.Backend, 16384)
	if e != nil {
		return e
	}
	var backend firecracker.Config
	if e = strictjson.Decode(data, &backend); e != nil {
		return e
	}
	if e = m.checkBinding(n, c, backend); e != nil {
		return e
	}
	if e = firecracker.ValidateAdmissionConfig(n.Backend.Path, n.Admission()); e != nil {
		return e
	}
	// Verify the daemon's manager-owned authority snapshot against its source pin.
	// No alternative backend or caller-selected authority can be supplied.
	authority := firecracker.Asset{Path: c.BackendAuthFile, SHA256: n.Auth.SHA256}
	if _, e = launch.PinnedServiceFile(authority, 65536); e != nil {
		return e
	}
	stage = "envelope"
	if e = launch.CheckServiceEnvelope(n.UnitRoot, m.Device, n.Parent, false, os.Getpid()); e != nil {
		return e
	}
	if e = launch.CheckServiceEnvelope(m.UnitRoot, m.Device, m.Ingress, true, os.Getpid()); e != nil {
		return e
	}
	stage = "asset"
	executable, e := launch.StaticServiceELF(m.Gateway)
	if e != nil {
		return e
	}
	defer executable.Close()
	info, e := executable.Stat()
	if e != nil {
		return e
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return errors.New("privileged executable mode forbidden")
	}
	stage = "exec"
	if e = launch.ServicePlacement(m.UnitRoot); e != nil {
		return e
	}
	if e = launch.ServiceCapabilities(capabilityCeiling); e != nil {
		return e
	}
	if e = launch.RejectServiceDescriptors(); e != nil {
		return e
	}
	// The source config remains the gateway's normal reload path. Operators must
	// publish its new digest in this manifest before restart after a policy update.
	// Root is trusted; this is not atomic protection against a malicious root writer.
	e = unix.Exec("/proc/self/fd/"+strconv.Itoa(int(executable.Fd())), []string{m.Gateway.Path, "-config", m.Config.Path}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C", "GOMAXPROCS=2", "GOTRACEBACK=none"})
	runtime.KeepAlive(executable)
	return e
}
