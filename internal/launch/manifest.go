// Package launch prepares only a systemd-delegated node and execs a pinned
// ordinary Firecracker daemon. It never accepts tenant commands or a fallback.
package launch

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

type Frontend struct {
	MaxInstances      int  `json:"max_instances"`
	MaxRecords        int  `json:"max_records"`
	MaxTenantRecords  int  `json:"max_tenant_records"`
	MaxSessions       int  `json:"max_sessions"`
	MaxTenantSessions int  `json:"max_tenant_sessions"`
	SessionHistory    int  `json:"session_history"`
	StopWorkers       int  `json:"stop_workers"`
	CleanupWorkers    int  `json:"cleanup_workers"`
	WorkQueueSize     int  `json:"work_queue_size"`
	Metrics           bool `json:"metrics"`
}
type ParentEnvelope struct {
	MemoryMax             uint64 `json:"memory_max"`
	PidsMax               uint64 `json:"pids_max"`
	CPUQuota              uint64 `json:"cpu_quota"`
	IOBytesPerSecond      uint64 `json:"io_bytes_per_second"`
	IOOperationsPerSecond uint64 `json:"io_operations_per_second"`
}
type Manifest struct {
	Version  int               `json:"version"`
	UnitRoot string            `json:"unit_root"`
	InputDir string            `json:"input_dir"`
	StateDir string            `json:"state_dir"`
	Daemon   firecracker.Asset `json:"daemon"`
	Backend  firecracker.Asset `json:"backend"`
	Auth     firecracker.Asset `json:"auth"`
	Frontend Frontend          `json:"frontend"`
	Parent   ParentEnvelope    `json:"parent"`
}

var unitName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}\.service$`)
var sha = regexp.MustCompile(`^[0-9a-f]{64}$`)
var errPolicy = errors.New("invalid immutable launch policy")

func canonical(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && p != "/" && !strings.ContainsAny(p, "\x00\r\n")
}
func Decode(data []byte) (Manifest, error) {
	var m Manifest
	if len(data) > 16384 {
		return m, errPolicy
	}
	if e := strictjson.Decode(data, &m); e != nil {
		return m, errPolicy
	}
	f, p := m.Frontend, m.Parent
	if m.Version != 1 || !canonical(m.UnitRoot) || filepath.Dir(m.UnitRoot) != "/sys/fs/cgroup/system.slice" || !unitName.MatchString(filepath.Base(m.UnitRoot)) ||
		m.InputDir != "/run/"+strings.TrimSuffix(filepath.Base(m.UnitRoot), ".service")+"-inputs" || !canonical(m.StateDir) || !strings.HasPrefix(m.StateDir, "/srv/") ||
		f.MaxInstances < 1 || f.MaxInstances > 10000 || f.MaxRecords < f.MaxInstances || f.MaxRecords > sandbox.MaxLedgerRecords || f.MaxTenantRecords < 1 || f.MaxTenantRecords > f.MaxRecords ||
		f.MaxSessions < 1 || f.MaxSessions > 10000 || f.MaxTenantSessions < 1 || f.MaxTenantSessions > f.MaxSessions || f.SessionHistory < 1 || f.SessionHistory > 64 ||
		f.StopWorkers < 1 || f.StopWorkers > 64 || f.CleanupWorkers < 1 || f.CleanupWorkers > 64 || f.WorkQueueSize < 1 || f.WorkQueueSize > 10000 ||
		p.MemoryMax == 0 || p.MemoryMax > 1<<40 || p.PidsMax == 0 || p.PidsMax > 1<<24 || p.CPUQuota == 0 || p.CPUQuota > 1000000000 ||
		p.IOBytesPerSecond < 1<<20 || p.IOBytesPerSecond > 1<<30 || p.IOOperationsPerSecond < 128 || p.IOOperationsPerSecond > 65536 {
		return m, errPolicy
	}
	for _, a := range []firecracker.Asset{m.Daemon, m.Backend, m.Auth} {
		if !canonical(a.Path) || !sha.MatchString(a.SHA256) {
			return m, errPolicy
		}
	}
	if filepath.Base(m.Daemon.Path) != "sandboxd" || m.Backend.Path == m.Auth.Path || inside(m.StateDir, m.Daemon.Path) || inside(m.StateDir, m.Backend.Path) || inside(m.StateDir, m.Auth.Path) {
		return m, errPolicy
	}
	return m, nil
}
func (m Manifest) Admission() sandbox.AdmissionLimits {
	return sandbox.AdmissionLimits{MaxInstances: m.Frontend.MaxInstances, MaxRecords: m.Frontend.MaxRecords, MaxSessions: m.Frontend.MaxSessions}
}
func inside(parent, path string) bool { return path == parent || strings.HasPrefix(path, parent+"/") }
func (m Manifest) checkBackend(c firecracker.Config) error {
	if c.Version != 3 || c.Node == nil || c.IO == nil || c.Quota == nil || c.Node.CgroupRoot != m.UnitRoot+"/node" || c.CgroupRoot != m.UnitRoot+"/node/instances" {
		return errPolicy
	}
	if inside(m.StateDir, c.RuntimeRoot) || inside(c.RuntimeRoot, m.StateDir) {
		return errPolicy
	}
	p, n := m.Parent, c.Node
	if p.MemoryMax < n.MemoryMax || p.MemoryMax-n.MemoryMax < 64<<20 || p.PidsMax < n.PidsMax || p.PidsMax-n.PidsMax < 16 || p.CPUQuota < n.CPUQuota ||
		p.IOBytesPerSecond < n.IOBytesPerSecond || p.IOOperationsPerSecond < n.IOOperationsPerSecond {
		return errPolicy
	}
	return nil
}
func (m Manifest) Arguments() []string {
	f := m.Frontend
	args := []string{m.Daemon.Path, "-backend", "firecracker", "-firecracker-config", m.InputDir + "/backend.json", "-auth-file", m.InputDir + "/auth.json", "-state-dir", m.StateDir}
	for _, v := range []struct {
		name string
		n    int
	}{{"max-instances", f.MaxInstances}, {"max-records", f.MaxRecords}, {"max-tenant-records", f.MaxTenantRecords}, {"max-sessions", f.MaxSessions}, {"max-tenant-sessions", f.MaxTenantSessions}, {"session-history", f.SessionHistory}, {"stop-workers", f.StopWorkers}, {"cleanup-workers", f.CleanupWorkers}, {"work-queue-size", f.WorkQueueSize}} {
		args = append(args, "-"+v.name, strconv.Itoa(v.n))
	}
	if f.Metrics {
		args = append(args, "-metrics")
	}
	return args
}
func ioLine(device string, bps, ops uint64) string {
	return fmt.Sprintf("%s rbps=%d wbps=%d riops=%d wiops=%d", device, bps, bps, ops, ops)
}
