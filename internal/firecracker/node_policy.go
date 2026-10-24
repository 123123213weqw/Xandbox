package firecracker

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

const (
	instanceMemoryMax uint64 = 768 << 20
	instancePidsMax   uint64 = 64
	instanceCPUQuota  uint64 = 200000
	nodeCPUPeriod     uint64 = 100000
)

// NodePolicy is an immutable operator envelope. Version3 makes this mandatory;
// legacy configurations remain explicitly experimental, not silently upgraded.
// Disk admission conservatively reserves BOTH the maximum managed allocation
// and the same amount still free, rather than subtracting racy quota/statfs
// samples. External allocations (assets, exports, logs) need operator bounds.
// This is not unique-RAM billing or a node-wide ext4 project quota.
type NodePolicy struct {
	Version               int    `json:"version"`
	CgroupRoot            string `json:"cgroup_root"`
	MaxInstances          int    `json:"max_instances"`
	MaxRecords            int    `json:"max_records"`
	MaxSessions           int    `json:"max_sessions"`
	PrepareWorkers        int    `json:"prepare_workers"`
	MemoryMax             uint64 `json:"memory_max"`
	ControllerMemoryMax   uint64 `json:"controller_memory_max"`
	HostMemoryReserve     uint64 `json:"host_memory_reserve"`
	PidsMax               uint64 `json:"pids_max"`
	ControllerPidsMax     uint64 `json:"controller_pids_max"`
	CPUQuota              uint64 `json:"cpu_quota"`
	IOBytesPerSecond      uint64 `json:"io_bytes_per_second"`
	IOOperationsPerSecond uint64 `json:"io_operations_per_second"`
	DiskBytes             uint64 `json:"disk_bytes"`
	DiskInodes            uint64 `json:"disk_inodes"`
	ExternalDiskBytes     uint64 `json:"external_disk_bytes"`
	ExternalInodes        uint64 `json:"external_inodes"`
	MinFreeBytes          uint64 `json:"min_free_bytes"`
	MinFreeInodes         uint64 `json:"min_free_inodes"`
}

// NodeReservation contains planning ceilings, NOT disjoint measured charges.
// Catalog cache is deliberately counted in addition to per-instance limits.
type NodeReservation struct {
	Memory, ControllerMemory, Pids, CPUQuota uint64
	ManagedDisk, ManagedInodes               uint64
	RequiredDisk, RequiredInodes             uint64
	FreeDiskGuard, FreeInodeGuard            uint64
}

func checkedSum(values ...uint64) (uint64, error) {
	var n uint64
	for _, v := range values {
		if v > math.MaxUint64-n {
			return 0, errors.New("node reservation overflow")
		}
		n += v
	}
	return n, nil
}
func checkedProduct(a, b uint64) (uint64, error) {
	if b != 0 && a > math.MaxUint64/b {
		return 0, errors.New("node reservation overflow")
	}
	return a * b, nil
}
func (p NodePolicy) match(l sandbox.AdmissionLimits, complete bool) error {
	for _, v := range []int{l.MaxInstances, l.MaxRecords, l.MaxSessions, l.AllocatedInstances, l.RetainedRecords, l.RetainedSessions} {
		if v < 0 {
			return errors.New("negative node admission inventory")
		}
	}
	if complete && (l.MaxInstances == 0 || l.MaxRecords == 0 || l.MaxSessions == 0) {
		return errors.New("version3 requires complete service admission limits")
	}
	if l.MaxInstances != 0 && l.MaxInstances != p.MaxInstances || l.MaxRecords != 0 && l.MaxRecords != p.MaxRecords || l.MaxSessions != 0 && l.MaxSessions != p.MaxSessions {
		return ErrAdmissionMismatch
	}
	if l.AllocatedInstances > p.MaxInstances || l.RetainedRecords > p.MaxRecords || l.RetainedSessions > p.MaxSessions {
		return errors.New("recovered inventory exceeds immutable node reservation")
	}
	return nil
}
func (p NodePolicy) validate(c Config) (NodeReservation, error) {
	var r NodeReservation
	if p.Version != 1 || !cleanAbsolute(p.CgroupRoot) || filepath.Dir(c.CgroupRoot) != p.CgroupRoot || filepath.Base(c.CgroupRoot) != "instances" ||
		p.MaxInstances < 1 || p.MaxInstances > c.UIDCount || p.MaxRecords < p.MaxInstances || p.MaxRecords > sandbox.MaxLedgerRecords || p.MaxSessions < 1 || p.MaxSessions > 10000 || p.PrepareWorkers < 1 || p.PrepareWorkers > p.MaxInstances ||
		p.MemoryMax > 1<<40 || p.ControllerMemoryMax < 128<<20 || p.ControllerMemoryMax > p.MemoryMax || p.HostMemoryReserve < 256<<20 || p.HostMemoryReserve > 1<<40 ||
		p.ControllerPidsMax < 32 || p.ControllerPidsMax > 65536 || p.PidsMax > 1<<24 || p.CPUQuota > 1_000_000_000 ||
		p.IOBytesPerSecond < 1<<20 || p.IOBytesPerSecond > 1<<30 || p.IOOperationsPerSecond < 128 || p.IOOperationsPerSecond > 65536 ||
		p.DiskBytes > 1<<50 || p.DiskInodes > 1<<40 || p.ExternalDiskBytes < diskBytes || p.ExternalDiskBytes > 1<<50 || p.ExternalInodes < 32 || p.ExternalInodes > 1<<40 ||
		p.MinFreeBytes < 256<<20 || p.MinFreeBytes > 1<<50 || p.MinFreeInodes < 128 || p.MinFreeInodes > 1<<40 || c.Quota == nil || c.IO == nil {
		return r, errors.New("invalid complete node envelope or missing quota/IO policy")
	}
	n, records, sessions := uint64(p.MaxInstances), uint64(p.MaxRecords), uint64(p.MaxSessions)
	var catalog, catEntries uint64
	if c.Snapshot != nil {
		catalog = uint64(c.Snapshot.MaxBytes)
		catEntries = uint64(c.Snapshot.MaxEntries*2 + 9)
	}
	// Fixed protocol/store maxima plus generous control-runtime planning margins.
	// Kernel control/parent cgroups separately enforce their actual memory bounds.
	r.ControllerMemory = 128<<20 + records*(256<<10) + sessions*(1<<20) + n*(128<<20) + uint64(p.PrepareWorkers)*(2<<20)
	r.Memory = n*instanceMemoryMax + p.ControllerMemoryMax + catalog + uint64(p.PrepareWorkers)*(2<<20)
	r.Pids = n*instancePidsMax + p.ControllerPidsMax
	r.CPUQuota = n * instanceCPUQuota
	metadataBytes := (records+n+256)*(80<<10) + (sessions*2+64)*(144<<10) + catEntries*(32<<10) + (16 << 20)
	metadataInodes := (records+n+256)*2 + (sessions*2+64)*2 + catEntries*8 + 256
	// Counts were tightly bounded above; checked arithmetic is retained at
	// policy-controlled byte/inode multiplications and aggregate additions.
	private, e := checkedProduct(n, c.Quota.MaxBytes)
	if e != nil {
		return r, e
	}
	privateInodes, e := checkedProduct(n, c.Quota.MaxInodes)
	if e != nil {
		return r, e
	}
	r.ManagedDisk, e = checkedSum(private, catalog, metadataBytes)
	if e != nil {
		return r, e
	}
	r.ManagedInodes, e = checkedSum(privateInodes, metadataInodes)
	if e != nil {
		return r, e
	}
	twice, e := checkedProduct(r.ManagedDisk, 2)
	if e != nil {
		return r, e
	}
	r.RequiredDisk, e = checkedSum(twice, p.ExternalDiskBytes, p.MinFreeBytes)
	if e != nil {
		return r, e
	}
	twice, e = checkedProduct(r.ManagedInodes, 2)
	if e != nil {
		return r, e
	}
	r.RequiredInodes, e = checkedSum(twice, p.ExternalInodes, p.MinFreeInodes)
	if e != nil {
		return r, e
	}
	r.FreeDiskGuard, e = checkedSum(r.ManagedDisk, p.MinFreeBytes)
	if e != nil {
		return r, e
	}
	r.FreeInodeGuard, e = checkedSum(r.ManagedInodes, p.MinFreeInodes)
	if e != nil {
		return r, e
	}
	ioBytes, e := checkedProduct(n, c.IO.BytesPerSecond)
	if e != nil {
		return r, e
	}
	ioOps, e := checkedProduct(n, c.IO.OperationsPerSecond)
	if e != nil {
		return r, e
	}
	if p.MemoryMax < r.Memory || p.ControllerMemoryMax < r.ControllerMemory || p.PidsMax < r.Pids || p.CPUQuota < r.CPUQuota || p.DiskBytes < r.RequiredDisk || p.DiskInodes < r.RequiredInodes || p.IOBytesPerSecond < ioBytes || p.IOOperationsPerSecond < ioOps {
		return r, fmt.Errorf("node envelope cannot reserve all guest, control, catalog, metadata and preparation ceilings")
	}
	return r, nil
}

// ValidateAdmissionConfig rejects service-policy mismatches before backend
// binding/import. NewWithAdmission repeats this check for non-CLI callers.
func ValidateAdmissionConfig(path string, l sandbox.AdmissionLimits) error {
	c, e := loadConfig(path)
	if e != nil {
		return e
	}
	if c.Node != nil {
		return c.Node.match(l, true)
	}
	return nil
}

func nodeControllerPlacement(raw, root string) error {
	var path string
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if strings.HasPrefix(line, "0::") {
			if path != "" {
				return errors.New("duplicate unified node placement")
			}
			path = strings.TrimPrefix(line, "0::")
		}
	}
	want := strings.TrimPrefix(filepath.Join(root, "control"), "/sys/fs/cgroup")
	if !cleanAbsolute(path) || (path != want && !strings.HasPrefix(path, want+"/")) {
		return ErrControllerPlacement
	}
	return nil
}
func allowedNodeCPUs(status string) (int, error) {
	value := ""
	found := false
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "Cpus_allowed_list:") {
			if found {
				return 0, errors.New("duplicate CPU affinity")
			}
			found = true
			value = strings.TrimSpace(strings.TrimPrefix(line, "Cpus_allowed_list:"))
		}
	}
	return nodeCPUCount(value)
}
func nodeCPUCount(value string) (int, error) {
	seen := map[uint64]bool{}
	if value == "" || len(value) > 4096 {
		return 0, errors.New("invalid CPU affinity")
	}
	for _, part := range strings.Split(value, ",") {
		a, b, has := strings.Cut(part, "-")
		first, e := strconv.ParseUint(a, 10, 20)
		if e != nil {
			return 0, e
		}
		last := first
		if has {
			last, e = strconv.ParseUint(b, 10, 20)
			if e != nil {
				return 0, e
			}
		}
		if last < first || last-first >= 4096 {
			return 0, errors.New("CPU range exceeds bound")
		}
		for v := first; v <= last; v++ {
			if seen[v] || len(seen) >= 4096 {
				return 0, errors.New("duplicate/oversized CPU affinity")
			}
			seen[v] = true
		}
	}
	return len(seen), nil
}
func nodeMemTotal(raw string) (uint64, error) {
	var total uint64
	seen := false
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == "MemTotal:" {
			if seen || len(f) != 3 || f[2] != "kB" {
				return 0, errors.New("invalid physical memory inventory")
			}
			seen = true
			v, e := strconv.ParseUint(f[1], 10, 64)
			if e != nil {
				return 0, e
			}
			total, e = checkedProduct(v, 1024)
			if e != nil {
				return 0, e
			}
		}
	}
	if total == 0 {
		return 0, errors.New("physical memory inventory absent")
	}
	return total, nil
}
func checkNodeFS(p NodePolicy, r NodeReservation, block, blocks, available, files, free uint64, space bool) error {
	if block != 4096 || available > blocks || free > files {
		return errors.New("invalid node filesystem accounting")
	}
	total, e := checkedProduct(block, blocks)
	if e != nil {
		return e
	}
	avail, e := checkedProduct(block, available)
	if e != nil {
		return e
	}
	if total < p.DiskBytes || files < p.DiskInodes {
		return errors.New("filesystem cannot hold bound node disk/inode envelope")
	}
	if space && (avail < r.FreeDiskGuard || free < r.FreeInodeGuard) {
		return errors.New("node free disk/inodes below full conservative admission reserve")
	}
	return nil
}
func nodeAncestorLimit(raw string, want uint64) error {
	if raw == "max" {
		return nil
	}
	v, e := strconv.ParseUint(raw, 10, 64)
	if e != nil || v < want {
		return errors.New("ancestor budget below node envelope")
	}
	return nil
}
func nodeAncestorCPU(raw string, want uint64) error {
	f := strings.Fields(raw)
	if len(f) != 2 {
		return errors.New("invalid ancestor CPU policy")
	}
	period, e := strconv.ParseUint(f[1], 10, 64)
	if e != nil || period < 1000 || period > 1_000_000 {
		return errors.New("invalid ancestor CPU period")
	}
	if f[0] == "max" {
		return nil
	}
	quota, e := strconv.ParseUint(f[0], 10, 64)
	if e != nil || quota > 1_000_000_000_000 || quota*nodeCPUPeriod < want*period {
		return errors.New("ancestor CPU policy below node envelope")
	}
	return nil
}

// A preparation permit covers real backend staging, not Stop or reclamation.
// The manager already reserves the generation before reaching this gate.
type prepareGate struct{ tokens chan struct{} }

func newPrepareGate(capacity int) *prepareGate {
	return &prepareGate{tokens: make(chan struct{}, capacity)}
}
func (g *prepareGate) acquire(ctx context.Context) error {
	select {
	case g.tokens <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if e := ctx.Err(); e != nil {
		g.release()
		return e
	}
	return nil
}
func (g *prepareGate) release() { <-g.tokens }
