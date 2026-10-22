package firecracker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/123123213weqw/Xandbox/internal/guestinit"
)

// SnapshotPolicy is node operator policy, never a tenant request. Catalog state
// lives below the bound backend registry; changing policy needs offline migration.
type SnapshotPolicy struct {
	Version     int    `json:"version"`
	AgentSHA256 string `json:"agent_sha256"`
	MemoryMiB   int    `json:"memory_mib"`
	VCPUs       int    `json:"vcpus"`
	MaxEntries  int    `json:"max_entries"`
	MaxBytes    int64  `json:"max_bytes"`
}

const pristineBootArgs = "console=ttyS0 reboot=k panic=1 pci=off rdinit=/sbin/init xandbox.guest=1 xandbox.pristine=1"
const snapshotStateMaxBytes = 4 << 20

// SnapshotManifest is a trusted offline builder declaration, NOT attestation.
// Source paths are deliberately excluded from its content-addressed identity.
// Only the pinned pristine guest can pass the separate one-shot admission gate.
type SnapshotManifest struct {
	Version           int       `json:"version"`
	Format            string    `json:"format"`
	SourceRevision    string    `json:"source_revision"`
	CreatedAt         time.Time `json:"created_at"`
	Assignment        string    `json:"assignment"`
	BootArgs          string    `json:"boot_args"`
	BootstrapProtocol int       `json:"bootstrap_protocol"`
	AgentSHA256       string    `json:"agent_sha256"`
	FirecrackerSHA256 string    `json:"firecracker_sha256"`
	JailerSHA256      string    `json:"jailer_sha256"`
	KernelSHA256      string    `json:"kernel_sha256"`
	InitrdSHA256      string    `json:"initrd_sha256"`
	WorkspaceSHA256   string    `json:"workspace_sha256"`
	HostABI           string    `json:"host_abi"`
	MemoryMiB         int       `json:"memory_mib"`
	VCPUs             int       `json:"vcpus"`
	MemorySHA256      string    `json:"memory_sha256"`
	StateSHA256       string    `json:"state_sha256"`
	StateBytes        int64     `json:"state_bytes"`
}

func (m SnapshotManifest) ID() string {
	b, _ := json.Marshal(m)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func (m SnapshotManifest) bytes() int64 {
	b, _ := json.Marshal(m)
	return int64(m.MemoryMiB)<<20 + m.StateBytes + int64(len(b)+1)
}
func (m SnapshotManifest) validate(cfg Config) error {
	p := cfg.Snapshot
	source, e := hex.DecodeString(m.SourceRevision)
	if p == nil || p.Version != 1 || m.Version != 1 || m.Format != "firecracker-v1.17.0-full" || e != nil || len(source) != 20 || m.CreatedAt.IsZero() || m.CreatedAt.Year() < 2020 || m.CreatedAt.Year() > 2100 || m.Assignment != "UNASSIGNED" || m.BootArgs != pristineBootArgs || m.BootstrapProtocol != guestinit.Version || m.MemoryMiB != p.MemoryMiB || m.VCPUs != p.VCPUs || m.MemoryMiB < 1 || m.MemoryMiB > 512 || m.VCPUs < 1 || m.VCPUs > 2 || m.StateBytes < 1 || m.StateBytes > snapshotStateMaxBytes {
		return errors.New("invalid pristine snapshot manifest or geometry")
	}
	for _, s := range []string{m.AgentSHA256, m.FirecrackerSHA256, m.JailerSHA256, m.KernelSHA256, m.InitrdSHA256, m.WorkspaceSHA256, m.HostABI, m.MemorySHA256, m.StateSHA256} {
		if !hex64.MatchString(s) {
			return errors.New("invalid snapshot digest")
		}
	}
	if m.AgentSHA256 != p.AgentSHA256 || m.FirecrackerSHA256 != cfg.Firecracker.SHA256 || m.JailerSHA256 != cfg.Jailer.SHA256 || m.KernelSHA256 != cfg.Kernel.SHA256 || m.InitrdSHA256 != cfg.Initrd.SHA256 || m.WorkspaceSHA256 != cfg.Workspace.SHA256 {
		return errors.New("snapshot does not match pinned node images")
	}
	return nil
}
func configDigest(cfg Config) string {
	b, _ := json.Marshal(cfg)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
