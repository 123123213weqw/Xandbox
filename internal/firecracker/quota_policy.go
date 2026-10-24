package firecracker

import (
	"errors"
	"strings"
)

// QuotaPolicy is immutable operator policy. A project is paired with a durable
// reserved UID slot, not with a caller-chosen ID or a reusable guest identity.
// Shared catalog inodes and node-wide metadata need separate admission budgets.
type QuotaPolicy struct {
	Version        int    `json:"version"`
	FilesystemUUID string `json:"filesystem_uuid"`
	ProjectStart   uint32 `json:"project_start"`
	MaxBytes       uint64 `json:"max_bytes"`
	MaxInodes      uint64 `json:"max_inodes"`
}

func (p QuotaPolicy) validate(slots int) error {
	if p.Version != 1 || !hex32.MatchString(p.FilesystemUUID) || p.FilesystemUUID == strings.Repeat("0", 32) ||
		p.ProjectStart < 65536 || slots < 1 || slots > 10000 || uint64(p.ProjectStart)+uint64(slots)-1 > 1<<32-1 ||
		p.MaxBytes < 16<<20 || p.MaxBytes > 1<<40 || p.MaxBytes%4096 != 0 || p.MaxInodes < 1 || p.MaxInodes > 1<<20 {
		return errors.New("invalid ext4 project quota policy or reserved project range")
	}
	return nil
}

func (c Config) projectForUID(uid int) (uint32, bool) {
	if c.Quota == nil || uid < c.UIDStart || uid >= c.UIDStart+c.UIDCount {
		return 0, false
	}
	return c.Quota.ProjectStart + uint32(uid-c.UIDStart), true
}

func snapshotOwnership(o ownership) bool { return o.Version == 2 || o.Version == 4 }
