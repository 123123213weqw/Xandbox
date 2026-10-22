// Package firecracker implements an experimental fail-closed Linux/KVM driver.
package firecracker

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

type Asset struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Config is operator policy, never tenant input. Paths and asset digests are
// bound to the persistent state directory; changing them requires migration.
type Config struct {
	Version          int             `json:"version"`
	RuntimeRoot      string          `json:"runtime_root"`
	CgroupRoot       string          `json:"cgroup_root"`
	UIDStart         int             `json:"uid_start"`
	UIDCount         int             `json:"uid_count"`
	ReservedUIDRange bool            `json:"reserved_uid_range"`
	Firecracker      Asset           `json:"firecracker"`
	Jailer           Asset           `json:"jailer"`
	Warden           Asset           `json:"warden"`
	Kernel           Asset           `json:"kernel"`
	Initrd           Asset           `json:"initrd"`
	Workspace        Asset           `json:"workspace"`
	Snapshot         *SnapshotPolicy `json:"snapshot,omitempty"`
}

const diskBytes = 128 << 20

var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var cgName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func key(ref sandbox.Ref) (string, error) {
	if !hex32.MatchString(ref.ID) || !hex32.MatchString(ref.Generation) {
		return "", sandbox.ErrInvalid
	}
	return ref.ID + ref.Generation, nil
}

func (c Config) validate() error {
	if (c.Version != 1 && c.Version != 2) || (c.Version == 1 && c.Snapshot != nil) || (c.Version == 2 && c.Snapshot == nil) || !c.ReservedUIDRange || c.UIDStart < 65536 || c.UIDCount < 1 || c.UIDCount > 10000 || int64(c.UIDStart) > (int64(1)<<31)-int64(c.UIDCount) {
		return errors.New("invalid Firecracker version or reserved UID range")
	}
	if !cleanAbsolute(c.RuntimeRoot) || (!strings.HasPrefix(c.RuntimeRoot, "/run/") && !strings.HasPrefix(c.RuntimeRoot, "/srv/")) || len(filepath.Join(c.RuntimeRoot, "j/firecracker", strings.Repeat("0", 64), "root/api.sock")) > 107 {
		return errors.New("runtime root must be a short canonical path below /run or /srv")
	}
	if !cleanAbsolute(c.CgroupRoot) || !strings.HasPrefix(c.CgroupRoot, "/sys/fs/cgroup/") {
		return errors.New("cgroup root must be below /sys/fs/cgroup")
	}
	for _, part := range strings.Split(strings.TrimPrefix(c.CgroupRoot, "/sys/fs/cgroup/"), "/") {
		if !cgName.MatchString(part) {
			return errors.New("invalid cgroup root component")
		}
	}
	for _, asset := range c.assets() {
		if !cleanAbsolute(asset.Path) || !hex64.MatchString(asset.SHA256) {
			return errors.New("assets require canonical absolute paths and SHA-256 digests")
		}
	}
	if p := c.Snapshot; p != nil {
		if p.Version != 1 || !hex64.MatchString(p.AgentSHA256) || p.MemoryMiB != 512 || p.VCPUs != 2 || p.MaxEntries < 1 || p.MaxEntries > 128 || p.MaxBytes < 513<<20 || p.MaxBytes > 1<<40 {
			return errors.New("invalid fixed snapshot policy or catalog budget")
		}
	}
	if filepath.Base(c.Firecracker.Path) != "firecracker" {
		return errors.New("Firecracker executable basename must be firecracker")
	}
	return nil
}

func cleanAbsolute(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p && p != "/" }

func (c Config) assets() []Asset {
	return []Asset{c.Firecracker, c.Jailer, c.Warden, c.Kernel, c.Initrd, c.Workspace}
}

func loadConfig(path string) (Config, error) {
	var c Config
	data, err := privatefile.Read(path, 16384)
	if err != nil {
		return c, err
	}
	if err := strictjson.Decode(data, &c); err != nil {
		return c, err
	}
	return c, c.validate()
}
