//go:build linux && xandbox_host_fixture

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

type snapshotFixturePolicy struct {
	SourceRevision string `json:"source_revision"`
	AgentSHA256    string `json:"agent_sha256"`
	AdminSHA256    string `json:"admin_sha256"`
	BuilderSHA256  string `json:"builder_sha256"`
}

// This fixed operator builder runs only in our L1. It creates an UNASSIGNED
// template in the actual L1 CPU/kernel ABI; it never relabels an L0 snapshot.
func (n *node) quotaSnapshotSetup(ctx context.Context) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.quotaSnapshot || n.process != nil {
		return nil, errors.New("fresh fixed snapshot profile required")
	}
	for _, path := range []string{"/srv/export", "/srv/qb", "/srv/state/firecracker/config.json"} {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			return nil, errors.New("snapshot setup refuses existing export, builder or backend binding")
		}
	}
	b, e := os.ReadFile("/srv/config/snapshot-fixture.json")
	if e != nil {
		return nil, e
	}
	var p snapshotFixturePolicy
	if e = strictjson.Decode(b, &p); e != nil {
		return nil, e
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(p.SourceRevision) {
		return nil, errors.New("fixed builder source revision required")
	}
	for path, want := range map[string]string{"/srv/assets/admin": p.AdminSHA256, "/srv/assets/snapshot-builder": p.BuilderSHA256} {
		actual, e := fileHash(path)
		if e != nil || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(want) || actual != want {
			return nil, errors.New("fixed builder/admin digest mismatch")
		}
	}
	b, e = os.ReadFile("/srv/config/backend.json")
	if e != nil {
		return nil, e
	}
	var cfg firecracker.Config
	if e = strictjson.Decode(b, &cfg); e != nil {
		return nil, e
	}
	if cfg.Version != 2 || cfg.Snapshot == nil || cfg.Quota == nil || cfg.Snapshot.AgentSHA256 != p.AgentSHA256 || cfg.Snapshot.MemoryMiB != 512 || cfg.Snapshot.VCPUs != 2 {
		return nil, errors.New("fixed snapshot backend policy required")
	}
	pins := map[string]string{"agent": p.AgentSHA256, "workspace": cfg.Workspace.SHA256}
	for name, asset := range map[string]firecracker.Asset{"firecracker": cfg.Firecracker, "jailer": cfg.Jailer, "warden": cfg.Warden, "kernel": cfg.Kernel, "initrd": cfg.Initrd} {
		pins[name] = asset.SHA256
	}
	f := map[string]any{"Root": "/srv/qb", "Cgroup": "/sys/fs/cgroup/xandbox-pristine-proof-qdriver", "Firecracker": cfg.Firecracker.Path, "Jailer": cfg.Jailer.Path, "Warden": cfg.Warden.Path, "Kernel": cfg.Kernel.Path, "Initrd": cfg.Initrd.Path, "Workspace": cfg.Workspace.Path, "Report": "/srv/fixture/snapshot-builder-report.json", "SourceRevision": p.SourceRevision, "ExportDirectory": "/srv/export", "UIDStart": 450000, "SHA256": pins}
	if e = privateWrite("/srv/fixture/snapshot-builder-config.json", f); e != nil {
		return nil, e
	}
	log, e := os.OpenFile("/srv/fixture/snapshot-builder.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, e
	}
	cmd := exec.CommandContext(ctx, "/srv/assets/snapshot-builder", "-test.run=^TestKVMPristineBootstrapSnapshot$", "-test.v")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "XANDBOX_KVM_PRISTINE=1", "XANDBOX_KVM_PRISTINE_FIXTURE=/srv/fixture/snapshot-builder-config.json"}
	cmd.Stdout, cmd.Stderr = log, log
	e = cmd.Run()
	log.Close()
	if e != nil {
		// PRIVATE diagnostics only. Never copy this raw builder log to the
		// sanitized acceptance JSON or tenant API. Drain its serial tail.
		if f, openErr := os.Open("/srv/fixture/snapshot-builder.log"); openErr == nil {
			if info, statErr := f.Stat(); statErr == nil {
				off := info.Size() - 8192
				if off < 0 {
					off = 0
				}
				f.Seek(off, 0)
				io.CopyN(os.Stderr, f, 8192)
			}
			f.Close()
		}
		time.Sleep(time.Second)
		return nil, fmt.Errorf("fixed L1 snapshot builder failed: %w", e)
	}
	for _, path := range []string{"/srv/qb", "/sys/fs/cgroup/xandbox-pristine-proof-qdriver"} {
		if _, e = os.Lstat(path); !os.IsNotExist(e) {
			return nil, errors.New("builder runtime was not reclaimed")
		}
	}
	b, e = os.ReadFile("/srv/fixture/snapshot-builder-report.json")
	if e != nil {
		return nil, e
	}
	var report struct {
		Test      string            `json:"test"`
		Source    string            `json:"source_revision"`
		Toolchain string            `json:"toolchain"`
		Checks    []string          `json:"checks"`
		Samples   []json.RawMessage `json:"samples"`
	}
	if e = json.Unmarshal(b, &report); e != nil {
		return nil, e
	}
	if report.Test != "experimental_pristine_bootstrap_snapshot_component" || report.Source != p.SourceRevision || report.Toolchain != "go1.27.3" || len(report.Checks) < 6 || len(report.Samples) != 2 {
		return nil, errors.New("actual pristine builder/two-clone report missing")
	}
	b, e = os.ReadFile("/srv/export/manifest.json")
	if e != nil {
		return nil, e
	}
	var m firecracker.SnapshotManifest
	if e = strictjson.Decode(b, &m); e != nil {
		return nil, e
	}
	abi, e := firecracker.SnapshotHostABI()
	if e != nil {
		return nil, e
	}
	if m.Assignment != "UNASSIGNED" || m.HostABI != abi || m.SourceRevision != p.SourceRevision || m.AgentSHA256 != p.AgentSHA256 || m.MemoryMiB != 512 || m.VCPUs != 2 {
		return nil, errors.New("export is not an L1-built unassigned template")
	}
	workspaceHash, e := fileHash("/srv/export/workspace.ext4")
	if e != nil || workspaceHash != m.WorkspaceSHA256 {
		return nil, errors.New("export workspace digest mismatch")
	}
	cfg.Workspace = firecracker.Asset{Path: "/srv/export/workspace.ext4", SHA256: workspaceHash}
	// This is still unbound state: no daemon has opened the registry yet.
	if e = privateWrite("/srv/config/backend.json", cfg); e != nil {
		return nil, e
	}
	if e = n.start(ctx); e != nil {
		return nil, e
	}
	admin := func(arguments ...string) ([]byte, error) {
		args := append([]string{"-state-dir", "/srv/state", "-config", "/srv/config/backend.json"}, arguments...)
		c := exec.CommandContext(ctx, "/srv/assets/admin", args...)
		c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
		c.Stderr = os.Stderr
		var out bytes.Buffer
		c.Stdout = &out
		if e := c.Run(); e != nil {
			return nil, e
		}
		if out.Len() > 8192 {
			return nil, errors.New("oversized fixed admin reply")
		}
		return out.Bytes(), nil
	}
	b, e = admin("-manifest", "/srv/export/manifest.json", "-memory", "/srv/export/memory", "-snapshot-state", "/srv/export/state", "publish")
	if e != nil {
		return nil, e
	}
	var published struct {
		ID string `json:"template_id"`
	}
	if e = strictjson.Decode(b, &published); e != nil {
		return nil, e
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(published.ID) || strings.Trim(published.ID, "0") == "" {
		return nil, errors.New("invalid published template identifier")
	}
	if _, e = admin("activate", published.ID); e != nil {
		return nil, e
	}
	sharing, e := n.quotaSnapshotSharing(ctx, admin, published.ID)
	if e != nil {
		return nil, e
	}
	return map[string]any{"quota_snapshot_sharing": sharing, "genuine_l1_unassigned_template_built": true, "l1_host_abi_checked": true, "builder_two_independent_clones_checked": true, "builder_runtime_reclaimed": true, "ordinary_catalog_published_and_activated": true, "snapshot_memory_bytes": 512 << 20}, nil
}

func (n *node) quotaSnapshotSharing(ctx context.Context, admin func(...string) ([]byte, error), template string) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.quotaSnapshot {
		return nil, errors.New("fixed snapshot profile required")
	}
	clones := []sandbox.Record{}
	projects := []uint32{}
	roots := []string{}
	for i, marker := range []string{"quota-a", "quota-b"} {
		key, e := randomKey()
		if e != nil {
			return nil, e
		}
		r, e := n.create(ctx, key)
		if e != nil {
			return nil, e
		}
		clones = append(clones, r)
		if e = actualNestedVM(r.Ref); e != nil {
			return nil, e
		}
		u, e := n.execute(ctx, r.Ref, []string{"id", "-u"})
		if e != nil || strings.TrimSpace(u.Stdout) != "65534" {
			return nil, errors.New("wrong snapshot guest UID")
		}
		if _, e = n.execute(ctx, r.Ref, []string{"sh", "-c", "printf " + marker + " > quota-marker"}); e != nil {
			return nil, e
		}
		k := r.ID + r.Generation
		b, e := os.ReadFile("/srv/state/firecracker/" + k + ".json")
		if e != nil {
			return nil, e
		}
		var o struct {
			Version     int    `json:"version"`
			Project     uint32 `json:"project_id"`
			Template    string `json:"template_id"`
			Attempt     bool   `json:"quota_attempted"`
			Initialized bool   `json:"initialization_attempted"`
		}
		if e = json.Unmarshal(b, &o); e != nil {
			return nil, e
		}
		if o.Version != 4 || !o.Attempt || !o.Initialized || o.Template != template {
			return nil, errors.New("snapshot did not persist quota and initialized template ownership")
		}
		projects = append(projects, o.Project)
		root := "/srv/r/j/firecracker/" + k
		roots = append(roots, root)
		if e = verifySharedQuotaFiles(root); e != nil {
			return nil, e
		}
		blocks, inodes, entries, e := driverQuotaTree(root, true)
		if e != nil {
			return nil, e
		}
		record, e := driverQuotaRead(o.Project)
		if e != nil {
			return nil, e
		}
		if e = validateDriverQuotaAccounting(driverQuotaReceipt{Snapshot: true, Record: record, Entries: entries}, record, blocks, inodes, entries); e != nil {
			return nil, e
		}
		if i == 1 && projects[0] == projects[1] {
			return nil, errors.New("live clones share a private quota project")
		}
	}
	for _, name := range []string{"template.mem", "template.state"} {
		var a, b unix.Stat_t
		if e := unix.Lstat(filepath.Join(roots[0], "root", name), &a); e != nil {
			return nil, e
		}
		if e := unix.Lstat(filepath.Join(roots[1], "root", name), &b); e != nil {
			return nil, e
		}
		if a.Dev != b.Dev || a.Ino != b.Ino || a.Nlink < 3 {
			return nil, errors.New("ordinary clones did not share pinned read-only catalog inodes")
		}
	}
	pins := func(expected int) error {
		b, e := admin("status")
		if e != nil {
			return e
		}
		var status firecracker.CatalogStatus
		if e = strictjson.Decode(b, &status); e != nil {
			return e
		}
		for _, item := range status.Items {
			if item.ID == template {
				if item.Pins != expected {
					return errors.New("catalog pin count mismatch")
				}
				return nil
			}
		}
		return errors.New("owned template missing")
	}
	gc := func(expected int) error {
		b, e := admin("gc")
		if e != nil {
			return e
		}
		var out struct {
			Removed []string `json:"removed"`
		}
		if e = strictjson.Decode(b, &out); e != nil {
			return e
		}
		if len(out.Removed) != expected || (expected == 1 && out.Removed[0] != template) {
			return errors.New("pinned catalog GC result mismatch")
		}
		return nil
	}
	if e := pins(2); e != nil {
		return nil, e
	}
	if _, e := admin("retire", template); e != nil {
		return nil, e
	}
	if e := gc(0); e != nil {
		return nil, e
	}
	if e := n.destroy(ctx, clones[0].Ref); e != nil {
		return nil, e
	}
	if e := n.clean(clones[0].Ref); e != nil {
		return nil, e
	}
	r, e := driverQuotaRead(projects[0])
	if e != nil || !quotaEmpty(r) {
		return nil, errors.New("first clone project not cleared")
	}
	if e = pins(1); e != nil {
		return nil, e
	}
	if e = gc(0); e != nil {
		return nil, e
	}
	if e = actualNestedVM(clones[1].Ref); e != nil {
		return nil, e
	}
	out, e := n.execute(ctx, clones[1].Ref, []string{"cat", "quota-marker"})
	if e != nil || out.Stdout != "quota-b" {
		return nil, errors.New("surviving clone data/execution changed")
	}
	if e = verifySharedQuotaFiles(roots[1]); e != nil {
		return nil, e
	}
	if e = n.destroy(ctx, clones[1].Ref); e != nil {
		return nil, e
	}
	if e = n.clean(clones[1].Ref); e != nil {
		return nil, e
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	if e = gc(1); e != nil {
		return nil, e
	}
	// Publish a NEW declaration of the same NEVER-assigned creator export.
	// The retired ID stays retired; no assigned clone becomes a new template.
	b, e := os.ReadFile("/srv/export/manifest.json")
	if e != nil {
		return nil, e
	}
	var m firecracker.SnapshotManifest
	if e = strictjson.Decode(b, &m); e != nil {
		return nil, e
	}
	m.CreatedAt = time.Now().UTC()
	if e = privateWrite("/srv/fixture/snapshot-republish-manifest.json", m); e != nil {
		return nil, e
	}
	b, e = admin("-manifest", "/srv/fixture/snapshot-republish-manifest.json", "-memory", "/srv/export/memory", "-snapshot-state", "/srv/export/state", "publish")
	if e != nil {
		return nil, e
	}
	var next struct {
		ID string `json:"template_id"`
	}
	if e = strictjson.Decode(b, &next); e != nil {
		return nil, e
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(next.ID) || next.ID == template {
		return nil, errors.New("retired template identity reused")
	}
	if _, e = admin("activate", next.ID); e != nil {
		return nil, e
	}
	return map[string]any{"simultaneous_ordinary_clones": 2, "private_projects_distinct": true, "shared_readonly_project_zero_inodes": true, "per_clone_charge_excludes_shared_inodes": true, "pins_two_then_one_checked": true, "retired_backing_survived_first_clone_gc": true, "surviving_real_vm_data_exec_checked": true, "last_pin_gc_removed_one_template": true, "all_private_project_records_cleared": true, "new_declaration_reuses_only_never_assigned_export": true}, nil
}
