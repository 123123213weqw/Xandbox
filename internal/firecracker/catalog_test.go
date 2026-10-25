package firecracker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

// Unit tests use 1MiB synthetic files and bypass the production Config validator
// (which permits only512MiB/2vCPU). These do NOT represent runnable VM snapshots.
func catalogFixture(t *testing.T) (*registry, SnapshotManifest, string, string) {
	return catalogFixtureQuota(t, nil)
}
func catalogFixtureQuota(t *testing.T, quota *QuotaPolicy) (*registry, SnapshotManifest, string, string) {
	t.Helper()
	base := t.TempDir()
	t.Cleanup(func() {
		// Fixtures are caller-owned synthetic files, not live VMM backing. Restore
		// directory write permission before testing.TempDir's non-root cleanup.
		_ = filepath.WalkDir(base, func(path string, d fs.DirEntry, e error) error {
			if e == nil && d.IsDir() {
				return os.Chmod(path, 0700)
			}
			return e
		})
	})
	cfg := policy()
	cfg.Quota = quota
	cfg.Version = 2
	cfg.RuntimeRoot = filepath.Join(base, "runtime")
	cfg.CgroupRoot = filepath.Join(base, "groups")
	cfg.UIDCount = 64
	cfg.Snapshot = &SnapshotPolicy{Version: 1, AgentSHA256: strings.Repeat("b", 64), MemoryMiB: 1, VCPUs: 2, MaxEntries: 8, MaxBytes: 16 << 20}
	dir := filepath.Join(base, "backend")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	r, e := newRegistry(dir, cfg, nil)
	if e != nil {
		t.Fatal(e)
	}
	r.hostABI = strings.Repeat("c", 64)
	memory, state := filepath.Join(base, "source.memory"), filepath.Join(base, "source.state")
	mem := make([]byte, 1<<20)
	for i := range mem {
		mem[i] = byte(i)
	}
	st := []byte("synthetic-state-not-a-VM")
	if e = os.WriteFile(memory, mem, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(state, st, 0600); e != nil {
		t.Fatal(e)
	}
	digest := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	m := SnapshotManifest{Version: 1, Format: "firecracker-v1.17.0-full", SourceRevision: strings.Repeat("d", 40), CreatedAt: time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC), Assignment: "UNASSIGNED", BootArgs: pristineBootArgs, BootstrapProtocol: 1, AgentSHA256: cfg.Snapshot.AgentSHA256, FirecrackerSHA256: cfg.Firecracker.SHA256, JailerSHA256: cfg.Jailer.SHA256, KernelSHA256: cfg.Kernel.SHA256, InitrdSHA256: cfg.Initrd.SHA256, WorkspaceSHA256: cfg.Workspace.SHA256, HostABI: r.hostABI, MemoryMiB: 1, VCPUs: 2, MemorySHA256: digest(mem), StateSHA256: digest(st), StateBytes: int64(len(st))}
	return r, m, memory, state
}
func publishActive(t *testing.T, r *registry, m SnapshotManifest, memory, state string) string {
	t.Helper()
	id, e := r.catalog.publish(context.Background(), m, memory, state, r.hostABI)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.catalog.activate(context.Background(), id, r.hostABI); e != nil {
		t.Fatal(e)
	}
	return id
}
func TestCatalogPinsRecoverAndRetirementCannotDeleteSharedBacking(t *testing.T) {
	r, m, mem, st := catalogFixture(t)
	id := publishActive(t, r, m, mem, st)
	a, e := r.reserve(reference("1"))
	if e != nil {
		t.Fatal(e)
	}
	b, e := r.reserve(reference("2"))
	if e != nil {
		t.Fatal(e)
	}
	if a.TemplateID != id || a.Version != 2 || b.TemplateID != id {
		t.Fatal("owner not pinned")
	}
	if e = r.catalog.retire(context.Background(), id); e != nil {
		t.Fatal(e)
	}
	if _, e = r.reserve(reference("3")); e == nil {
		t.Fatal("retired template admitted new owner")
	}
	if removed, e := r.catalog.collect(context.Background()); e != nil || len(removed) != 0 {
		t.Fatal("pinned memory removed", e, removed)
	}
	// No in-memory count survives this reconstruction. Ownership files do.
	recovered, e := newRegistry(r.dir, r.cfg, []sandbox.Record{ledger(a.Ref), ledger(b.Ref)})
	if e != nil {
		t.Fatal(e)
	}
	recovered.hostABI = r.hostABI
	status, e := recovered.catalog.status(context.Background())
	if e != nil || len(status.Items) != 1 || status.Items[0].Pins != 2 {
		t.Fatal("pins lost on restart", e, status)
	}
	ka, _ := key(a.Ref)
	kb, _ := key(b.Ref)
	if e = recovered.release(ka); e != nil {
		t.Fatal(e)
	}
	if removed, e := recovered.catalog.collect(context.Background()); e != nil || len(removed) != 0 {
		t.Fatal("last live pin ignored", e)
	}
	if e = recovered.release(kb); e != nil {
		t.Fatal(e)
	}
	if removed, e := recovered.catalog.collect(context.Background()); e != nil || len(removed) != 1 {
		t.Fatal("unreferenced retired template not collected", e, removed)
	}
	if _, e = os.Lstat(recovered.catalog.object(id)); !os.IsNotExist(e) {
		t.Fatal("backing remains")
	}
	if e = recovered.catalog.activate(context.Background(), id, r.hostABI); e == nil {
		t.Fatal("retired identity resurrected")
	}
	if _, e = recovered.catalog.publish(context.Background(), m, mem, st, r.hostABI); e == nil {
		t.Fatal("retired identity republished")
	}
}
func TestCatalogPinFsyncBlocksRetirementButNeverOwnershipReaders(t *testing.T) {
	r, m, mem, st := catalogFixture(t)
	id := publishActive(t, r, m, mem, st)
	persist := r.persist
	entered, release := make(chan struct{}), make(chan struct{})
	r.persist = func(path string, v any) error { close(entered); <-release; return persist(path, v) }
	done := make(chan error, 1)
	go func() { _, e := r.reserve(reference("1")); done <- e }()
	<-entered
	k, _ := key(reference("1"))
	reader := make(chan bool, 1)
	go func() { reader <- r.owns(k) }()
	select {
	case yes := <-reader:
		if !yes {
			t.Fatal("reservation not visible")
		}
	case <-time.After(time.Second):
		t.Fatal("Stop ownership reader blocked behind fsync")
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if e := r.catalog.retire(context.Background(), id); e != nil {
		t.Fatal(e)
	}
}
func TestCatalogRetirementSerializesWithPinAcrossIndependentDescriptors(t *testing.T) {
	r, m, mem, st := catalogFixture(t)
	id := publishActive(t, r, m, mem, st)
	admin, e := openCatalog(r.dir, r.cfg, false)
	if e != nil {
		t.Fatal(e)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	persist := r.persist
	r.persist = func(p string, v any) error { close(entered); <-release; return persist(p, v) }
	pin := make(chan error, 1)
	go func() { _, e := r.reserve(reference("1")); pin <- e }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if e = admin.retire(ctx, id); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("retirement bypassed pending durable acquisition", e)
	}
	close(release)
	if e = <-pin; e != nil {
		t.Fatal(e)
	}
	if e = admin.retire(context.Background(), id); e != nil {
		t.Fatal(e)
	}
	if removed, e := admin.collect(context.Background()); e != nil || len(removed) != 0 {
		t.Fatal("retire/GC raced ahead of durable pin", e, removed)
	}
}
func TestCatalogLostOwnershipOrUnknownResourceNeverLooksUnreferenced(t *testing.T) {
	for _, mode := range []string{"lost-owner", "corrupt-owner", "unknown-jail", "lost-index", "retired-with-pin"} {
		t.Run(mode, func(t *testing.T) {
			r, m, mem, st := catalogFixture(t)
			id := publishActive(t, r, m, mem, st)
			o, e := r.reserve(reference("1"))
			if e != nil {
				t.Fatal(e)
			}
			k, _ := key(o.Ref)
			path := filepath.Join(r.cfg.RuntimeRoot, "j/firecracker", k)
			if e = os.MkdirAll(path, 0700); e != nil {
				t.Fatal(e)
			}
			if e = r.catalog.retire(context.Background(), id); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "lost-owner":
				e = os.Remove(filepath.Join(r.dir, k+".json"))
			case "corrupt-owner":
				e = os.WriteFile(filepath.Join(r.dir, k+".json"), []byte("broken"), 0600)
			case "unknown-jail":
				e = os.Mkdir(filepath.Join(filepath.Dir(path), strings.Repeat("a", 64)), 0700)
			case "lost-index":
				e = os.Remove(filepath.Join(r.catalog.root, "index.json"))
			case "retired-with-pin":
				d, err := r.catalog.readIndex()
				if err != nil {
					t.Fatal(err)
				}
				v := d.Entries[id]
				v.Phase = templateRetired
				d.Entries[id] = v
				e = r.catalog.saveIndex(d)
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = r.catalog.collect(context.Background()); e == nil {
				t.Fatal("uncertain ownership allowed GC")
			}
			if _, e = os.Stat(filepath.Join(r.catalog.object(id), "memory")); e != nil {
				t.Fatal("shared backing was deleted", e)
			}
		})
	}
}
func TestCatalogInitializationAttemptDurableAndNeverReplayed(t *testing.T) {
	r, m, mem, st := catalogFixture(t)
	publishActive(t, r, m, mem, st)
	o, e := r.reserve(reference("1"))
	if e != nil {
		t.Fatal(e)
	}
	k, _ := key(o.Ref)
	if e = r.markInitialization(context.Background(), k); e != nil {
		t.Fatal(e)
	}
	recovered, e := newRegistry(r.dir, r.cfg, []sandbox.Record{ledger(o.Ref)})
	if e != nil {
		t.Fatal(e)
	}
	if !recovered.owners[k].InitializationAttempted {
		t.Fatal("attempt fence not durable")
	}
	if e = recovered.markInitialization(context.Background(), k); e == nil {
		t.Fatal("initialization attempt replayed")
	}
	recovered.hostABI = r.hostABI
	if _, e = recovered.reserve(o.Ref); e == nil {
		t.Fatal("same Ref reused after controller crash")
	}
}
func TestCatalogPartialPublicationAndInterruptedDeletionReconcile(t *testing.T) {
	r, m, mem, st := catalogFixture(t)
	wrong := m
	wrong.MemorySHA256 = strings.Repeat("0", 64)
	if _, e := r.catalog.publish(context.Background(), wrong, mem, st, r.hostABI); e == nil {
		t.Fatal("bad source admitted")
	}
	if removed, e := r.catalog.collect(context.Background()); e != nil || len(removed) != 1 {
		t.Fatal("partial stage not accounted/collected", e, removed)
	}
	id := publishActive(t, r, m, mem, st)
	if e := r.catalog.retire(context.Background(), id); e != nil {
		t.Fatal(e)
	}
	persist := r.catalog.persist
	r.catalog.persist = func(p string, v any) error { return errors.New("injected post-unlink index barrier") }
	if _, e := r.catalog.collect(context.Background()); e == nil {
		t.Fatal("failure hidden")
	}
	r.catalog.persist = persist
	// Backing deletion was already durable; a new instance must finish metadata.
	c, e := openCatalog(r.dir, r.cfg, false)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.collect(context.Background()); e != nil {
		t.Fatal(e)
	}
	s, e := c.status(context.Background())
	if e != nil || s.Items[0].Phase != templateRetired {
		t.Fatal("interrupted retirement not recovered", e, s)
	}
}
func TestCatalogConcurrentPinRetireAndPolicyBoundaries(t *testing.T) {
	r, m, mem, st := catalogFixture(t)
	id := publishActive(t, r, m, mem, st)
	var wg sync.WaitGroup
	for n := range 32 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ref := sandbox.Ref{ID: fmt.Sprintf("%032x", n+1), Generation: strings.Repeat("f", 32)}
			_, _ = r.reserve(ref)
		}(n)
	}
	wg.Add(1)
	go func() { defer wg.Done(); _ = r.catalog.retire(context.Background(), id) }()
	wg.Wait()
	status, e := r.catalog.status(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	for _, x := range status.Items {
		if x.Pins != len(r.owners) {
			t.Fatal("durable pin count mismatch")
		}
	}
	if _, e = r.catalog.collect(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(r.owners) > 0 {
		if _, e = os.Stat(filepath.Join(r.catalog.object(id), "memory")); e != nil {
			t.Fatal("live shared file disappeared")
		}
	}
}
func TestSnapshotModeIsExplicitAndColdBindingUnchanged(t *testing.T) {
	c := policy()
	if e := c.validate(); e != nil {
		t.Fatal(e)
	}
	c.Snapshot = &SnapshotPolicy{Version: 1, AgentSHA256: strings.Repeat("a", 64), MemoryMiB: 512, VCPUs: 2, MaxEntries: 2, MaxBytes: 2 << 30}
	if e := c.validate(); e == nil {
		t.Fatal("snapshot silently enabled in schema1")
	}
	c.Version = 2
	if e := c.validate(); e != nil {
		t.Fatal(e)
	}
	c.Snapshot.MemoryMiB = 1
	if e := c.validate(); e == nil {
		t.Fatal("production geometry changed by unit fixture policy")
	}
}

func TestCatalogDetectsBackingWhoseTypedPinWasChanged(t *testing.T) {
	r, m, mem, st := catalogFixture(t)
	a := publishActive(t, r, m, mem, st)
	o, e := r.reserve(reference("1"))
	if e != nil {
		t.Fatal(e)
	}
	other := m
	other.CreatedAt = other.CreatedAt.Add(time.Second)
	b, e := r.catalog.publish(context.Background(), other, mem, st, r.hostABI)
	if e != nil {
		t.Fatal(e)
	}
	k, _ := key(o.Ref)
	root := filepath.Join(r.cfg.RuntimeRoot, "j/firecracker", k, "root")
	if e = os.MkdirAll(root, 0700); e != nil {
		t.Fatal(e)
	}
	// A valid-looking but wrong owner digest must not hide a different actual
	// memory inode. Both templates are untrusted for GC until reconciled.
	if e = os.Link(filepath.Join(r.catalog.object(b), "memory"), filepath.Join(root, "template.mem")); e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{a, b} {
		if e = r.catalog.retire(context.Background(), id); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = r.catalog.collect(context.Background()); e == nil {
		t.Fatal("inconsistent typed pin allowed shared GC")
	}
	if _, e = os.Stat(filepath.Join(r.catalog.object(b), "memory")); e != nil {
		t.Fatal("actual backing deleted", e)
	}
}
func TestCatalogRejectsABIImageAndMutableBackingMismatch(t *testing.T) {
	for _, mode := range []string{"abi", "agent", "geometry", "dirty-declaration", "tamper", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			r, m, mem, st := catalogFixture(t)
			switch mode {
			case "abi":
				m.HostABI = strings.Repeat("1", 64)
			case "agent":
				m.AgentSHA256 = strings.Repeat("1", 64)
			case "geometry":
				m.MemoryMiB = 2
			case "dirty-declaration":
				m.Assignment = "ASSIGNED"
			}
			id, e := r.catalog.publish(context.Background(), m, mem, st, r.hostABI)
			if mode != "tamper" && mode != "symlink" {
				if e == nil {
					t.Fatal("invalid template accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			p := filepath.Join(r.catalog.object(id), "memory")
			if mode == "tamper" {
				if e = os.Chmod(p, 0644); e != nil {
					t.Fatal(e)
				}
			} else {
				if e = os.Chmod(r.catalog.object(id), 0755); e != nil {
					t.Fatal(e)
				}
				if e = os.Remove(p); e != nil {
					t.Fatal(e)
				}
				if e = os.Symlink(mem, p); e != nil {
					t.Fatal(e)
				}
				if e = os.Chmod(r.catalog.object(id), 0555); e != nil {
					t.Fatal(e)
				}
			}
			if e = r.catalog.activate(context.Background(), id, r.hostABI); e == nil {
				t.Fatal("mutable/symlink backing activated")
			}
		})
	}
}

func TestCatalogOpenHonorsLockCancellation(t *testing.T) {
	r, _, _, _ := catalogFixture(t)
	unlock, e := catalogLock(context.Background(), filepath.Join(r.catalog.root, ".lock"))
	if e != nil {
		t.Fatal(e)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, e = openCatalogContext(ctx, r.dir, r.cfg, false); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("catalog constructor ignored admin deadline", e)
	}
}

func TestCatalogGCRequiresDurableOwnerDeletionBarrier(t *testing.T) {
	r, m, mem, state := catalogFixture(t)
	id := publishActive(t, r, m, mem, state)
	o, e := r.reserve(reference("1"))
	if e != nil {
		t.Fatal(e)
	}
	k, _ := key(o.Ref)
	if e = r.catalog.retire(context.Background(), id); e != nil {
		t.Fatal(e)
	}
	fsyncFailure := func(path string) error {
		if path == r.dir {
			return errors.New("injected ownership directory fsync failure")
		}
		return syncDir(path)
	}
	r.syncDirectory = fsyncFailure
	r.catalog.syncDirectory = fsyncFailure
	if e = r.release(k); e == nil {
		t.Fatal("ownership unlink uncertainty ignored")
	}
	if !r.owns(k) {
		t.Fatal("reservation released despite failed barrier")
	}
	if _, e = r.catalog.collect(context.Background()); e == nil {
		t.Fatal("GC treated unconfirmed ownership unlink as durable absence")
	}
	if _, e = os.Stat(filepath.Join(r.catalog.object(id), "memory")); e != nil {
		t.Fatal("shared backing deleted before ownership barrier", e)
	}
	r.catalog.syncDirectory = syncDir
	r.syncDirectory = syncDir
	// A successful later barrier can safely resolve the previous uncertain unlink.
	if _, e = r.catalog.collect(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = r.release(k); e != nil {
		t.Fatal(e)
	}
}

func TestEmptySnapshotCatalogCannotFallBackToColdAllocation(t *testing.T) {
	r, _, _, _ := catalogFixture(t)
	if _, e := r.reserve(reference("1")); e == nil {
		t.Fatal("empty catalog silently allocated an owner")
	}
	if len(r.owners) != 0 {
		t.Fatal("empty catalog created ownership")
	}
	status, e := r.catalog.status(context.Background())
	if e != nil || status.Active != "" || len(status.Items) != 0 {
		t.Fatal("unexpected empty catalog state", e, status)
	}
}

func TestCatalogSealsFinalPathBeforeAvailabilityCommit(t *testing.T) {
	r, m, mem, state := catalogFixture(t)
	id := m.ID()
	persist := r.catalog.persist
	checked := false
	r.catalog.persist = func(path string, value any) error {
		d, ok := value.(catalogIndex)
		if !ok {
			t.Fatal("unexpected catalog persistence type")
		}
		if d.Entries[id].Phase == templateAvailable {
			checked = true
			i, e := os.Stat(r.catalog.object(id))
			if e != nil || i.Mode().Perm() != 0555 {
				t.Fatal("unsealed object became available", e)
			}
			for _, name := range []string{"memory", "state", "manifest.json"} {
				i, e = os.Stat(filepath.Join(r.catalog.object(id), name))
				if e != nil || i.Mode().Perm() != 0444 {
					t.Fatal("unsealed file became available", name, e)
				}
			}
		}
		return persist(path, value)
	}
	if _, e := r.catalog.publish(context.Background(), m, mem, state, r.hostABI); e != nil {
		t.Fatal(e)
	}
	if !checked {
		t.Fatal("availability commit was not checked")
	}
}
