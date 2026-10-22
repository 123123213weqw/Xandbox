package firecracker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

const (
	templateAvailable = "AVAILABLE"
	templateRetiring  = "RETIRING"
	templateRetired   = "RETIRED"
	catalogIndexMax   = 256 << 10
)

type catalogEntry struct {
	Phase string `json:"phase"`
	Bytes int64  `json:"bytes"`
}
type catalogIndex struct {
	Version        int                     `json:"version"`
	ConfigSHA256   string                  `json:"config_sha256"`
	RegistrySHA256 string                  `json:"registry_sha256"`
	Active         string                  `json:"active,omitempty"`
	Entries        map[string]catalogEntry `json:"entries"`
}
type verifiedCatalogFile struct {
	info   os.FileInfo
	digest string
}

// The catalog lock serializes publication/retirement with durable ownership
// acquisition/release. Stop never acquires it. There is no volatile refcount:
// generation ownership files are the sole pin authority, including on restart.
type catalog struct {
	root, backend string
	cfg           Config
	persist       func(string, any) error
	syncDirectory func(string) error
	cacheMu       sync.Mutex
	verified      map[string]verifiedCatalogFile
}
type CatalogItem struct {
	ID    string `json:"id"`
	Phase string `json:"phase"`
	Pins  int    `json:"pins"`
	Bytes int64  `json:"bytes"`
}
type CatalogStatus struct {
	Active      string        `json:"active,omitempty"`
	Items       []CatalogItem `json:"items"`
	StoredBytes int64         `json:"stored_bytes"`
}

func openCatalog(backend string, cfg Config, initialize bool) (*catalog, error) {
	return openCatalogContext(context.Background(), backend, cfg, initialize)
}
func openCatalogContext(ctx context.Context, backend string, cfg Config, initialize bool) (*catalog, error) {
	if cfg.Snapshot == nil {
		return nil, errors.New("snapshot policy required")
	}
	c := &catalog{root: filepath.Join(backend, "catalog"), backend: backend, cfg: cfg, persist: durableJSON, syncDirectory: syncDir, verified: make(map[string]verifiedCatalogFile)}
	if _, e := os.Lstat(c.root); os.IsNotExist(e) && initialize {
		if e = os.Mkdir(c.root, 0700); e != nil {
			return nil, e
		}
		if e = c.syncDirectory(backend); e != nil {
			return nil, e
		}
	}
	if e := c.checkRoot(); e != nil {
		return nil, e
	}
	e := c.withLock(ctx, func() error {
		_, e := os.Lstat(filepath.Join(c.root, "index.json"))
		if !os.IsNotExist(e) {
			if e != nil {
				return e
			}
			_, e = c.readIndex()
			return e
		}
		if !initialize {
			return errors.New("snapshot catalog index missing")
		}
		owners, e := c.scanOwners()
		if e != nil || len(owners) != 0 {
			return errors.New("cannot initialize catalog with existing ownership")
		}
		entries, e := os.ReadDir(c.root)
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if entry.Name() != ".lock" && entry.Name() != "objects" {
				return errors.New("missing catalog index in nonempty catalog")
			}
		}
		objects := filepath.Join(c.root, "objects")
		if e = os.Mkdir(objects, 0700); e != nil && !os.IsExist(e) {
			return e
		}
		if e = c.checkObjects(); e != nil {
			return e
		}
		entries, e = os.ReadDir(objects)
		if e != nil || len(entries) != 0 {
			return errors.New("missing index cannot adopt snapshot objects")
		}
		if e = c.syncDirectory(objects); e != nil {
			return e
		}
		return c.saveIndex(catalogIndex{Version: 1, ConfigSHA256: configDigest(cfg), RegistrySHA256: registryDigest(backend), Entries: map[string]catalogEntry{}})
	})
	return c, e
}
func registryDigest(path string) string {
	s := sha256.Sum256([]byte(path))
	return hex.EncodeToString(s[:])
}
func (c *catalog) checkRoot() error {
	i, e := os.Lstat(c.root)
	if e != nil {
		return e
	}
	if !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm() != 0700 || !catalogOwned(i) {
		return errors.New("catalog root must be owned private directory")
	}
	_, e = privatefile.EnsureDirectory(c.root)
	return e
}
func (c *catalog) checkObjects() error {
	p := filepath.Join(c.root, "objects")
	i, e := os.Lstat(p)
	if e != nil {
		return e
	}
	if !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm() != 0700 || !catalogOwned(i) {
		return errors.New("invalid catalog objects directory")
	}
	return nil
}
func (c *catalog) withLock(ctx context.Context, fn func() error) error {
	if e := c.checkRoot(); e != nil {
		return e
	}
	unlock, e := catalogLock(ctx, filepath.Join(c.root, ".lock"))
	if e != nil {
		return e
	}
	defer unlock()
	if e = ctx.Err(); e != nil {
		return e
	}
	return fn()
}
func (c *catalog) readIndex() (catalogIndex, error) {
	var d catalogIndex
	// Resolve a prior rename whose caller could not confirm directory fsync.
	if e := c.syncDirectory(c.root); e != nil {
		return d, e
	}
	b, e := privatefile.Read(filepath.Join(c.root, "index.json"), catalogIndexMax)
	if e != nil {
		return d, e
	}
	if e = strictjson.Decode(b, &d); e != nil {
		return d, e
	}
	if d.Version != 1 || d.ConfigSHA256 != configDigest(c.cfg) || d.RegistrySHA256 != registryDigest(c.backend) || d.Entries == nil || len(d.Entries) > c.cfg.Snapshot.MaxEntries {
		return d, errors.New("invalid catalog index or node binding")
	}
	var liveBytes int64
	for id, v := range d.Entries {
		if !hex64.MatchString(id) || v.Bytes < 1 || v.Bytes > c.cfg.Snapshot.MaxBytes || (v.Phase != templateAvailable && v.Phase != templateRetiring && v.Phase != templateRetired) {
			return d, errors.New("invalid catalog entry")
		}
		if v.Phase != templateRetired {
			liveBytes += v.Bytes
		}
	}
	if liveBytes > c.cfg.Snapshot.MaxBytes || (d.Active != "" && d.Entries[d.Active].Phase != templateAvailable) {
		return d, errors.New("invalid active template or catalog budget")
	}
	if e = c.checkObjects(); e != nil {
		return d, e
	}
	return d, nil
}
func (c *catalog) saveIndex(d catalogIndex) error {
	return c.persist(filepath.Join(c.root, "index.json"), d)
}
func (c *catalog) object(id string) string { return filepath.Join(c.root, "objects", id) }
func (c *catalog) scanOwners() (map[string]ownership, error) {
	// Resolve visible-but-unconfirmed owner rename/unlink before treating the
	// disk namespace as pin authority. Otherwise GC could outlive a failed fsync.
	if e := c.syncDirectory(c.backend); e != nil {
		return nil, e
	}
	es, e := os.ReadDir(c.backend)
	if e != nil {
		return nil, e
	}
	out := map[string]ownership{}
	uids := map[int]bool{}
	for _, f := range es {
		if f.Name() == "config.json" || f.Name() == "catalog" || strings.HasPrefix(f.Name(), ".atomic-") {
			continue
		}
		if !f.Type().IsRegular() {
			return nil, errors.New("unknown ownership resource")
		}
		b, e := privatefile.Read(filepath.Join(c.backend, f.Name()), 2048)
		if e != nil {
			return nil, e
		}
		var o ownership
		if e = strictjson.Decode(b, &o); e != nil {
			return nil, e
		}
		k, e := key(o.Ref)
		if e != nil || f.Name() != k+".json" || !validOwnership(o, c.cfg) || uids[o.UID] {
			return nil, errors.New("invalid catalog ownership authority")
		}
		uids[o.UID] = true
		out[k] = o
	}
	return out, nil
}
func (c *catalog) pins(d catalogIndex, owners map[string]ownership) (map[string]int, error) {
	refs := map[string]int{}
	for _, o := range owners {
		v, ok := d.Entries[o.TemplateID]
		if !ok || v.Phase == templateRetired {
			return nil, errors.New("ownership references missing or retired template")
		}
		refs[o.TemplateID]++
	}
	return refs, nil
}

// Namespace reconciliation is essential: a lost ownership file must not make a
// live or partially prepared jail's shared backing appear unreferenced.
func (c *catalog) checkResources(owners map[string]ownership) error {
	for _, p := range []string{c.cfg.CgroupRoot, filepath.Join(c.cfg.RuntimeRoot, "j/firecracker")} {
		es, e := os.ReadDir(p)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		for _, f := range es {
			jail := p != c.cfg.CgroupRoot
			if !jail && !f.IsDir() {
				continue
			}
			if !f.IsDir() || f.Type()&os.ModeSymlink != 0 {
				return errors.New("unknown backend namespace entry")
			}
			o, ok := owners[f.Name()]
			if !ok {
				return errors.New("unowned backend resource prevents catalog retirement")
			}
			if jail {
				for _, name := range []string{"memory", "state"} {
					file := "template.mem"
					if name == "state" {
						file = "template.state"
					}
					local := filepath.Join(p, f.Name(), "root", file)
					li, err := os.Lstat(local)
					if os.IsNotExist(err) {
						continue
					}
					if err != nil {
						return err
					}
					shared, err := os.Lstat(filepath.Join(c.object(o.TemplateID), name))
					if err != nil || !li.Mode().IsRegular() || !os.SameFile(li, shared) {
						return errors.New("private backing does not match durable template pin")
					}
				}
			}
		}
	}
	return nil
}
func immutableFile(path string, size int64) (*os.File, os.FileInfo, error) {
	before, e := os.Lstat(path)
	if e != nil {
		return nil, nil, e
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0444 || !catalogOwned(before) || before.Size() != size {
		return nil, nil, errors.New("snapshot backing must be owned read-only regular file with exact size")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, nil, e
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) {
		f.Close()
		return nil, nil, errors.New("snapshot backing changed during open")
	}
	return f, after, nil
}
func (c *catalog) verifyFile(ctx context.Context, path, digest string, size int64) error {
	f, info, e := immutableFile(path, size)
	if e != nil {
		return e
	}
	defer f.Close()
	c.cacheMu.Lock()
	old, ok := c.verified[path]
	c.cacheMu.Unlock()
	if ok && old.digest == digest && os.SameFile(old.info, info) && old.info.Size() == info.Size() && old.info.ModTime().Equal(info.ModTime()) {
		return nil
	}
	h := sha256.New()
	buf := make([]byte, 128<<10)
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) || hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("snapshot backing digest/identity changed")
	}
	// Link/unlink changes ctime, not contents or mtime. Never retain seed/VM state
	// in this cache; only immutable file identity, expected digest and stat data.
	c.cacheMu.Lock()
	c.verified[path] = verifiedCatalogFile{info: after, digest: digest}
	c.cacheMu.Unlock()
	return nil
}
func (c *catalog) loadTemplate(ctx context.Context, id string) (SnapshotManifest, error) {
	var m SnapshotManifest
	p := c.object(id)
	di, e := os.Lstat(p)
	if e != nil {
		return m, e
	}
	if !di.IsDir() || di.Mode().Perm() != 0555 || !catalogOwned(di) {
		return m, errors.New("snapshot object directory is not sealed")
	}
	mi, e := os.Lstat(filepath.Join(p, "manifest.json"))
	if e != nil {
		return m, e
	}
	if mi.Size() < 1 || mi.Size() > 8192 {
		return m, errors.New("invalid manifest size")
	}
	f, _, e := immutableFile(filepath.Join(p, "manifest.json"), mi.Size())
	if e != nil {
		return m, e
	}
	b, e := io.ReadAll(io.LimitReader(f, 8193))
	f.Close()
	if e != nil {
		return m, e
	}
	if e = strictjson.Decode(b, &m); e != nil {
		return m, e
	}
	if e = m.validate(c.cfg); e != nil {
		return m, e
	}
	if m.ID() != id {
		return m, errors.New("snapshot manifest identity mismatch")
	}
	es, e := os.ReadDir(p)
	if e != nil {
		return m, e
	}
	if len(es) != 3 {
		return m, errors.New("unexpected snapshot object contents")
	}
	for _, x := range es {
		if x.Name() != "memory" && x.Name() != "state" && x.Name() != "manifest.json" {
			return m, errors.New("unknown snapshot object file")
		}
	}
	if e = c.verifyFile(ctx, filepath.Join(p, "memory"), m.MemorySHA256, int64(m.MemoryMiB)<<20); e != nil {
		return m, e
	}
	if e = c.verifyFile(ctx, filepath.Join(p, "state"), m.StateSHA256, m.StateBytes); e != nil {
		return m, e
	}
	return m, nil
}

// acquire invokes persistOwner under the same interprocess lock as retirement.
// The owner must be durable BEFORE staging links, loading or resuming any VMM.
func (c *catalog) acquire(ctx context.Context, hostABI string, persistOwner func(string) error) (SnapshotManifest, error) {
	var m SnapshotManifest
	e := c.withLock(ctx, func() error {
		d, e := c.readIndex()
		if e != nil {
			return e
		}
		if d.Active == "" {
			return errors.New("no active pristine snapshot; cold fallback is forbidden")
		}
		m, e = c.loadTemplate(ctx, d.Active)
		if e != nil {
			return e
		}
		if m.bytes() != d.Entries[d.Active].Bytes {
			return errors.New("catalog accounting differs from manifest")
		}
		if m.HostABI != hostABI {
			return errors.New("snapshot host ABI does not match current node")
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		return persistOwner(d.Active)
	})
	return m, e
}
func (c *catalog) validatePins(ctx context.Context) error {
	return c.withLock(ctx, func() error {
		d, e := c.readIndex()
		if e != nil {
			return e
		}
		owners, e := c.scanOwners()
		if e != nil {
			return e
		}
		refs, e := c.pins(d, owners)
		if e != nil {
			return e
		}
		if e = c.checkResources(owners); e != nil {
			return e
		}
		for id := range refs {
			m, err := c.loadTemplate(ctx, id)
			if err != nil {
				return err
			}
			if m.bytes() != d.Entries[id].Bytes {
				return errors.New("catalog pin accounting differs from manifest")
			}
		}
		return nil
	})
}
func (c *catalog) linkOwned(ctx context.Context, o ownership, root string) error {
	if o.TemplateID == "" {
		return errors.New("missing durable template ownership")
	}
	// An already acquired pin may finish preparing after retirement starts. GC
	// cannot delete this object until stopped private links and owner are durable.
	if _, e := c.loadTemplate(ctx, o.TemplateID); e != nil {
		return e
	}
	for source, dest := range map[string]string{"memory": "template.mem", "state": "template.state"} {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := os.Link(filepath.Join(c.object(o.TemplateID), source), filepath.Join(root, dest)); e != nil {
			return fmt.Errorf("snapshot hardlink (same filesystem required; no copy fallback): %w", e)
		}
	}
	return nil
}
func (c *catalog) storedBytes() (int64, error) {
	es, e := os.ReadDir(filepath.Join(c.root, "objects"))
	if e != nil {
		return 0, e
	}
	if len(es) > c.cfg.Snapshot.MaxEntries*2+8 {
		return 0, errors.New("catalog object-count ceiling reached; reconcile first")
	}
	var n int64
	for _, d := range es {
		if !d.IsDir() || d.Type()&os.ModeSymlink != 0 || (!hex64.MatchString(d.Name()) && !stageName(d.Name())) {
			return 0, errors.New("unknown catalog object")
		}
		ds, e := os.Lstat(filepath.Join(c.root, "objects", d.Name()))
		if e != nil || !catalogOwned(ds) {
			return 0, errors.New("unowned catalog object")
		}
		fs, e := os.ReadDir(filepath.Join(c.root, "objects", d.Name()))
		if e != nil {
			return 0, e
		}
		if len(fs) > 3 {
			return 0, errors.New("unknown catalog files")
		}
		for _, f := range fs {
			i, e := os.Lstat(filepath.Join(c.root, "objects", d.Name(), f.Name()))
			if e != nil {
				return 0, e
			}
			if !i.Mode().IsRegular() || !catalogOwned(i) || (f.Name() != "memory" && f.Name() != "state" && f.Name() != "manifest.json") {
				return 0, errors.New("unknown catalog file")
			}
			if i.Size() < 0 || i.Size() > c.cfg.Snapshot.MaxBytes-n {
				return n, errors.New("catalog storage budget exceeded")
			}
			n += i.Size()
			if n > c.cfg.Snapshot.MaxBytes {
				return n, errors.New("catalog storage budget exceeded")
			}
		}
	}
	return n, nil
}
func stageName(s string) bool {
	return strings.HasPrefix(s, ".stage-") && hex32.MatchString(strings.TrimPrefix(s, ".stage-"))
}
func copySnapshot(ctx context.Context, from, to, digest string, size int64) error {
	// Operator paths are independently ancestry-validated by the Linux CLI.
	in, e := os.Open(from)
	if e != nil {
		return e
	}
	defer in.Close()
	i, e := in.Stat()
	if e != nil || !i.Mode().IsRegular() || i.Size() != size {
		return errors.New("invalid snapshot source file size")
	}
	out, e := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0444)
	if e != nil {
		return e
	}
	defer out.Close()
	h := sha256.New()
	buf := make([]byte, 128<<10)
	var written int64
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		n, err := in.Read(buf)
		if n > 0 {
			written += int64(n)
			if written > size {
				return errors.New("snapshot source grew during publication")
			}
			if _, e = io.MultiWriter(out, h).Write(buf[:n]); e != nil {
				return e
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if written != size || hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("snapshot source digest mismatch")
	}
	if e = out.Sync(); e != nil {
		return e
	}
	return out.Close()
}
func (c *catalog) publish(ctx context.Context, m SnapshotManifest, memory, state, hostABI string) (string, error) {
	if e := m.validate(c.cfg); e != nil {
		return "", e
	}
	if m.HostABI != hostABI {
		return "", errors.New("builder manifest host ABI mismatch")
	}
	id := m.ID()
	e := c.withLock(ctx, func() error {
		d, e := c.readIndex()
		if e != nil {
			return e
		}
		if _, ok := d.Entries[id]; ok {
			return errors.New("template identity already exists, including retired tombstone")
		}
		if len(d.Entries) >= c.cfg.Snapshot.MaxEntries {
			return errors.New("catalog retained-entry budget reached")
		}
		used, e := c.storedBytes()
		if e != nil {
			return e
		}
		if used+m.bytes() > c.cfg.Snapshot.MaxBytes {
			return errors.New("catalog storage budget reached")
		}
		token, e := newCatalogToken()
		if e != nil {
			return e
		}
		stage := filepath.Join(c.root, "objects", ".stage-"+token)
		if e = os.Mkdir(stage, 0700); e != nil {
			return e
		}
		// Leave partial objects on failure: explicit GC accounts/reconciles them
		// under the same authority, rather than hiding uncertain publication work.
		if e = copySnapshot(ctx, memory, filepath.Join(stage, "memory"), m.MemorySHA256, int64(m.MemoryMiB)<<20); e != nil {
			return e
		}
		if e = copySnapshot(ctx, state, filepath.Join(stage, "state"), m.StateSHA256, m.StateBytes); e != nil {
			return e
		}
		b, _ := json.Marshal(m)
		f, e := os.OpenFile(filepath.Join(stage, "manifest.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
		if e != nil {
			return e
		}
		_, e = f.Write(append(b, '\n'))
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		// Some Unix filesystems require a writable source directory for rename.
		// Keep it private and UNPUBLISHED until the final pathname is sealed;
		// no acquire can observe it through the authoritative index yet.
		if e = c.syncDirectory(stage); e != nil {
			return e
		}
		if _, e = os.Lstat(c.object(id)); !os.IsNotExist(e) {
			return errors.New("unindexed snapshot object requires reconciliation")
		}
		if e = os.Rename(stage, c.object(id)); e != nil {
			return e
		}
		if e = os.Chmod(c.object(id), 0555); e != nil {
			return e
		}
		if e = c.syncDirectory(c.object(id)); e != nil {
			return e
		}
		if e = c.syncDirectory(filepath.Join(c.root, "objects")); e != nil {
			return e
		}
		d.Entries[id] = catalogEntry{Phase: templateAvailable, Bytes: m.bytes()}
		return c.saveIndex(d)
	})
	return id, e
}
func (c *catalog) activate(ctx context.Context, id string, hostABI string) error {
	return c.withLock(ctx, func() error {
		d, e := c.readIndex()
		if e != nil {
			return e
		}
		if d.Entries[id].Phase != templateAvailable {
			return errors.New("only available templates can be activated")
		}
		m, e := c.loadTemplate(ctx, id)
		if e != nil {
			return e
		}
		if m.HostABI != hostABI {
			return errors.New("template host ABI mismatch")
		}
		d.Active = id
		return c.saveIndex(d)
	})
}
func (c *catalog) retire(ctx context.Context, id string) error {
	return c.withLock(ctx, func() error {
		d, e := c.readIndex()
		if e != nil {
			return e
		}
		v, ok := d.Entries[id]
		if !ok {
			return errors.New("unknown template")
		}
		if v.Phase == templateRetired {
			return nil
		}
		v.Phase = templateRetiring
		d.Entries[id] = v
		if d.Active == id {
			d.Active = ""
		}
		return c.saveIndex(d)
	})
}
func (c *catalog) status(ctx context.Context) (CatalogStatus, error) {
	var out CatalogStatus
	e := c.withLock(ctx, func() error {
		d, e := c.readIndex()
		if e != nil {
			return e
		}
		owners, e := c.scanOwners()
		if e != nil {
			return e
		}
		pins, e := c.pins(d, owners)
		if e != nil {
			return e
		}
		out.Active = d.Active
		for id, v := range d.Entries {
			out.Items = append(out.Items, CatalogItem{ID: id, Phase: v.Phase, Pins: pins[id], Bytes: v.Bytes})
		}
		sort.Slice(out.Items, func(i, j int) bool { return out.Items[i].ID < out.Items[j].ID })
		out.StoredBytes, e = c.storedBytes()
		return e
	})
	return out, e
}
func (c *catalog) collect(ctx context.Context) ([]string, error) {
	removed := []string{}
	e := c.withLock(ctx, func() error {
		d, e := c.readIndex()
		if e != nil {
			return e
		}
		owners, e := c.scanOwners()
		if e != nil {
			return e
		}
		pins, e := c.pins(d, owners)
		if e != nil {
			return e
		}
		if e = c.checkResources(owners); e != nil {
			return e
		}
		// Complete a prior interrupted object-directory deletion barrier before
		// turning RETIRING-with-missing-directory into a durable tombstone.
		if e = c.syncDirectory(filepath.Join(c.root, "objects")); e != nil {
			return e
		}
		if _, e = c.storedBytes(); e != nil {
			return e
		}
		es, e := os.ReadDir(filepath.Join(c.root, "objects"))
		if e != nil {
			return e
		}
		for _, entry := range es {
			if e = ctx.Err(); e != nil {
				return e
			}
			id := entry.Name()
			v, known := d.Entries[id]
			if known && (v.Phase == templateAvailable || pins[id] > 0) {
				continue
			}
			if !known && !hex64.MatchString(id) && !stageName(id) {
				return errors.New("unknown catalog garbage")
			}
			path := filepath.Join(c.root, "objects", id)
			if e = os.Chmod(path, 0700); e != nil {
				return e
			}
			if e = os.RemoveAll(path); e != nil {
				return e
			}
			if e = c.syncDirectory(filepath.Join(c.root, "objects")); e != nil {
				return e
			}
			if known {
				v.Phase = templateRetired
				d.Entries[id] = v
				if e = c.saveIndex(d); e != nil {
					return e
				}
			}
			c.cacheMu.Lock()
			delete(c.verified, filepath.Join(path, "memory"))
			delete(c.verified, filepath.Join(path, "state"))
			c.cacheMu.Unlock()
			removed = append(removed, id)
		}
		// A crash can leave RETIRING metadata after durable object deletion.
		for id, v := range d.Entries {
			if v.Phase == templateRetiring && pins[id] == 0 {
				if _, e = os.Lstat(c.object(id)); os.IsNotExist(e) {
					v.Phase = templateRetired
					d.Entries[id] = v
					if e = c.saveIndex(d); e != nil {
						return e
					}
				} else if e != nil {
					return e
				}
			}
		}
		return nil
	})
	return removed, e
}
