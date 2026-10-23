package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

type ownership struct {
	Version                 int         `json:"version"`
	Ref                     sandbox.Ref `json:"ref"`
	QuotaAttempted          bool        `json:"quota_attempted,omitempty"`
	ProjectID               uint32      `json:"project_id,omitempty"`
	UID                     int         `json:"uid"`
	TemplateID              string      `json:"template_id,omitempty"`
	InitializationAttempted bool        `json:"initialization_attempted,omitempty"`
}

// Registry memory locks never cover persistence. The manager serializes lifecycle
// operations for the SAME Ref; different generations may persist concurrently.
// Reservations remain visible until ownership deletion is durable, so Stop can
// read ownership without waiting for another generation's fsync.
type registry struct {
	mu            sync.RWMutex
	persist       func(string, any) error
	syncDirectory func(string) error
	beforeRelease func(ownership) error // Installed once before workers start; no memory lock across quota I/O.
	dir           string
	cfg           Config
	catalog       *catalog
	hostABI       string
	owners        map[string]ownership
}

func newRegistry(dir string, cfg Config, records []sandbox.Record) (*registry, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := syncDir(filepath.Dir(dir)); err != nil {
		return nil, err
	}
	want, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "config.json")
	data, err := privatefile.Read(path, 16384)
	if os.IsNotExist(err) {
		entries, readErr := os.ReadDir(dir)
		if readErr != nil || len(entries) != 0 {
			return nil, errors.New("backend binding missing from nonempty registry")
		}
		if err = durableJSON(path, cfg); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		var old Config
		if err := strictjson.Decode(data, &old); err != nil {
			return nil, err
		}
		have, _ := json.Marshal(old)
		if !bytes.Equal(have, want) {
			return nil, errors.New("backend binding changed; explicit offline migration is required")
		}
	}
	r := &registry{dir: dir, cfg: cfg, owners: make(map[string]ownership), persist: durableJSON, syncDirectory: syncDir}
	live := make(map[string]bool)
	for _, record := range records {
		k, err := key(record.Ref)
		if err != nil {
			return nil, err
		}
		if record.Backend == "firecracker" && record.State != sandbox.Destroyed {
			live[k] = true
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	uids := make(map[int]bool)
	for _, entry := range entries {
		if entry.Name() == "catalog" && cfg.Snapshot != nil {
			if !entry.IsDir() {
				return nil, errors.New("invalid catalog directory")
			}
			continue
		}
		if entry.Name() == "config.json" || len(entry.Name()) > 0 && entry.Name()[0] == '.' {
			continue // Atomic-write leftovers allocated no external resources.
		}
		if !entry.Type().IsRegular() {
			return nil, errors.New("invalid ownership file")
		}
		data, err := privatefile.Read(filepath.Join(dir, entry.Name()), 2048)
		if err != nil {
			return nil, err
		}
		var owner ownership
		if err := strictjson.Decode(data, &owner); err != nil {
			return nil, err
		}
		k, err := key(owner.Ref)
		if err != nil || !validOwnership(owner, cfg) || entry.Name() != k+".json" || owner.UID < cfg.UIDStart || owner.UID >= cfg.UIDStart+cfg.UIDCount || uids[owner.UID] || !live[k] {
			return nil, errors.New("ownership does not match live ledger or reserved UID policy")
		}
		uids[owner.UID], r.owners[k] = true, owner
	}
	if cfg.Snapshot != nil {
		r.catalog, err = openCatalog(dir, cfg, len(r.owners) == 0)
		if err != nil {
			return nil, err
		}
		if err = r.catalog.validatePins(context.Background()); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *registry) reserve(ref sandbox.Ref) (ownership, error) {
	return r.reserveContext(context.Background(), ref)
}
func (r *registry) reserveContext(ctx context.Context, ref sandbox.Ref) (ownership, error) {
	if r.catalog == nil {
		return r.reserveOwner(ref, "")
	}
	var owner ownership
	_, err := r.catalog.acquire(ctx, r.hostABI, func(id string) error { var err error; owner, err = r.reserveOwner(ref, id); return err })
	return owner, err
}
func (r *registry) reserveOwner(ref sandbox.Ref, template string) (ownership, error) {
	k, err := key(ref)
	if err != nil {
		return ownership{}, err
	}
	r.mu.Lock()
	if _, exists := r.owners[k]; exists {
		r.mu.Unlock()
		return ownership{}, errors.New("generation already has ownership; cannot prepare again")
	}
	if r.cfg.Node != nil && len(r.owners) >= r.cfg.Node.MaxInstances {
		r.mu.Unlock()
		return ownership{}, sandbox.ErrCapacity
	}
	used := make(map[int]bool)
	for _, owner := range r.owners {
		used[owner.UID] = true
	}
	for uid := r.cfg.UIDStart; uid < r.cfg.UIDStart+r.cfg.UIDCount; uid++ {
		if used[uid] {
			continue
		}
		owner := ownership{Version: 1, Ref: ref, UID: uid}
		if template != "" {
			owner.Version = 2
			owner.TemplateID = template
		}
		if project, ok := r.cfg.projectForUID(uid); ok {
			owner.Version += 2
			owner.ProjectID = project
		}
		// Keep the reservation even if fsync reports failure after rename.
		r.owners[k] = owner
		r.mu.Unlock()
		if err := r.persist(filepath.Join(r.dir, k+".json"), owner); err != nil {
			return owner, fmt.Errorf("persist generation ownership: %w", err)
		}
		return owner, nil
	}
	r.mu.Unlock()
	return ownership{}, sandbox.ErrCapacity
}

func (r *registry) release(k string) error { return r.releaseContext(context.Background(), k) }
func (r *registry) releaseContext(ctx context.Context, k string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var quotaProof *ownership
	if r.cfg.Quota != nil {
		r.mu.RLock()
		o, exists := r.owners[k]
		r.mu.RUnlock()
		if !exists || !validOwnership(o, r.cfg) || r.beforeRelease == nil {
			return errors.New("quota ownership cannot be released without zero-usage proof")
		}
		// Slow quota I/O must not hold the catalog's inter-process pin lock.
		// The exact durable owner (and hence pin, UID and project) stays in
		// place until the short, serialized ownership deletion below succeeds.
		if err := r.beforeRelease(o); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		quotaProof = &o
	}
	if r.catalog == nil {
		return r.releaseOwner(k, quotaProof)
	}
	return r.catalog.withLock(ctx, func() error { return r.releaseOwner(k, quotaProof) })
}
func (r *registry) releaseOwner(k string, quotaProof *ownership) error {
	if r.cfg.Quota != nil {
		r.mu.RLock()
		o, exists := r.owners[k]
		r.mu.RUnlock()
		if !exists || quotaProof == nil || o != *quotaProof || !validOwnership(o, r.cfg) {
			return errors.New("quota ownership changed or its release proof is missing")
		}
	}

	if err := os.Remove(filepath.Join(r.dir, k+".json")); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := r.syncDirectory(r.dir); err != nil {
		return err
	}
	r.mu.Lock()
	delete(r.owners, k)
	r.mu.Unlock()
	return nil
}

func (r *registry) owns(k string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.owners[k]
	return exists
}

func durableJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".atomic-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func validOwnership(o ownership, cfg Config) bool {
	want := 1
	if cfg.Snapshot != nil {
		want = 2
	}
	if cfg.Quota != nil {
		want += 2
		project, ok := cfg.projectForUID(o.UID)
		if !ok || o.ProjectID != project || (o.InitializationAttempted && !o.QuotaAttempted) {
			return false
		}
	} else if o.ProjectID != 0 || o.QuotaAttempted {
		return false
	}
	if o.Version != want {
		return false
	}
	if cfg.Snapshot == nil {
		return o.TemplateID == "" && !o.InitializationAttempted
	}
	return hex64.MatchString(o.TemplateID)
}

// This durable attempt fence is written before any entropy/identity request.
// After controller death recovery only stops/reclaims; WAITING is not reusable.
func (r *registry) markInitialization(ctx context.Context, k string) error {
	if r.catalog == nil {
		return errors.New("snapshot ownership required")
	}
	return r.catalog.withLock(ctx, func() error {
		r.mu.Lock()
		o, ok := r.owners[k]
		if !ok || !snapshotOwnership(o) || o.InitializationAttempted || (r.cfg.Quota != nil && !o.QuotaAttempted) {
			r.mu.Unlock()
			return errors.New("initialization attempt already consumed or unowned")
		}
		o.InitializationAttempted = true
		r.owners[k] = o
		r.mu.Unlock()
		return r.persist(filepath.Join(r.dir, k+".json"), o)
	})
}

// markQuotaAttempt durably claims the right to set limits for this owner. A
// pre-attempt owner can only own an empty quota record; recovery must not clear
// a nonempty record merely because an unused UID slot was reserved.
func (r *registry) markQuotaAttempt(k string) error {
	r.mu.Lock()
	o, ok := r.owners[k]
	if !ok || r.cfg.Quota == nil || !validOwnership(o, r.cfg) || o.QuotaAttempted {
		r.mu.Unlock()
		return errors.New("quota attempt is unowned or already consumed")
	}
	o.QuotaAttempted = true
	r.owners[k] = o
	r.mu.Unlock()
	return r.persist(filepath.Join(r.dir, k+".json"), o)
}
