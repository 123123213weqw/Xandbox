package firecracker

import (
	"bytes"
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
	Version int         `json:"version"`
	Ref     sandbox.Ref `json:"ref"`
	UID     int         `json:"uid"`
}

// Registry memory locks never cover persistence. The manager serializes lifecycle
// operations for the SAME Ref; different generations may persist concurrently.
// Reservations remain visible until ownership deletion is durable, so Stop can
// read ownership without waiting for another generation's fsync.
type registry struct {
	mu            sync.RWMutex
	persist       func(string, any) error
	syncDirectory func(string) error
	dir           string
	cfg           Config
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
		if err != nil || owner.Version != 1 || entry.Name() != k+".json" || owner.UID < cfg.UIDStart || owner.UID >= cfg.UIDStart+cfg.UIDCount || uids[owner.UID] || !live[k] {
			return nil, errors.New("ownership does not match live ledger or reserved UID policy")
		}
		uids[owner.UID], r.owners[k] = true, owner
	}
	return r, nil
}

func (r *registry) reserve(ref sandbox.Ref) (ownership, error) {
	k, err := key(ref)
	if err != nil {
		return ownership{}, err
	}
	r.mu.Lock()
	if _, exists := r.owners[k]; exists {
		r.mu.Unlock()
		return ownership{}, errors.New("generation already has ownership; cannot prepare again")
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

func (r *registry) release(k string) error {
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
