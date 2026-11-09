package firecracker

import (
	"encoding/json"
	"errors"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// InspectionOwnership is disk metadata, not a live owner/reclaim capability.
// The underlying versioned schema is unchanged; no constructor/Load is invoked.
type InspectionOwnership = ownership
type InspectionCatalogIndex = catalogIndex

func DecodeInspectionConfig(raw []byte) (Config, error) {
	var c Config
	if len(raw) == 0 || len(raw) > 16384 {
		return c, errors.New("invalid backend inspection size")
	}
	if e := strictjson.Decode(raw, &c); e != nil {
		return c, e
	}
	return c, c.validate()
}

func DecodeInspectionOwnership(raw []byte, cfg Config) (InspectionOwnership, error) {
	var o ownership
	if len(raw) == 0 || len(raw) > 2048 {
		return o, errors.New("invalid ownership inspection size")
	}
	if e := cfg.validate(); e != nil {
		return o, e
	}
	if e := strictjson.Decode(raw, &o); e != nil {
		return o, e
	}
	if _, e := key(o.Ref); e != nil {
		return o, e
	}
	if !validOwnership(o, cfg) || o.UID < cfg.UIDStart || o.UID >= cfg.UIDStart+cfg.UIDCount {
		return o, errors.New("ownership inspection policy mismatch")
	}
	return o, nil
}

// Validate only metadata and pin joins. This does NOT open/hash shared backing,
// initialize or sync a catalog, take its lock, retire/GC objects or authorize
// file selection. The caller owns the original state/catalog locks and anchored
// reads. An installed cold-only policy must reject any catalog instead.
func DecodeInspectionCatalog(raw []byte, cfg Config, backend string, owners []InspectionOwnership) (InspectionCatalogIndex, error) {
	var d catalogIndex
	if len(raw) == 0 || len(raw) > catalogIndexMax || !cleanAbsolute(backend) {
		return d, errors.New("invalid catalog inspection input")
	}
	if e := cfg.validate(); e != nil {
		return d, e
	}
	if cfg.Snapshot == nil {
		return d, errors.New("catalog forbidden by cold policy")
	}
	if e := strictjson.Decode(raw, &d); e != nil {
		return d, e
	}
	if e := validateCatalogIndex(d, cfg, backend); e != nil {
		return d, e
	}
	seen := map[string]bool{}
	uids := map[int]bool{}
	for _, o := range owners {
		k, e := key(o.Ref)
		if e != nil || !validOwnership(o, cfg) || o.UID < cfg.UIDStart || o.UID >= cfg.UIDStart+cfg.UIDCount || seen[k] || uids[o.UID] {
			return d, errors.New("invalid catalog inspection owner set")
		}
		seen[k], uids[o.UID] = true, true
		entry, ok := d.Entries[o.TemplateID]
		if !ok || entry.Phase == templateRetired {
			return d, errors.New("catalog inspection pin missing or retired")
		}
	}
	return d, nil
}

func DecodeInspectionManifest(raw []byte, cfg Config, id string) (SnapshotManifest, error) {
	var m SnapshotManifest
	if len(raw) == 0 || len(raw) > 8192 {
		return m, errors.New("invalid inspection manifest size")
	}
	if e := cfg.validate(); e != nil {
		return m, e
	}
	if e := strictjson.Decode(raw, &m); e != nil {
		return m, e
	}
	if e := m.validate(cfg); e != nil {
		return m, e
	}
	if !hex64.MatchString(id) || m.ID() != id {
		return m, errors.New("inspection manifest identity mismatch")
	}
	return m, nil
}

// Semantic binding matches the existing ordinary registry reader, not a new
// serializer/version. Neither helper reads or mutates any filesystem path.
func InspectionConfigEqual(a, b Config) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
