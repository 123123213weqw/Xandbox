package firecracker

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func inspectionJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestInspectionMetadataConfigAndOwnerReuseStrictOrdinarySchema(t *testing.T) {
	cfg := policy()
	cfg.Quota = quotaPolicy()
	decoded, e := DecodeInspectionConfig(inspectionJSON(t, cfg))
	if e != nil || !InspectionConfigEqual(cfg, decoded) {
		t.Fatal(e)
	}
	o := ownership{Version: 3, Ref: reference("1"), UID: cfg.UIDStart, ProjectID: cfg.Quota.ProjectStart}
	for _, kind := range []string{"valid", "foreign-uid", "foreign-project", "wrong-version", "invalid-ref", "initialization-cold", "unknown-field", "oversize", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			copy := o
			switch kind {
			case "foreign-uid":
				copy.UID--
			case "foreign-project":
				copy.ProjectID++
			case "wrong-version":
				copy.Version = 4
			case "invalid-ref":
				copy.Ref.ID = "wrong"
			case "initialization-cold":
				copy.InitializationAttempted = true
			}
			b := inspectionJSON(t, copy)
			switch kind {
			case "unknown-field":
				b = append([]byte(`{"foreign":true,`), b[1:]...)
			case "oversize":
				b = make([]byte, 2049)
			case "malformed":
				b = []byte("{")
			}
			_, e := DecodeInspectionOwnership(b, cfg)
			if (e == nil) != (kind == "valid") {
				t.Fatal(e)
			}
		})
	}
	for _, raw := range [][]byte{nil, []byte("{}"), []byte(`{"version":9}`), make([]byte, 16385)} {
		if _, e := DecodeInspectionConfig(raw); e == nil {
			t.Fatal("bad config accepted")
		}
	}
}

func inspectionSnapshotMetadata(t *testing.T) (Config, SnapshotManifest, catalogIndex, ownership) {
	t.Helper()
	cfg := policy()
	cfg.Version = 2
	cfg.Snapshot = &SnapshotPolicy{Version: 1, AgentSHA256: strings.Repeat("b", 64), MemoryMiB: 512, VCPUs: 2, MaxEntries: 8, MaxBytes: 2 << 30}
	m := SnapshotManifest{Version: 1, Format: "firecracker-v1.17.0-full", SourceRevision: strings.Repeat("d", 40), CreatedAt: time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC), Assignment: "UNASSIGNED", BootArgs: pristineBootArgs, BootstrapProtocol: 1, AgentSHA256: cfg.Snapshot.AgentSHA256, FirecrackerSHA256: cfg.Firecracker.SHA256, JailerSHA256: cfg.Jailer.SHA256, KernelSHA256: cfg.Kernel.SHA256, InitrdSHA256: cfg.Initrd.SHA256, WorkspaceSHA256: cfg.Workspace.SHA256, HostABI: strings.Repeat("c", 64), MemoryMiB: 512, VCPUs: 2, MemorySHA256: strings.Repeat("e", 64), StateSHA256: strings.Repeat("f", 64), StateBytes: 128}
	id := m.ID()
	d := catalogIndex{Version: 1, ConfigSHA256: configDigest(cfg), RegistrySHA256: registryDigest("/srv/xi/s/firecracker"), Active: id, Entries: map[string]catalogEntry{id: {Phase: templateAvailable, Bytes: m.bytes()}}}
	o := ownership{Version: 2, Ref: reference("1"), UID: cfg.UIDStart, TemplateID: id}
	return cfg, m, d, o
}

func TestInspectionMetadataCatalogBindingsAndDurablePins(t *testing.T) {
	for _, kind := range []string{"available", "retiring-pin", "cold-policy", "wrong-config", "wrong-registry", "missing-pin", "retired-pin", "duplicate-uid", "duplicate-ref", "unknown-field", "nil-entries", "bad-active", "over-budget"} {
		t.Run(kind, func(t *testing.T) {
			cfg, m, d, o := inspectionSnapshotMetadata(t)
			owners := []InspectionOwnership{o}
			backend := "/srv/xi/s/firecracker"
			switch kind {
			case "retiring-pin":
				d.Active = ""
				d.Entries[m.ID()] = catalogEntry{Phase: templateRetiring, Bytes: m.bytes()}
			case "cold-policy":
				cfg.Snapshot = nil
				cfg.Version = 1
			case "wrong-config":
				d.ConfigSHA256 = strings.Repeat("9", 64)
			case "wrong-registry":
				backend = "/srv/other/firecracker"
			case "missing-pin":
				owners[0].TemplateID = strings.Repeat("9", 64)
			case "retired-pin":
				d.Active = ""
				d.Entries[m.ID()] = catalogEntry{Phase: templateRetired, Bytes: m.bytes()}
			case "duplicate-uid":
				other := o
				other.Ref = reference("2")
				owners = append(owners, other)
			case "duplicate-ref":
				other := o
				other.UID++
				owners = append(owners, other)
			case "nil-entries":
				d.Entries = nil
			case "bad-active":
				d.Active = strings.Repeat("9", 64)
			case "over-budget":
				cfg.Snapshot.MaxBytes = 513 << 20
				d.ConfigSHA256 = configDigest(cfg)
				d.Entries[strings.Repeat("9", 64)] = catalogEntry{Phase: templateAvailable, Bytes: m.bytes()}
			}
			b := inspectionJSON(t, d)
			if kind == "unknown-field" {
				b = append([]byte(`{"foreign":true,`), b[1:]...)
			}
			_, e := DecodeInspectionCatalog(b, cfg, backend, owners)
			want := kind == "available" || kind == "retiring-pin"
			if (e == nil) != want {
				t.Fatal(e)
			}
		})
	}
}

func TestInspectionMetadataManifestIsDeclarationNotBackingOrHostAttestation(t *testing.T) {
	for _, kind := range []string{"valid", "assigned", "geometry", "asset", "source", "wrong-id", "unknown-field", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			cfg, m, _, _ := inspectionSnapshotMetadata(t)
			switch kind {
			case "assigned":
				m.Assignment = "ASSIGNED"
			case "geometry":
				m.MemoryMiB = 1
			case "asset":
				m.KernelSHA256 = strings.Repeat("9", 64)
			case "source":
				m.SourceRevision = "bad"
			}
			id := m.ID()
			if kind == "wrong-id" {
				id = strings.Repeat("9", 64)
			}
			b := inspectionJSON(t, m)
			if kind == "unknown-field" {
				b = append([]byte(`{"foreign":true,`), b[1:]...)
			}
			if kind == "oversize" {
				b = make([]byte, 8193)
			}
			_, e := DecodeInspectionManifest(b, cfg, id)
			if (e == nil) != (kind == "valid") {
				t.Fatal(e)
			}
		})
	}
	// There are no backing bytes or kernel/host inputs to this pure decoder.
	// A valid result therefore certifies neither the digests nor current ABI.
}
