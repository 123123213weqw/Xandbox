//go:build linux

package firecracker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// SnapshotHostABI deliberately rejects portability. This fingerprint combines
// kernel, architecture and homogeneous CPU/microcode/features. It is a strict
// compatibility guard, not proof that an arbitrary snapshot is safe/trustworthy.
func SnapshotHostABI() (string, error) {
	f, e := os.Open("/proc/cpuinfo")
	if e != nil {
		return "", e
	}
	b, e := io.ReadAll(io.LimitReader(f, 4<<20+1))
	f.Close()
	if e != nil {
		return "", e
	}
	if len(b) > 4<<20 {
		return "", errors.New("CPU inventory exceeds compatibility bound")
	}
	kernel, e := os.ReadFile("/proc/sys/kernel/osrelease")
	if e != nil {
		return "", e
	}
	return snapshotHostABI(runtime.GOARCH, strings.TrimSpace(string(kernel)), string(b))
}
func snapshotHostABI(arch, kernel, cpu string) (string, error) {
	if arch != "amd64" || kernel == "" {
		return "", errors.New("snapshot compatibility currently supports linux/amd64 only")
	}
	fields := []string{"vendor_id", "cpu family", "model", "stepping", "microcode", "flags"}
	var first map[string]string
	cpus := 0
	for _, block := range strings.Split(strings.TrimSpace(cpu), "\n\n") {
		m := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			k, v, ok := strings.Cut(line, ":")
			if ok {
				m[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		if _, ok := m["processor"]; !ok {
			continue
		}
		current := map[string]string{}
		for _, key := range fields {
			v := m[key]
			if v == "" {
				return "", errors.New("incomplete CPU compatibility inventory")
			}
			if key == "flags" {
				xs := strings.Fields(v)
				sort.Strings(xs)
				v = strings.Join(xs, " ")
			}
			current[key] = v
		}
		if first == nil {
			first = current
		} else {
			for _, k := range fields {
				if first[k] != current[k] {
					return "", errors.New("heterogeneous CPU compatibility inventory")
				}
			}
		}
		cpus++
	}
	if cpus < 2 {
		return "", errors.New("snapshot requires at least two compatible host CPUs")
	}
	v := struct {
		Version              int
		Architecture, Kernel string
		CPU                  map[string]string
	}{1, arch, kernel, first}
	raw, _ := json.Marshal(v)
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:]), nil
}

type SnapshotCatalog struct {
	catalog *catalog
	hostABI string
}

// OpenSnapshotCatalog requires an existing immutable backend binding established
// by sandboxd. It never adopts an unrelated directory or creates ownership.
func OpenSnapshotCatalog(stateDir, configPath string) (*SnapshotCatalog, error) {
	return OpenSnapshotCatalogContext(context.Background(), stateDir, configPath)
}
func OpenSnapshotCatalogContext(ctx context.Context, stateDir, configPath string) (*SnapshotCatalog, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("snapshot administration requires node root")
	}
	if e := securePath(stateDir); e != nil {
		return nil, e
	}
	if e := securePath(configPath); e != nil {
		return nil, e
	}
	cfg, e := loadConfig(configPath)
	if e != nil {
		return nil, e
	}
	if cfg.Snapshot == nil {
		return nil, errors.New("snapshot backend policy required")
	}
	backend := filepath.Join(stateDir, "firecracker")
	raw, e := privatefile.Read(filepath.Join(backend, "config.json"), 16384)
	if e != nil {
		return nil, e
	}
	var bound Config
	if e = strictjson.Decode(raw, &bound); e != nil || configDigest(bound) != configDigest(cfg) {
		return nil, errors.New("catalog administration does not match backend binding")
	}
	c, e := openCatalogContext(ctx, backend, cfg, false)
	if e != nil {
		return nil, e
	}
	abi, e := SnapshotHostABI()
	if e != nil {
		return nil, e
	}
	return &SnapshotCatalog{catalog: c, hostABI: abi}, nil
}
func (s *SnapshotCatalog) Publish(ctx context.Context, manifest, memory, state string) (string, error) {
	for _, p := range []string{manifest, memory, state} {
		if e := securePath(p); e != nil {
			return "", e
		}
	}
	raw, e := privatefile.Read(manifest, 8192)
	if e != nil {
		return "", e
	}
	var m SnapshotManifest
	if e = strictjson.Decode(raw, &m); e != nil {
		return "", e
	}
	return s.catalog.publish(ctx, m, memory, state, s.hostABI)
}
func (s *SnapshotCatalog) Activate(ctx context.Context, id string) error {
	return s.catalog.activate(ctx, id, s.hostABI)
}
func (s *SnapshotCatalog) Retire(ctx context.Context, id string) error {
	return s.catalog.retire(ctx, id)
}
func (s *SnapshotCatalog) Collect(ctx context.Context) ([]string, error) {
	return s.catalog.collect(ctx)
}
func (s *SnapshotCatalog) Status(ctx context.Context) (CatalogStatus, error) {
	return s.catalog.status(ctx)
}
