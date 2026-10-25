// Package releasestore publishes bounded, immutable deployment artifacts. A
// committed release is NOT installed or activated: no service, state binding,
// admission control, catalog or task is changed by this package.
package releasestore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

const Root = "/srv/xandbox-releases"
const MaxManifest = 16384
const MaxReleaseBytes int64 = 1 << 30

var ErrPolicy = errors.New("invalid release policy")
var ErrConflict = errors.New("release compare-and-swap conflict")
var ErrInventory = errors.New("unrecognized release inventory")
var ErrCapacity = errors.New("retained release capacity reached")
var ErrPlatform = errors.New("root Linux release publisher required")
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var requestPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var toolchainPattern = regexp.MustCompile(`^go1\.[0-9]{2}\.[0-9]{1,3}$`)
var pathPattern = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)

// The release is a deployment artifact bundle, not a caller-selected file tree.
// Configuration/credentials and mutable node state are deliberately separate.
var roles = []string{"daemon", "firecracker", "gateway", "ingress", "initrd", "jailer", "kernel", "launcher", "node", "ready", "template", "warden", "workspace"}

func executable(role string) bool { return role != "initrd" && role != "kernel" && role != "workspace" }
func maximum(role string) int64 {
	if role == "workspace" {
		return 512 << 20
	}
	return 128 << 20
}
func canonical(path string) bool {
	return pathPattern.MatchString(path) && filepath.Clean(path) == path && path != "/"
}

type File struct {
	Role   string `json:"role"`
	Source string `json:"source"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}
type Manifest struct {
	Version        int    `json:"version"`
	SourceRevision string `json:"source_revision"`
	Toolchain      string `json:"toolchain"`
	GOARCH         string `json:"goarch"`
	Files          []File `json:"files"`
}
type artifact struct {
	Role   string `json:"role"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}
type release struct {
	Version        int        `json:"version"`
	SourceRevision string     `json:"source_revision"`
	Toolchain      string     `json:"toolchain"`
	GOARCH         string     `json:"goarch"`
	Files          []artifact `json:"files"`
}

func Decode(data []byte) (Manifest, error) {
	var m Manifest
	if len(data) == 0 || len(data) > MaxManifest || strictjson.Decode(data, &m) != nil {
		return m, ErrPolicy
	}
	return normalize(m)
}
func normalize(m Manifest) (Manifest, error) {
	if m.Version != 1 || !revisionPattern.MatchString(m.SourceRevision) || !toolchainPattern.MatchString(m.Toolchain) || (m.GOARCH != "amd64" && m.GOARCH != "arm64") || len(m.Files) != len(roles) {
		return m, ErrPolicy
	}
	m.Files = append([]File(nil), m.Files...)
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Role < m.Files[j].Role })
	var total int64
	sources := map[string]bool{}
	for i, f := range m.Files {
		if f.Role != roles[i] || !canonical(f.Source) || f.Source == Root || strings.HasPrefix(f.Source, Root+"/") || sources[f.Source] || !digestPattern.MatchString(f.SHA256) || f.Bytes <= 0 || f.Bytes > maximum(f.Role) || f.Bytes > MaxReleaseBytes-total {
			return m, ErrPolicy
		}
		sources[f.Source] = true
		total += f.Bytes
	}
	return m, nil
}
func encoded(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic("fixed release schema is not encodable")
	}
	return append(b, '\n')
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func description(m Manifest) []byte {
	r := release{Version: 1, SourceRevision: m.SourceRevision, Toolchain: m.Toolchain, GOARCH: m.GOARCH}
	for _, f := range m.Files {
		r.Files = append(r.Files, artifact{f.Role, f.SHA256, f.Bytes})
	}
	return encoded(r)
}

// Reference records publication only, never which release a running node uses.
// The previous bundle remains retained; there is no implicit artifact GC.
type Reference struct {
	Version          int    `json:"version"`
	Revision         uint64 `json:"revision"`
	Release          string `json:"release"`
	Previous         string `json:"previous"`
	RequestID        string `json:"request_id"`
	ExpectedRevision uint64 `json:"expected_revision"`
	IntentSHA256     string `json:"intent_sha256"`
}
type intent struct {
	Version          int      `json:"version"`
	RequestID        string   `json:"request_id"`
	ExpectedRevision uint64   `json:"expected_revision"`
	BaseSHA256       string   `json:"base_sha256"`
	Manifest         Manifest `json:"manifest"`
}
type Result struct {
	Version            int    `json:"version"`
	Revision           uint64 `json:"revision"`
	Retained           int    `json:"retained"`
	PublicationDurable bool   `json:"publication_durable"`
	ServicesChanged    bool   `json:"services_changed"`
	ProductionReady    bool   `json:"production_ready"`
}

func result(r Reference) Result {
	n := 1
	if r.Previous != "" {
		n++
	}
	return Result{Version: 1, Revision: r.Revision, Retained: n, PublicationDurable: true}
}
func validReference(r Reference) bool {
	return r.Version == 1 && r.Revision > 0 && r.ExpectedRevision == r.Revision-1 && digestPattern.MatchString(r.Release) && requestPattern.MatchString(r.RequestID) && digestPattern.MatchString(r.IntentSHA256) && (r.Revision == 1 && r.Previous == "" || r.Revision > 1 && digestPattern.MatchString(r.Previous) && r.Previous != r.Release)
}

func intentDigest(in intent) string { in.BaseSHA256 = ""; return hash(encoded(in)) }
