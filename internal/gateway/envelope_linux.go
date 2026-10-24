//go:build linux

package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const managedRoot = "/etc/xandbox-install"
const MaxPolicyIntent = 16384

var policyRequest = regexp.MustCompile(`^[0-9a-f]{32}$`)
var policyPath = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)

type PolicySource struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// PolicyEnvelope is the single atomic installed policy authority AND payload.
// It avoids a torn two-file policy/rotation-record publication. Epoch1 has no
// rotation metadata and its whole bytes are pinned by the immutable base config.
type PolicyEnvelope struct {
	Version                  int          `json:"version"`
	Revision                 uint64       `json:"revision"`
	ExpectedRevision         uint64       `json:"expected_revision"`
	RequestID                string       `json:"request_id"`
	BaseCommitSHA256         string       `json:"base_commit_sha256"`
	ConfigSHA256             string       `json:"config_sha256"`
	InitialPolicySHA256      string       `json:"initial_policy_sha256"`
	Source                   PolicySource `json:"source"`
	Snapshot                 Snapshot     `json:"snapshot"`
	SupersededRequestID      string       `json:"superseded_request_id,omitempty"`
	ReplacedPendingRequestID string       `json:"replaced_pending_request_id,omitempty"`
}
type PolicyIntent struct {
	Version             int          `json:"version"`
	ExpectedRevision    uint64       `json:"expected_revision"`
	RequestID           string       `json:"request_id"`
	BaseCommitSHA256    string       `json:"base_commit_sha256"`
	ConfigSHA256        string       `json:"config_sha256"`
	InitialPolicySHA256 string       `json:"initial_policy_sha256"`
	OldPayloadSHA256    string       `json:"old_payload_sha256"`
	NewPayloadSHA256    string       `json:"new_payload_sha256"`
	Source              PolicySource `json:"source"`
}

func policyBytesDigest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func canonicalPolicyPath(p string) bool {
	return len(p) <= 4096 && policyPath.MatchString(p) && filepath.Clean(p) == p && p != "/"
}
func policySourceValid(s PolicySource) bool {
	if !canonicalPolicyPath(s.Path) || !policySHA(s.SHA256) {
		return false
	}
	for _, root := range []string{managedRoot, "/srv/xi", "/etc/systemd/system", "/usr/libexec"} {
		if s.Path == root || strings.HasPrefix(s.Path, root+"/") {
			return false
		}
	}
	return true
}
func EncodePolicyEnvelope(p PolicyEnvelope) ([]byte, error) {
	b, e := json.Marshal(p)
	if e != nil || len(b)+1 > MaxSnapshotBytes {
		return nil, errors.New("invalid managed policy envelope")
	}
	return append(b, '\n'), nil
}
func ManagedConfigDigest(c Config) (string, error) {
	if c.Version != 2 || c.ValidateShape() != nil {
		return "", errors.New("invalid managed config binding")
	}
	b, e := json.Marshal(c)
	if e != nil {
		return "", errors.New("invalid managed config binding")
	}
	return policyBytesDigest(b), nil
}
func DecodeManagedEnvelope(c Config, raw []byte, base string) (PolicyEnvelope, error) {
	var p PolicyEnvelope
	bad := errors.New("invalid managed policy envelope")
	if c.Version != 2 || c.ValidateShape() != nil || len(raw) == 0 || len(raw) > MaxSnapshotBytes || strictjson.Decode(raw, &p) != nil {
		return p, bad
	}
	b, e := EncodePolicyEnvelope(p)
	if e != nil || !bytes.Equal(b, raw) || p.Version != 1 || p.Revision == 0 || p.Snapshot.Epoch != p.Revision {
		return p, bad
	}
	if p.Snapshot.UID != c.UID || p.Snapshot.GID != c.GID || p.Snapshot.Listen != c.Listen || p.Snapshot.ServerName != c.ServerName {
		return p, bad
	}
	if _, e = SnapshotDigest(p.Snapshot); e != nil {
		return p, bad
	}
	if p.Revision == 1 {
		if p.ExpectedRevision != 0 || p.RequestID != "" || p.BaseCommitSHA256 != "" || p.ConfigSHA256 != "" || p.InitialPolicySHA256 != "" || p.Source != (PolicySource{}) || p.SupersededRequestID != "" || p.ReplacedPendingRequestID != "" || policyBytesDigest(raw) != c.InitialPolicySHA256 {
			return p, bad
		}
	} else {
		binding, e := ManagedConfigDigest(c)
		if e != nil || !policySHA(base) || p.BaseCommitSHA256 != base || p.ExpectedRevision != p.Revision-1 || !policyRequest.MatchString(p.RequestID) || p.ConfigSHA256 != binding || p.InitialPolicySHA256 != c.InitialPolicySHA256 || !policySourceValid(p.Source) {
			return p, bad
		}
		if p.SupersededRequestID != "" && (!policyRequest.MatchString(p.SupersededRequestID) || p.SupersededRequestID == p.RequestID || p.Revision < 3) {
			return p, bad
		}
		if p.ReplacedPendingRequestID != "" && (!policyRequest.MatchString(p.ReplacedPendingRequestID) || p.ReplacedPendingRequestID == p.RequestID || p.SupersededRequestID != "") {
			return p, bad
		}
	}
	return p, nil
}
func DecodePolicyIntent(c Config, base string, raw []byte) (PolicyIntent, error) {
	var p PolicyIntent
	bad := errors.New("invalid managed policy intent")
	if len(raw) == 0 || len(raw) > MaxPolicyIntent || strictjson.Decode(raw, &p) != nil {
		return p, bad
	}
	b, e := json.Marshal(p)
	binding, be := ManagedConfigDigest(c)
	if e != nil || be != nil || !bytes.Equal(append(b, '\n'), raw) || p.Version != 1 || p.ExpectedRevision == 0 || p.ExpectedRevision == ^uint64(0) || !policyRequest.MatchString(p.RequestID) || !policySHA(base) || p.BaseCommitSHA256 != base || p.ConfigSHA256 != binding || p.InitialPolicySHA256 != c.InitialPolicySHA256 || !policySHA(p.OldPayloadSHA256) || !policySHA(p.NewPayloadSHA256) || p.OldPayloadSHA256 == p.NewPayloadSHA256 || !policySourceValid(p.Source) {
		return p, bad
	}
	return p, nil
}
func ValidateVisiblePolicyIntent(c Config, base string, payload, intent []byte) (PolicyIntent, error) {
	i, e := DecodePolicyIntent(c, base, intent)
	if e != nil {
		return i, e
	}
	p, e := DecodeManagedEnvelope(c, payload, base)
	if e != nil || p.Revision != i.ExpectedRevision+1 || p.RequestID != i.RequestID || p.Source != i.Source || policyBytesDigest(payload) != i.NewPayloadSHA256 {
		return i, errors.New("managed policy transaction uncommitted")
	}
	return i, nil
}

// This verifies only the immutable gateway/policy base reference, not the
// installation's complete artifact inventory, self pin or manager state. The
// full installer verifier remains mandatory before any operator receipt.
func ValidateManagedBase(c Config, configRaw, commitRaw []byte) (string, error) {
	bad := errors.New("invalid managed gateway base commit")
	var config Config
	if strictjson.Decode(configRaw, &config) != nil {
		return "", bad
	}
	a, e := ManagedConfigDigest(c)
	b, be := ManagedConfigDigest(config)
	if e != nil || be != nil || a != b {
		return "", bad
	}
	var top map[string]json.RawMessage
	if len(commitRaw) == 0 || len(commitRaw) > 65536 || strictjson.Decode(commitRaw, &top) != nil || len(top) != 6 {
		return "", bad
	}
	for _, key := range []string{"version", "revision", "request_id", "plan", "release", "files"} {
		if _, ok := top[key]; !ok {
			return "", bad
		}
	}
	var ref struct {
		Version   int    `json:"version"`
		Revision  uint64 `json:"revision"`
		RequestID string `json:"request_id"`
		Plan      struct {
			Version int           `json:"version"`
			Gateway PolicySource  `json:"gateway"`
			Policy  *PolicySource `json:"policy"`
		} `json:"plan"`
		Files []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Bytes  int64  `json:"bytes"`
			Mode   uint32 `json:"mode"`
		} `json:"files"`
	}
	if json.Unmarshal(commitRaw, &ref) != nil || ref.Version != 1 || ref.Revision != 1 || !policyRequest.MatchString(ref.RequestID) || ref.Plan.Version != 2 || ref.Plan.Policy == nil || ref.Plan.Policy.SHA256 != c.InitialPolicySHA256 || ref.Plan.Gateway.SHA256 != policyBytesDigest(configRaw) || len(ref.Files) != 24 {
		return "", bad
	}
	seen := map[string]bool{}
	gateway, policy := false, false
	for _, f := range ref.Files {
		if seen[f.Path] || !canonicalPolicyPath(f.Path) || f.Bytes <= 0 || !policySHA(f.SHA256) {
			return "", bad
		}
		seen[f.Path] = true
		if f.Path == managedRoot+"/gateway.json" {
			gateway = f.SHA256 == ref.Plan.Gateway.SHA256 && f.Mode == 0600 && f.Bytes == int64(len(configRaw))
		}
		if f.Path == ManagedPolicyPath {
			policy = f.SHA256 == c.InitialPolicySHA256 && f.Mode == 0600
		}
	}
	if !gateway || !policy {
		return "", bad
	}
	return policyBytesDigest(commitRaw), nil
}

// Startup/activation shares the original installer lock inode. No lock or
// namespace is manufactured; hold through the corresponding child ACK so a
// concurrent rotation cannot publish before an older startup becomes active.
func managedReadLock() (func(), error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, errors.New("managed installation lock required")
	}
	if _, e := privatefile.ExistingDirectory(managedRoot); e != nil {
		return nil, e
	}
	fd, e := unix.Open(managedRoot+"/.lock", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "managed-install-read-lock")
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	info, e := f.Stat()
	if e != nil {
		return nil, e
	}
	st, valid := info.Sys().(*syscall.Stat_t)
	if !valid || !info.Mode().IsRegular() || st.Mode&07777 != 0600 || st.Uid != 0 || st.Nlink != 1 || st.Size != 0 {
		return nil, errors.New("managed installation lock required")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		e = unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB)
		if e == nil {
			break
		}
		if !errors.Is(e, unix.EAGAIN) && !errors.Is(e, unix.EWOULDBLOCK) {
			return nil, e
		}
		if !time.Now().Before(deadline) {
			return nil, errors.New("managed installation lock busy")
		}
		time.Sleep(5 * time.Millisecond)
	}
	after, e := os.Lstat(managedRoot + "/.lock")
	if e != nil || !os.SameFile(info, after) {
		return nil, errors.New("managed installation lock changed")
	}
	ok = true
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = f.Close() }, nil
}
