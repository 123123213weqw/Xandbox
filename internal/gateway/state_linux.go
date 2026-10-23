//go:build linux

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

type policyRecord struct {
	Version        int    `json:"version"`
	Revision       uint64 `json:"revision"`
	SnapshotSHA256 string `json:"snapshot_sha256"`
}
type policyIdentity struct {
	Version       int    `json:"version"`
	BindingSHA256 string `json:"binding_sha256"`
}
type policyState struct {
	dir     string
	info    os.FileInfo
	lock    *os.File
	binding string
	record  policyRecord
}

func digestJSON(v any) string {
	b, _ := json.Marshal(v)
	x := sha256.Sum256(b)
	return hex.EncodeToString(x[:])
}
func gatewayBinding(c Config, authority []byte) string {
	return digestJSON(struct {
		UID, GID                                                                                uint32
		Listen, ServerName, EmptyRoot, TenantSocket, BackendAuthFile, StateDir, AuthoritySHA256 string
	}{c.UID, c.GID, c.Listen, c.ServerName, c.EmptyRoot, c.TenantSocket, c.BackendAuthFile, c.StateDir, digestJSON(json.RawMessage(authority))})
}
func openPolicyState(dir, binding string) (out *policyState, err error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || len(binding) != 64 {
		return nil, errors.New("invalid gateway policy state binding")
	}
	if _, e := privatefile.ExistingDirectory(dir); e != nil {
		return nil, e
	}
	fd, e := unix.Open(filepath.Join(dir, "gateway.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "gateway-state-lock")
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	info, e := f.Stat()
	if e != nil {
		return nil, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return nil, errors.New("private single-link gateway lock required")
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, errors.New("gateway policy state already locked")
	}
	current, e := os.Lstat(filepath.Join(dir, "gateway.lock"))
	if e != nil || !os.SameFile(info, current) {
		return nil, errors.New("gateway policy lock changed")
	}
	root, e := os.Lstat(dir)
	if e != nil {
		return nil, e
	}
	s := &policyState{dir: dir, info: root, lock: f, binding: binding}
	identity, ie := privatefile.Read(filepath.Join(dir, "policy.identity"), 1024)
	record, re := privatefile.Read(filepath.Join(dir, "policy.json"), 4096)
	if os.IsNotExist(ie) && os.IsNotExist(re) {
		entries, e := os.ReadDir(dir)
		if e != nil || len(entries) != 1 || entries[0].Name() != "gateway.lock" {
			return nil, errors.New("used gateway state cannot bootstrap")
		}
		return s, nil
	}
	if ie != nil || re != nil {
		return nil, errors.New("gateway policy identity or record missing")
	}
	var id policyIdentity
	if strictjson.Decode(identity, &id) != nil || id.Version != 1 || id.BindingSHA256 != binding {
		return nil, errors.New("gateway policy binding changed")
	}
	if strictjson.Decode(record, &s.record) != nil || s.record.Version != 1 || s.record.Revision == 0 || len(s.record.SnapshotSHA256) != 64 {
		return nil, errors.New("invalid gateway policy record")
	}
	if _, e := hex.DecodeString(s.record.SnapshotSHA256); e != nil {
		return nil, errors.New("invalid gateway policy digest")
	}
	return s, nil
}
func (s *policyState) Close() { _ = s.lock.Close() }
func (s *policyState) checkDirectory() error {
	now, e := os.Lstat(s.dir)
	if e != nil || !os.SameFile(now, s.info) || !now.IsDir() || now.Mode().Perm() != 0700 {
		return errors.New("gateway policy directory changed")
	}
	return nil
}
func (s *policyState) atomic(name, prefix string, v any) error {
	if e := s.checkDirectory(); e != nil {
		return e
	}
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	file, e := os.CreateTemp(s.dir, prefix)
	if e != nil {
		return e
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, e = file.Write(append(b, '\n')); e != nil {
		return e
	}
	if e = file.Sync(); e != nil {
		return e
	}
	if e = file.Close(); e != nil {
		return e
	}
	if e = s.checkDirectory(); e != nil {
		return e
	}
	if e = os.Rename(file.Name(), filepath.Join(s.dir, name)); e != nil {
		return e
	}
	dir, e := os.Open(s.dir)
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}

// Commit happens BEFORE exposing a new snapshot. An unacknowledged attempted
// policy may become durable; rollback/reuse of its revision is never allowed.
func (s *policyState) Commit(snapshot Snapshot) error {
	next := policyRecord{Version: 1, Revision: snapshot.Epoch, SnapshotSHA256: digestJSON(snapshot)}
	if s.record.Revision == 0 {
		if next.Revision != 1 {
			return errors.New("fresh gateway policy must start at revision1")
		}
		if e := s.atomic("policy.json", ".policy-", next); e != nil {
			return e
		}
		if e := s.atomic("policy.identity", ".identity-", policyIdentity{Version: 1, BindingSHA256: s.binding}); e != nil {
			return e
		}
	} else if next.Revision == s.record.Revision {
		if next != s.record {
			return errors.New("gateway revision reused with different policy")
		}
		return nil
	} else {
		if s.record.Revision == ^uint64(0) || next.Revision != s.record.Revision+1 {
			return errors.New("gateway policy rollback or skipped revision")
		}
		if e := s.atomic("policy.json", ".policy-", next); e != nil {
			return e
		}
	}
	s.record = next
	return nil
}
