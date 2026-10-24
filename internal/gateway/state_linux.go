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

	"github.com/123123213weqw/Xandbox/internal/policycontrol"
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
	root    *os.File
	binding string
	record  policyRecord
}

func digestJSON(v any) string {
	b, _ := json.Marshal(v)
	x := sha256.Sum256(b)
	return hex.EncodeToString(x[:])
}
func gatewayBinding(c Config, authority []byte) string {
	legacy := digestJSON(struct {
		UID, GID                                                                                uint32
		Listen, ServerName, EmptyRoot, TenantSocket, BackendAuthFile, StateDir, AuthoritySHA256 string
	}{c.UID, c.GID, c.Listen, c.ServerName, c.EmptyRoot, c.TenantSocket, c.BackendAuthFile, c.StateDir, digestJSON(json.RawMessage(authority))})
	if c.Version == 1 {
		return legacy
	}
	return digestJSON(struct {
		Version                                                        int
		Legacy, ManagedPolicyFile, OperatorSocket, InitialPolicySHA256 string
	}{c.Version, legacy, c.ManagedPolicyFile, policycontrol.OperatorSocket, c.InitialPolicySHA256})
}
func openPolicyState(dir, binding string) (out *policyState, err error) {
	return openPolicyStateMode(dir, binding, true)
}

// Maintenance must never manufacture a used-directory marker or bootstrap a
// missing authority. Keep this distinct from the supervisor's initial opener.
func openExistingPolicyState(dir, binding string) (*policyState, error) {
	return openPolicyStateMode(dir, binding, false)
}

func openPolicyStateMode(dir, binding string, bootstrap bool) (out *policyState, err error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || len(binding) != 64 {
		return nil, errors.New("invalid gateway policy state binding")
	}
	if _, e := privatefile.ExistingDirectory(dir); e != nil {
		return nil, e
	}
	// The durable lock inode is also a used-directory marker. A surviving lock
	// must never authorize bootstrap after both authority records disappear.
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if bootstrap {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, e := unix.Open(filepath.Join(dir, "gateway.lock"), flags, 0600)
	freshLock := bootstrap && e == nil
	if bootstrap && errors.Is(e, unix.EEXIST) {
		fd, e = unix.Open(filepath.Join(dir, "gateway.lock"), unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	}
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "gateway-state-lock")
	var directory *os.File
	defer func() {
		if err != nil {
			f.Close()
			if directory != nil {
				directory.Close()
			}
		}
	}()
	info, e := f.Stat()
	if e != nil {
		return nil, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Mode&07777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || info.Size() != 0 {
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
	directoryFD, e := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	directory = os.NewFile(uintptr(directoryFD), "gateway-policy-directory")
	pinned, e := directory.Stat()
	if e != nil || !os.SameFile(root, pinned) {
		return nil, errors.New("gateway policy directory changed while opening")
	}
	s := &policyState{dir: dir, info: root, lock: f, root: directory, binding: binding}
	if freshLock {
		if e = f.Sync(); e != nil {
			return nil, e
		}
		d, e := os.Open(dir)
		if e != nil {
			return nil, e
		}
		e = d.Sync()
		_ = d.Close()
		if e != nil {
			return nil, e
		}
	}
	identity, ie := privatefile.Read(filepath.Join(dir, "policy.identity"), 1024)
	record, re := privatefile.Read(filepath.Join(dir, "policy.json"), 4096)
	if os.IsNotExist(ie) && os.IsNotExist(re) {
		if !freshLock {
			return nil, errors.New("used gateway state cannot bootstrap")
		}
		entries, e := s.names()
		if e != nil || len(entries) != 1 || entries[0] != "gateway.lock" {
			return nil, errors.New("used gateway state cannot bootstrap")
		}
		return s, nil
	}
	if ie != nil || re != nil {
		return nil, errors.New("gateway policy identity or record missing")
	}
	if freshLock {
		return nil, errors.New("gateway policy lock missing from initialized state")
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
func (s *policyState) Close() { _ = s.root.Close(); _ = s.lock.Close() }
func (s *policyState) checkDirectory() error {
	now, e := os.Lstat(s.dir)
	if e != nil || !os.SameFile(now, s.info) || !now.IsDir() || now.Mode().Perm() != 0700 {
		return errors.New("gateway policy directory changed")
	}
	pinned, e := s.root.Stat()
	if e != nil || !os.SameFile(pinned, s.info) {
		return errors.New("gateway policy directory descriptor changed")
	}
	lock, e := os.Lstat(filepath.Join(s.dir, "gateway.lock"))
	held, he := s.lock.Stat()
	if e != nil || he != nil || !os.SameFile(lock, held) || !lock.Mode().IsRegular() || lock.Mode().Perm() != 0600 {
		return errors.New("gateway policy lock identity changed")
	}
	st, ok := held.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || held.Size() != 0 {
		return errors.New("gateway policy lock attributes changed")
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
	digest, e := SnapshotDigest(snapshot)
	if e != nil {
		return e
	}
	next := policyRecord{Version: 1, Revision: snapshot.Epoch, SnapshotSHA256: digest}
	if s.record.Revision == 0 {
		if next.Revision != 1 {
			return errors.New("fresh gateway policy must start at revision1")
		}
	} else if next.Revision == s.record.Revision {
		if next != s.record {
			return errors.New("gateway revision reused with different policy")
		}
	} else if s.record.Revision == ^uint64(0) || next.Revision != s.record.Revision+1 {
		return errors.New("gateway policy rollback or skipped revision")
	}
	// No filesystem mutation for an invalid CAS. Recognized unreferenced temps
	// are collected and their removal synced before any snapshot can be exposed.
	if e := s.collect(); e != nil {
		return e
	}
	if next == s.record {
		return nil
	}
	if e := s.atomic("policy.json", ".policy-", next); e != nil {
		return e
	}
	if s.record.Revision == 0 {
		if e := s.atomic("policy.identity", ".identity-", policyIdentity{Version: 1, BindingSHA256: s.binding}); e != nil {
			return e
		}
	}
	s.record = next
	return nil
}
