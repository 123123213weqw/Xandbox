//go:build linux

package gateway

import (
	"crypto/sha256"
	"debug/elf"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// Config exists only in the privileged supervisor. Parent-only path selection
// is immutable at reload; the frontend receives no filesystem path capability.
type Config struct {
	PolicyRevision  uint64      `json:"policy_revision"`
	StateDir        string      `json:"state_dir"`
	Version         int         `json:"version"`
	UID             uint32      `json:"uid"`
	GID             uint32      `json:"gid"`
	Listen          string      `json:"listen"`
	ServerName      string      `json:"server_name"`
	EmptyRoot       string      `json:"empty_root"`
	TenantSocket    string      `json:"tenant_socket"`
	BackendAuthFile string      `json:"backend_auth_file"`
	CertificateFile string      `json:"certificate_file"`
	PrivateKeyFile  string      `json:"private_key_file"`
	Keys            []ClientKey `json:"keys"`
}

func rootFile(path string, limit int64) ([]byte, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("canonical root configuration path required")
	}
	if _, e := privatefile.ExistingDirectory(filepath.Dir(path)); e != nil {
		return nil, e
	}
	return privatefile.Read(path, limit)
}
func loadConfig(path string) (Config, error) {
	var c Config
	b, e := rootFile(path, MaxSnapshotBytes)
	if e != nil {
		return c, errors.New("cannot read private gateway configuration")
	}
	if strictjson.Decode(b, &c) != nil || c.Version != 1 {
		return Config{}, errors.New("invalid gateway configuration")
	}
	return c, nil
}
func (c Config) snapshot(epoch uint64, authority *access.Authenticator) (Snapshot, error) {
	cert, e := rootFile(c.CertificateFile, 65536)
	if e != nil {
		return Snapshot{}, errors.New("cannot read gateway certificate")
	}
	key, e := rootFile(c.PrivateKeyFile, 65536)
	if e != nil {
		return Snapshot{}, errors.New("cannot read gateway private key")
	}
	s := Snapshot{Version: 1, Epoch: epoch, UID: c.UID, GID: c.GID, Listen: c.Listen, ServerName: c.ServerName, CertificatePEM: string(cert), PrivateKeyPEM: string(key), Keys: c.Keys}
	if _, e := NewPolicy(s, authority, time.Now()); e != nil {
		return Snapshot{}, e
	}
	return s, nil
}
func (c Config) sameBinding(other Config) bool {
	return c.Version == other.Version && c.UID == other.UID && c.GID == other.GID && c.Listen == other.Listen && c.ServerName == other.ServerName && c.EmptyRoot == other.EmptyRoot && c.TenantSocket == other.TenantSocket && c.BackendAuthFile == other.BackendAuthFile && c.StateDir == other.StateDir
}
func socketParent(path string) (os.FileInfo, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "api.sock" {
		return nil, errors.New("fixed tenant api.sock required")
	}
	dir, e := privatefile.ExistingDirectory(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	return os.Lstat(dir)
}
func hashExecutable(path string) ([32]byte, error) {
	var zero [32]byte
	info, e := os.Lstat(path)
	if e != nil {
		return zero, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return zero, errors.New("root-owned immutable gateway executable required")
	}
	f, e := os.Open(path)
	if e != nil {
		return zero, e
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !os.SameFile(info, after) {
		return zero, errors.New("gateway executable changed")
	}
	binary, e := elf.NewFile(f)
	if e != nil {
		return zero, e
	}
	for _, p := range binary.Progs {
		if p.Type == elf.PT_INTERP {
			return zero, errors.New("gateway must be CGO-free static ELF")
		}
	}
	if _, e = f.Seek(0, 0); e != nil {
		return zero, e
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, 64<<20))
	if e != nil || n != info.Size() || n >= 64<<20 {
		return zero, errors.New("bounded gateway executable required")
	}
	copy(zero[:], h.Sum(nil))
	return zero, nil
}
func checkChildRoot(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return errors.New("dedicated gateway root required")
	}
	// Parent is private; the child root itself must be searchable after setuid.
	if _, e := privatefile.ExistingDirectory(filepath.Dir(root)); e != nil {
		return e
	}
	info, e := os.Lstat(root)
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || !info.IsDir() || info.Mode().Perm() != 0555 {
		return errors.New("gateway root must be root-owned0555")
	}
	entries, e := os.ReadDir(root)
	if e != nil || len(entries) != 1 || entries[0].Name() != "gateway" {
		return errors.New("gateway root must contain only its executable")
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	// os.Executable may contain a deleted suffix: never fall back to another path.
	if strings.HasSuffix(self, " (deleted)") {
		return errors.New("gateway executable deleted")
	}
	a, e := hashExecutable(self)
	if e != nil {
		return e
	}
	b, e := hashExecutable(filepath.Join(root, "gateway"))
	if e != nil || a != b {
		return errors.New("child gateway executable differs")
	}
	return nil
}
