//go:build linux

package gateway

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

// Fixed logical inventory budgets, not filesystem allocated-block accounting.
// One atomic writer may temporarily add one bounded file after this admission.
const policyMaxOrphans = 8
const policyMaxEntries = 3 + policyMaxOrphans
const policyMaxBytes = 8 << 10
const policyMaxOrphanBytes = 1024

type policyEntry struct {
	name string
	info os.FileInfo
	data []byte
}

func policyTemporary(name string) (string, bool) {
	kind := ""
	for _, prefix := range []string{".policy-", ".identity-"} {
		if strings.HasPrefix(name, prefix) {
			kind = prefix
			break
		}
	}
	if kind == "" {
		return "", false
	}
	digits := strings.TrimPrefix(name, kind)
	if len(digits) == 0 || len(digits) > 20 {
		return "", false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return "", false
		}
	}
	return kind, true
}
func policyDigestValid(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil
}
func (s *policyState) names() ([]string, error) {
	if e := s.checkDirectory(); e != nil {
		return nil, e
	}
	// A new open file description has its own directory offset. Never scan the
	// whole directory into memory before deciding whether it exceeds a budget.
	fd, e := unix.Openat(int(s.root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "policy-inventory")
	defer f.Close()
	names, e := f.Readdirnames(policyMaxEntries + 1)
	if e != nil && !errors.Is(e, io.EOF) {
		return nil, e
	}
	if len(names) > policyMaxEntries {
		return nil, errors.New("gateway policy entry budget exceeded")
	}
	sort.Strings(names)
	return names, nil
}
func (s *policyState) entry(name string, limit int64) (policyEntry, error) {
	var zero policyEntry
	if name == "" || strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
		return zero, errors.New("invalid gateway state entry")
	}
	var st unix.Stat_t
	if e := unix.Fstatat(int(s.root.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return zero, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Size < 0 || st.Size > limit {
		return zero, errors.New("private bounded single-link gateway entry required")
	}
	fd, e := unix.Openat(int(s.root.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return zero, e
	}
	f := os.NewFile(uintptr(fd), "policy-entry")
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return zero, e
	}
	actual, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(actual.Dev) != uint64(st.Dev) || uint64(actual.Ino) != st.Ino || actual.Nlink != 1 || actual.Mode != st.Mode || actual.Uid != st.Uid || info.Size() != st.Size {
		return zero, errors.New("gateway entry changed while opening")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return zero, e
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(info, after) || after.Size() != st.Size || int64(len(b)) != st.Size {
		return zero, errors.New("gateway entry changed while reading")
	}
	return policyEntry{name: name, info: info, data: b}, nil
}
func (s *policyState) inventory() ([]policyEntry, error) {
	names, e := s.names()
	if e != nil {
		return nil, e
	}
	orphans := make([]policyEntry, 0, policyMaxOrphans)
	named := map[string]bool{}
	total := int64(0)
	for _, name := range names {
		kind, temporary := policyTemporary(name)
		limit := int64(policyMaxOrphanBytes)
		switch name {
		case "gateway.lock":
			limit = 0
		case "policy.json":
			limit = 4096
		case "policy.identity":
			limit = 1024
		default:
			if !temporary {
				return nil, errors.New("unknown gateway policy entry")
			}
		}
		if remaining := int64(policyMaxBytes) - total; limit > remaining {
			limit = remaining
		}
		v, e := s.entry(name, limit)
		if e != nil {
			return nil, e
		}
		total += v.info.Size()
		if total > policyMaxBytes {
			return nil, errors.New("gateway policy logical byte budget exceeded")
		}
		if !temporary {
			named[name] = true
			switch name {
			case "gateway.lock":
				info, e := s.lock.Stat()
				if e != nil || !os.SameFile(info, v.info) {
					return nil, errors.New("gateway inventory lock changed")
				}
			case "policy.json":
				var r policyRecord
				if s.record.Revision == 0 || strictjson.Decode(v.data, &r) != nil || r != s.record {
					return nil, errors.New("gateway current policy authority changed")
				}
			case "policy.identity":
				var id policyIdentity
				if s.record.Revision == 0 || strictjson.Decode(v.data, &id) != nil || id.Version != 1 || id.BindingSHA256 != s.binding {
					return nil, errors.New("gateway current policy identity changed")
				}
			}
			continue
		}
		if s.record.Revision == 0 {
			return nil, errors.New("fresh gateway root contains temporary state")
		}
		switch kind {
		case ".policy-":
			var r policyRecord
			if strictjson.Decode(v.data, &r) != nil || r.Version != 1 || r.Revision == 0 || !policyDigestValid(r.SnapshotSHA256) || (r.Revision > s.record.Revision && (s.record.Revision == ^uint64(0) || r.Revision != s.record.Revision+1)) {
				return nil, errors.New("unrecognized gateway temporary policy")
			}
		case ".identity-":
			var id policyIdentity
			if strictjson.Decode(v.data, &id) != nil || id.Version != 1 || id.BindingSHA256 != s.binding {
				return nil, errors.New("unrecognized gateway temporary identity")
			}
		}
		orphans = append(orphans, v)
		if len(orphans) > policyMaxOrphans {
			return nil, errors.New("gateway orphan budget exceeded")
		}
	}
	expected := 1
	if s.record.Revision != 0 {
		expected = 3
	}
	if len(named) != expected || !named["gateway.lock"] || (expected == 3 && (!named["policy.json"] || !named["policy.identity"])) {
		return nil, errors.New("gateway authority inventory incomplete")
	}
	return orphans, nil
}
func (s *policyState) collect() error {
	// Validate the entire inventory before the first unlink. CAS is validated by
	// Commit before entering here. No unknown or partially written file is erased
	// as an automatic repair of authority, nor can a temp authorize a revision.
	orphans, e := s.inventory()
	if e != nil {
		return e
	}
	for _, v := range orphans {
		if e = s.checkDirectory(); e != nil {
			return e
		}
		now, e := s.entry(v.name, policyMaxOrphanBytes)
		if e != nil || !os.SameFile(v.info, now.info) || !bytes.Equal(v.data, now.data) {
			return errors.New("gateway temporary entry changed before collection")
		}
		if e = unix.Unlinkat(int(s.root.Fd()), v.name, 0); e != nil {
			return e
		}
	}
	if len(orphans) > 0 {
		if e = s.root.Sync(); e != nil {
			return e
		}
	}
	return s.checkDirectory()
}
