//go:build linux || darwin

package sandbox

import (
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"golang.org/x/sys/unix"
)

type resultEntry struct {
	mu               sync.Mutex
	reservation      ResultReservation
	sum              [32]byte
	terminal, failed bool
	version          int
	live             bool
}

// FileResultStore retains immutable outcomes independently of VM reclamation.
// The caller MUST hold the original controller's exclusive state lease. A
// partial/unknown scratch fails closed, is preserved and requires recovery; it
// is not silently deleted. Current support is process-crash recovery of fully
// published records, not arbitrary power-loss repair or media attestation.
type FileResultStore struct {
	fdMu        sync.Mutex
	dir         *os.File
	path        string
	identity    os.FileInfo
	mu          sync.Mutex
	entries     map[string]*resultEntry
	tenantBytes map[string]int64
	bytes       int64
	limits      ResultLimits
	sealed      bool
	writers     int
	closed      atomic.Bool
	point       func(string) error // Private TEST cut only; no CLI/environment control.
}

func OpenResultStore(path string, limits ResultLimits) (*FileResultStore, error) {
	if !limits.valid() {
		return nil, ErrInvalid
	}
	path, e := privatefile.EnsureDirectory(path)
	if e != nil {
		return nil, ErrResultUnavailable
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrResultUnavailable
	}
	dir := os.NewFile(uintptr(fd), "result-store")
	info, e := dir.Stat()
	if e != nil {
		dir.Close()
		return nil, ErrResultUnavailable
	}
	s := &FileResultStore{dir: dir, path: path, identity: info, entries: map[string]*resultEntry{}, tenantBytes: map[string]int64{}, limits: limits}
	if e = s.load(); e != nil {
		s.Close()
		return nil, ErrResultUnavailable
	}
	return s, nil
}
func (s *FileResultStore) Close() error {
	s.closed.Store(true)
	s.fdMu.Lock()
	defer s.fdMu.Unlock()
	if s.dir == nil {
		return nil
	}
	e := s.dir.Close()
	s.dir = nil
	return e
}

// Every operation owns its descriptor. Only duplication/close use fdMu;
// pathname/metadata IO never holds it. Close neither waits for per-entry IO
// locks nor closes/reuses an in-flight writer's descriptor. This is not a hard
// kernel syscall deadline guarantee.
func (s *FileResultStore) root() (*os.File, error) {
	s.fdMu.Lock()
	if s.dir == nil || s.closed.Load() {
		s.fdMu.Unlock()
		return nil, ErrResultUnavailable
	}
	duplicate, e := unix.FcntlInt(s.dir.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	s.fdMu.Unlock()
	if e != nil {
		return nil, ErrResultUnavailable
	}
	held := os.NewFile(uintptr(duplicate), "result-operation-pin")
	defer held.Close()
	if e = s.boundDir(held); e != nil {
		return nil, e
	}
	// Unlike dup, openat(.) has an independent directory iteration offset.
	fd, e := unix.Openat(duplicate, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrResultUnavailable
	}
	return os.NewFile(uintptr(fd), "result-operation"), nil
}
func (s *FileResultStore) boundDir(dir *os.File) error {
	if e := s.cut("result-root-before-stat"); e != nil {
		return e
	}
	return s.boundDirNoCut(dir)
}
func (s *FileResultStore) boundDirNoCut(dir *os.File) error {
	info, e := os.Lstat(s.path)
	if e != nil || !os.SameFile(info, s.identity) || !info.IsDir() || info.Mode().Perm() != 0700 {
		return ErrResultUnavailable
	}
	var st unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &st) != nil || st.Mode != unix.S_IFDIR|0700 || st.Uid != uint32(os.Geteuid()) {
		return ErrResultUnavailable
	}
	return nil
}
func resultRead(dir *os.File, name string) ([]byte, error) {
	fd, e := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrResultUnavailable
	}
	f := os.NewFile(uintptr(fd), "retained-result")
	defer f.Close()
	var a, b, c unix.Stat_t
	if unix.Fstat(fd, &a) != nil || a.Mode != unix.S_IFREG|0600 || a.Nlink != 1 || a.Uid != uint32(os.Geteuid()) || a.Size < 1 || a.Size > 2*65_536+16_384 {
		return nil, ErrResultUnavailable
	}
	raw, e := io.ReadAll(io.LimitReader(f, 2*65_536+16_384+1))
	if e != nil || int64(len(raw)) != a.Size {
		return nil, ErrResultUnavailable
	}
	if unix.Fstat(fd, &b) != nil || unix.Fstatat(int(dir.Fd()), name, &c, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameResultStat(a, b) || !sameResultStat(b, c) {
		return nil, ErrResultUnavailable
	}
	return raw, nil
}

// Atime may change because of reads. All write/identity metadata must match.
func sameResultStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func (s *FileResultStore) load() error {
	dir, e := s.root()
	if e != nil {
		return e
	}
	defer dir.Close()
	names, e := dir.Readdirnames(MaxResultRecords + 1)
	if e != nil && e != io.EOF {
		return ErrResultUnavailable
	}
	if len(names) > MaxResultRecords {
		return ErrResultUnavailable
	}
	sort.Strings(names)
	// Validate the COMPLETE namespace before any sync/index publication. No
	// partially trusted prefix is repaired, removed or exposed as results.
	entries := map[string]*resultEntry{}
	totals := map[string]int64{}
	var total int64
	for _, name := range names {
		if len(name) != 37 || name[32:] != ".json" || !tokenPattern.MatchString(name[:32]) {
			return ErrResultUnavailable
		}
		raw, e := resultRead(dir, name)
		if e != nil {
			return e
		}
		r, e := decodeResult(raw)
		if e != nil || r.Reservation.JobID+".json" != name {
			return ErrResultUnavailable
		}
		total += r.Reservation.charge()
		if total > MaxResultBytes {
			return ErrResultUnavailable
		}
		totals[r.Reservation.TenantID] += r.Reservation.charge()
		entries[r.Reservation.JobID] = &resultEntry{reservation: r.Reservation, sum: sha256.Sum256(raw), terminal: r.Result != nil, version: r.Version}
	}
	// Re-enumerate through an independent description; never accept an unknown
	// entry that arrived after the initial complete bounded enumeration.
	after, e := s.root()
	if e != nil {
		return e
	}
	again, e := after.Readdirnames(MaxResultRecords + 1)
	after.Close()
	if e != nil && e != io.EOF {
		return ErrResultUnavailable
	}
	sort.Strings(again)
	if len(again) != len(names) {
		return ErrResultUnavailable
	}
	for n := range names {
		if names[n] != again[n] {
			return ErrResultUnavailable
		}
	}
	// Confirm existing observed files and directory durably BEFORE API exposure,
	// including a prior rename whose directory sync had ambiguous completion.
	for _, name := range names {
		fd, e := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return ErrResultUnavailable
		}
		f := os.NewFile(uintptr(fd), "confirm-result")
		e = f.Sync()
		f.Close()
		if e != nil {
			return ErrResultUnavailable
		}
		raw, e := resultRead(dir, name)
		if e != nil || sha256.Sum256(raw) != entries[name[:32]].sum {
			return ErrResultUnavailable
		}
	}
	parent, e := os.Open(filepath.Dir(s.path))
	if e != nil {
		return ErrResultUnavailable
	}
	e = parent.Sync()
	parent.Close()
	if e != nil {
		return ErrResultUnavailable
	}
	if dir.Sync() != nil {
		return ErrResultUnavailable
	}
	e = s.boundDir(dir)
	if e != nil {
		return e
	}
	s.entries, s.tenantBytes, s.bytes = entries, totals, total
	return nil
}
func (s *FileResultStore) Bind(records []Record) (bool, error) {
	owners := make(map[Ref]Record, len(records))
	for _, r := range records {
		owners[r.Ref] = r
	}
	s.mu.Lock()
	entries := make([]*resultEntry, 0, len(s.entries))
	for _, entry := range s.entries {
		entries = append(entries, entry)
	}
	s.mu.Unlock()
	uncertain := false
	for _, entry := range entries {
		entry.mu.Lock()
		h := entry.reservation
		r, ok := owners[h.Ref]
		bad := !ok || r.TenantID != h.TenantID || r.Limits.MaxOutputBytes != h.MaxOutputBytes
		uncertain = uncertain || !entry.terminal || entry.failed
		entry.mu.Unlock()
		if bad {
			return false, ErrResultUnavailable
		}
	}
	return uncertain, nil
}

func (s *FileResultStore) cut(stage string) error {
	if s.point != nil {
		return s.point(stage)
	}
	return nil
}
func (s *FileResultStore) write(dir *os.File, r resultEnvelope, previous *resultEntry, stage string) error {
	raw := resultBytes(r)
	if _, e := decodeResult(raw); e != nil {
		return e
	}
	name := r.Reservation.JobID + ".json"
	tmp := "." + r.Reservation.JobID + ".next"
	if previous == nil {
		var st unix.Stat_t
		if e := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); e != unix.ENOENT {
			return ErrResultUnavailable
		}
	} else {
		before, e := resultRead(dir, name)
		if e != nil || sha256.Sum256(before) != previous.sum {
			return ErrResultUnavailable
		}
	}
	fd, e := unix.Openat(int(dir.Fd()), tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrResultUnavailable
	}
	f := os.NewFile(uintptr(fd), "result-publish")
	defer f.Close()
	if n, e := f.Write(raw); e != nil || n != len(raw) {
		return ErrResultUnavailable
	}
	if e = s.cut(stage + "-written"); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return ErrResultUnavailable
	}
	if e = s.cut(stage + "-synced"); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return ErrResultUnavailable
	}
	e = s.boundDir(dir)
	if e != nil {
		return e
	}
	if previous == nil {
		var st unix.Stat_t
		if unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
			return ErrResultUnavailable
		}
	} else {
		before, e := resultRead(dir, name)
		if e != nil || sha256.Sum256(before) != previous.sum {
			return ErrResultUnavailable
		}
	}
	if e = unix.Renameat(int(dir.Fd()), tmp, int(dir.Fd()), name); e != nil {
		return ErrResultUnavailable
	}
	if e = s.cut(stage + "-renamed"); e != nil {
		return e
	}
	if e = dir.Sync(); e != nil {
		return ErrResultUnavailable
	}
	if e = s.cut(stage + "-durable"); e != nil {
		return e
	}
	e = s.boundDir(dir)
	if e != nil {
		return e
	}
	current, e := resultRead(dir, name)
	if e != nil || sha256.Sum256(current) != sha256.Sum256(raw) {
		return ErrResultUnavailable
	}
	return nil
}

// The seal rejects new writers and refuses while ANY previously accepted
// writer is active, including one waiting for an entry lock. No IO holds mu.
func (s *FileResultStore) beginResultWrite() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sealed || s.closed.Load() {
		return ErrResultUnavailable
	}
	s.writers++
	return nil
}
func (s *FileResultStore) endResultWrite() { s.mu.Lock(); s.writers--; s.mu.Unlock() }
func (s *FileResultStore) Reserve(h ResultReservation) error {
	h.StartedAt = h.StartedAt.UTC()
	if !h.valid() {
		return ErrInvalid
	}
	if e := s.beginResultWrite(); e != nil {
		return e
	}
	defer s.endResultWrite()
	entry := &resultEntry{reservation: h, version: resultVersion}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	s.mu.Lock()
	if _, ok := s.entries[h.JobID]; ok {
		s.mu.Unlock()
		return ErrResultUnavailable
	}
	if len(s.entries) >= s.limits.Records || h.charge() > s.limits.Bytes-s.bytes || h.charge() > s.limits.TenantBytes-s.tenantBytes[h.TenantID] {
		s.mu.Unlock()
		return ErrResultCapacity
	}
	// Reserve BEFORE IO. Failure/ambiguous publication cannot release this slot
	// or let another tenant consume the same bytes in this live process.
	s.entries[h.JobID] = entry
	s.bytes += h.charge()
	s.tenantBytes[h.TenantID] += h.charge()
	s.mu.Unlock()
	dir, e := s.root()
	if e != nil {
		entry.failed = true
		return ErrResultUnavailable
	}
	defer dir.Close()
	r := resultEnvelope{Version: resultVersion, Reservation: h}
	if e = s.write(dir, r, nil, "result-reserve"); e != nil {
		entry.failed = true
		return ErrResultUnavailable
	}
	entry.sum = sha256.Sum256(resultBytes(r))
	entry.live = true
	return nil
}
func (s *FileResultStore) entry(id string) *resultEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.entries[id]
}
func (s *FileResultStore) Complete(j Job) error {
	if e := s.beginResultWrite(); e != nil {
		return e
	}
	defer s.endResultWrite()
	entry := s.entry(j.ID)
	if entry == nil {
		return ErrResultUnavailable
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	h := entry.reservation
	if entry.failed || entry.version != resultVersion || (!entry.terminal && !entry.live) || j.Ref != h.Ref || !j.StartedAt.Equal(h.StartedAt) {
		return ErrResultUnavailable
	}
	r := resultEnvelope{Version: resultVersion, Reservation: h, Result: &retainedOutput{Status: j.Status, FinishedAt: j.FinishedAt, Stdout: []byte(j.Output.Stdout), Stderr: []byte(j.Output.Stderr), ExitCode: j.Output.ExitCode, Truncated: j.Output.Truncated, Error: []byte(boundedLedgerError(j.Error))}}
	r.SHA256 = resultDigest(r)
	if !r.valid() {
		return ErrInvalid
	}
	raw := resultBytes(r)
	if entry.terminal {
		if entry.sum != sha256.Sum256(raw) {
			return ErrResultUnavailable
		}
		dir, e := s.root()
		if e != nil {
			return e
		}
		defer dir.Close()
		observed, e := resultRead(dir, j.ID+".json")
		if e != nil || sha256.Sum256(observed) != entry.sum {
			return ErrResultUnavailable
		}
		return nil
	}
	dir, e := s.root()
	if e != nil {
		return ErrResultUnavailable
	}
	defer dir.Close()
	if e = s.write(dir, r, entry, "result-complete"); e != nil {
		entry.failed = true
		return ErrResultUnavailable
	}
	entry.sum = sha256.Sum256(raw)
	entry.terminal = true
	return nil
}
func (s *FileResultStore) Get(ref Ref, tenant, id string) (Job, error) {
	entry := s.entry(id)
	if entry == nil {
		return Job{}, ErrNotFound
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.reservation.Ref != ref || entry.reservation.TenantID != tenant {
		return Job{}, ErrNotFound
	}
	if entry.failed {
		return Job{}, ErrResultUnavailable
	}
	dir, e := s.root()
	if e != nil {
		return Job{}, ErrResultUnavailable
	}
	defer dir.Close()
	raw, e := resultRead(dir, id+".json")
	if e != nil || sha256.Sum256(raw) != entry.sum {
		return Job{}, ErrResultUnavailable
	}
	r, e := decodeResult(raw)
	if e != nil || r.Reservation != entry.reservation {
		return Job{}, ErrResultUnavailable
	}
	e = s.boundDir(dir)
	if e != nil {
		return Job{}, e
	}
	return r.job(), nil
}
