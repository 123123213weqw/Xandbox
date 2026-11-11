//go:build linux || darwin

package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"sort"

	"golang.org/x/sys/unix"
)

func (s *FileResultStore) resultsAlive() bool { return s != nil && !s.closed.Load() }

type sealedResultEntry struct {
	header ResultReservation
	sum    [32]byte
}
type resultFileIdentity struct {
	Device, Inode, Links uint64
	Mode, UID, GID       uint32
	Bytes                int64
	Modified, Changed    unix.Timespec
}

func resultIdentity(v unix.Stat_t) resultFileIdentity {
	return resultFileIdentity{uint64(v.Dev), v.Ino, uint64(v.Nlink), uint32(v.Mode), v.Uid, v.Gid, v.Size, v.Mtim, v.Ctim}
}

type resultSnapshot struct {
	observation ResultClosureObservation
	footprint   string
}

func (s *FileResultStore) sealResults(ctx context.Context, records []Record) (ResultClosureObservation, error) {
	var zero ResultClosureObservation
	if e := ctx.Err(); e != nil {
		return zero, e
	}
	owners := make(map[Ref]Record, len(records))
	ids := make(map[string]bool, len(records))
	for _, r := range records {
		if !validRef(r.Ref) || ids[r.ID] || r.State != Destroyed {
			return zero, ErrResultUnavailable
		}
		ids[r.ID] = true
		owners[r.Ref] = r
	}
	s.mu.Lock()
	s.sealed = true
	if s.writers != 0 || s.closed.Load() {
		s.mu.Unlock()
		return zero, ErrResultUnavailable
	}
	entries := make(map[string]sealedResultEntry, len(s.entries))
	var reserved int64
	for id, entry := range s.entries {
		// writers==0 under mu happens-after every entry mutation; the seal
		// rejects all later writers. Readers never mutate entries, so their
		// potentially slow IO must not hold up or veto this immutable copy.
		h := entry.reservation
		r, ok := owners[h.Ref]
		bad := !ok || r.TenantID != h.TenantID || r.Limits.MaxOutputBytes != h.MaxOutputBytes || entry.failed || !entry.terminal || entry.version != resultVersion
		entries[id] = sealedResultEntry{h, entry.sum}
		reserved += h.charge()
		if bad {
			s.mu.Unlock()
			return zero, ErrResultUnavailable
		}
	}
	if reserved != s.bytes || reserved > MaxResultBytes {
		s.mu.Unlock()
		return zero, ErrResultUnavailable
	}
	s.mu.Unlock()
	dir, e := s.root()
	if e != nil {
		return zero, e
	}
	defer dir.Close()
	before, e := s.resultSnapshot(ctx, dir, entries, reserved)
	if e != nil {
		return zero, e
	}
	if e = s.cut("result-seal-after-first"); e != nil {
		return zero, e
	}
	after, e := s.resultSnapshot(ctx, dir, entries, reserved)
	if e != nil {
		return zero, e
	}
	if before != after || !after.observation.Valid() {
		return zero, ErrResultUnavailable
	}
	// NO callbacks after the final full scan. This checks only the original FD
	// and current path, not another constructor/sync/writer or cached count.
	if e = s.boundDirNoCut(dir); e != nil {
		return zero, e
	}
	if e = ctx.Err(); e != nil {
		return zero, e
	}
	if !s.resultsAlive() {
		return zero, ErrResultUnavailable
	}
	return after.observation, nil
}
func resultNames(dir *os.File) ([]string, error) {
	fd, e := unix.Openat(int(dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrResultUnavailable
	}
	f := os.NewFile(uintptr(fd), "result-namespace")
	defer f.Close()
	names, e := f.Readdirnames(MaxResultRecords + 1)
	if e != nil && e != io.EOF {
		return nil, ErrResultUnavailable
	}
	if len(names) > MaxResultRecords {
		return nil, ErrResultUnavailable
	}
	sort.Strings(names)
	return names, nil
}
func (s *FileResultStore) resultSnapshot(ctx context.Context, dir *os.File, expected map[string]sealedResultEntry, reserved int64) (resultSnapshot, error) {
	var zero resultSnapshot
	var rootBefore, rootAfter unix.Stat_t
	if e := ctx.Err(); e != nil {
		return zero, e
	}
	if unix.Fstat(int(dir.Fd()), &rootBefore) != nil {
		return zero, ErrResultUnavailable
	}
	names, e := resultNames(dir)
	if e != nil || len(names) != len(expected) {
		return zero, ErrResultUnavailable
	}
	want := make([]string, 0, len(expected))
	for id := range expected {
		want = append(want, id+".json")
	}
	sort.Strings(want)
	for n := range names {
		if names[n] != want[n] {
			return zero, ErrResultUnavailable
		}
	}
	content, footprint := sha256.New(), sha256.New()
	content.Write([]byte("xandbox-results-closure-v2\n"))
	footprint.Write([]byte("xandbox-results-footprint-v2\n"))
	enc := json.NewEncoder(footprint)
	if e = enc.Encode(resultIdentity(rootBefore)); e != nil {
		return zero, e
	}
	var total int64
	for _, name := range names {
		if e = ctx.Err(); e != nil {
			return zero, e
		}
		entry := expected[name[:32]]
		var a, b unix.Stat_t
		if unix.Fstatat(int(dir.Fd()), name, &a, unix.AT_SYMLINK_NOFOLLOW) != nil || a.Dev != rootBefore.Dev {
			return zero, ErrResultUnavailable
		}
		raw, e := resultRead(dir, name)
		if e != nil {
			return zero, e
		}
		digest := sha256.Sum256(raw)
		if digest != entry.sum {
			return zero, ErrResultUnavailable
		}
		row, e := decodeResult(raw)
		if e != nil || row.Version != resultVersion || row.Result == nil || row.Reservation != entry.header {
			return zero, ErrResultUnavailable
		}
		if unix.Fstatat(int(dir.Fd()), name, &b, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameResultStat(a, b) {
			return zero, ErrResultUnavailable
		}
		total += int64(len(raw))
		if total > reserved {
			return zero, ErrResultUnavailable
		}
		// Ordered canonical framing binds the actual whole raw record, not merely
		// record count, Output.ExitCode, its checksum field or a caller report.
		leaf := struct{ Name, SHA256 string }{name, hex.EncodeToString(digest[:])}
		if e = json.NewEncoder(content).Encode(leaf); e != nil {
			return zero, e
		}
		if e = enc.Encode(struct {
			Name   string
			Entry  resultFileIdentity
			SHA256 string
		}{name, resultIdentity(b), leaf.SHA256}); e != nil {
			return zero, e
		}
	}
	again, e := resultNames(dir)
	if e != nil || len(again) != len(names) {
		return zero, ErrResultUnavailable
	}
	for n := range names {
		if names[n] != again[n] {
			return zero, ErrResultUnavailable
		}
	}
	if unix.Fstat(int(dir.Fd()), &rootAfter) != nil || !sameResultStat(rootBefore, rootAfter) {
		return zero, ErrResultUnavailable
	}
	return resultSnapshot{observation: ResultClosureObservation{Version: 2, Records: len(names), Bytes: total, ReservedBytes: reserved, RecordsSHA256: hex.EncodeToString(content.Sum(nil))}, footprint: hex.EncodeToString(footprint.Sum(nil))}, nil
}
