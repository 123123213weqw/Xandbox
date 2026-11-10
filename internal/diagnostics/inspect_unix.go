//go:build linux || darwin

package diagnostics

import (
	"bytes"
	"path/filepath"
)

// DecodePersistedSnapshot checks an already bounded, privately read immutable
// byte snapshot with the EXACT ordinary committed-window reader. Directory is
// the original canonical daemon directory, not a relocated backup path. This
// pure parser opens/locks/syncs/repairs nothing and proves no operation outcome,
// writer absence or media durability. Uncommitted/staging bytes are not truth.
func DecodePersistedSnapshot(directory string, raw []byte) (Snapshot, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || len(raw) != RingBytes {
		return Snapshot{}, ErrWrite
	}
	r := bytes.NewReader(raw)
	h, e := readHead(r, scopeFor(directory))
	if e != nil {
		return Snapshot{}, e
	}
	records, e := readRecords(r, h)
	if e != nil {
		return Snapshot{}, e
	}
	overwritten := uint64(0)
	if h.seq > RetainedRecords {
		overwritten = h.seq - RetainedRecords
	}
	return Snapshot{Version: 1, ObservedSequence: h.seq, RetainedCapacity: RetainedRecords, Overwritten: overwritten, Records: records}, nil
}
