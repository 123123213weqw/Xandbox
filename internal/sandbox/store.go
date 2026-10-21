package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var tokenPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func validRef(ref Ref) bool {
	return tokenPattern.MatchString(ref.ID) && tokenPattern.MatchString(ref.Generation)
}

// FileStore is a single-controller ledger: fsync(file), rename, fsync(directory).
// Do not run multiple controllers against the same state directory.
type FileStore struct{ dir string }

func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &FileStore{dir: dir}, nil
}

func (s *FileStore) Save(r Record) error {
	if !validRef(r.Ref) {
		return fmt.Errorf("%w: invalid ledger identity", ErrInvalid)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".record-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(s.dir, r.ID+".json")); err != nil {
		return err
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *FileStore) Load() ([]Record, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var records []Record
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("ledger entry is not a regular file: %s", entry.Name())
		}
		data, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var r Record
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("corrupt ledger %s: %w", entry.Name(), err)
		}
		if !validRef(r.Ref) || entry.Name() != r.ID+".json" || !knownState(r.State) {
			return nil, fmt.Errorf("invalid ledger %s", entry.Name())
		}
		records = append(records, r)
	}
	return records, nil
}

func knownState(s State) bool {
	switch s {
	case Creating, Ready, Stopping, Stopped, Reclaiming, Destroyed:
		return true
	default:
		return false
	}
}
