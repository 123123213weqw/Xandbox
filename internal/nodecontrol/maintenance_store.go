package nodecontrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

const MaintenanceName = "maintenance.json"
const maintenanceScratch = ".maintenance-next"
const maintenanceIdentity = "maintenance.identity"

func maintenanceBytes(r MaintenanceRecord) []byte { b, _ := json.Marshal(r); return append(b, '\n') }
func maintenanceHash(r MaintenanceRecord) string {
	sum := sha256.Sum256(maintenanceBytes(r))
	return hex.EncodeToString(sum[:])
}
func decodeMaintenance(b []byte) (MaintenanceRecord, error) {
	var r MaintenanceRecord
	if len(b) == 0 || len(b) > StateLimit || strictjson.Decode(b, &r) != nil || !r.Valid() || !bytes.Equal(b, maintenanceBytes(r)) {
		return r, ErrInvalid
	}
	return r, nil
}
func (f *FileStore) maintenancePoint(at string) error {
	if f.maintenanceHook != nil {
		return f.maintenanceHook(at)
	}
	return nil
}

// Prefix reads permit an empty known scratch ONLY when an already accepted
// exact request supplies its complete input. Restart never guesses a lost owner.
func readMaintenancePrefix(path string) ([]byte, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !privateSingleFile(st) || st.Size() > StateLimit {
		return nil, ErrInvalid
	}
	in, e := os.OpenFile(path, os.O_RDONLY|maintenanceNoFollow, 0)
	if e != nil {
		return nil, e
	}
	defer in.Close()
	opened, e := in.Stat()
	if e != nil || !os.SameFile(st, opened) {
		return nil, ErrInvalid
	}
	b, e := io.ReadAll(io.LimitReader(in, StateLimit+1))
	if e != nil {
		return nil, e
	}
	current, e := os.Lstat(path)
	if e != nil || !privateSingleFile(current) || !os.SameFile(opened, current) || int64(len(b)) != current.Size() {
		return nil, ErrInvalid
	}
	return b, nil
}

// Validate complete admission inventory, and the independent root binding.
// Nothing is deleted, adopted, initialized or synced by this reader.
func (f *FileStore) readMaintenance(expected *MaintenanceRecord) (*MaintenanceRecord, bool, error) {
	es, e := os.ReadDir(f.dir)
	if e != nil {
		return nil, false, e
	}
	if len(es) > 33 {
		return nil, false, ErrInvalid
	}
	final, scratch := false, false
	for _, v := range es {
		switch v.Name() {
		case MaintenanceName:
			final = true
		case maintenanceScratch:
			scratch = true
		default:
			if v.Name() != "state.json" && !tempName.MatchString(v.Name()) {
				return nil, false, ErrInvalid
			}
			if _, e = privateRead(filepath.Join(f.dir, v.Name())); e != nil {
				return nil, false, e
			}
		}
	}
	if final && scratch {
		return nil, false, ErrConflict
	}
	var r *MaintenanceRecord
	if final || scratch {
		name := MaintenanceName
		if scratch {
			name = maintenanceScratch
		}
		b, e := readMaintenancePrefix(filepath.Join(f.dir, name))
		if e != nil {
			return nil, false, e
		}
		if expected != nil {
			want := maintenanceBytes(*expected)
			if len(b) > len(want) || !bytes.HasPrefix(want, b) || final && !bytes.Equal(b, want) {
				return nil, false, ErrConflict
			}
			copy := *expected
			r = &copy
		} else {
			copy, e := decodeMaintenance(b)
			if e != nil {
				return nil, false, e
			}
			r = &copy
		}
	}
	b, e := privateRead(filepath.Join(f.root, maintenanceIdentity))
	if e == nil {
		var anchor struct {
			Version      int    `json:"version"`
			RecordSHA256 string `json:"record_sha256"`
		}
		if strictjson.Decode(b, &anchor) != nil || anchor.Version != 1 || r == nil || anchor.RecordSHA256 != maintenanceHash(*r) {
			return nil, false, ErrConflict
		}
	} else if !os.IsNotExist(e) {
		return nil, false, e
	}
	return r, scratch, nil
}
func (f *FileStore) LoadMaintenance() (*MaintenanceRecord, error) {
	if _, e := f.Load(); e != nil {
		return nil, e
	}
	r, _, e := f.readMaintenance(nil)
	return r, e
}

// Caller holds original state ownership + Controller.serial. Finish only an
// exact immutable fence/prefix and confirm both directory barriers BEFORE CAS.
// No release/removal or old admission-state restoration is exposed.
func (f *FileStore) EnsureMaintenance(r MaintenanceRecord) error {
	if !r.Valid() {
		return ErrInvalid
	}
	if e := f.directories(); e != nil {
		return e
	}
	existing, scratch, e := f.readMaintenance(&r)
	if e != nil {
		return e
	}
	s, e := f.readStateFile()
	if e != nil {
		return e
	}
	if e = f.verifyEpoch(s); e != nil {
		return e
	}
	if s != r.Before && s != r.After() {
		return ErrConflict
	}
	if existing == nil && s != r.Before {
		return ErrConflict
	}
	if existing == nil || scratch {
		path := filepath.Join(f.dir, maintenanceScratch)
		flags := os.O_RDWR | maintenanceNoFollow
		if existing == nil {
			flags |= os.O_CREATE | os.O_EXCL
		}
		file, e := os.OpenFile(path, flags, 0600)
		if e != nil {
			return e
		}
		defer file.Close()
		st, e := file.Stat()
		if e != nil || !privateSingleFile(st) {
			return ErrInvalid
		}
		if e = f.maintenancePoint("maintenance-scratch-created"); e != nil {
			return e
		}
		prefix, e := readMaintenancePrefix(path)
		if e != nil {
			return e
		}
		want := maintenanceBytes(r)
		linked, e := os.Lstat(path)
		if e != nil || !os.SameFile(st, linked) || !bytes.HasPrefix(want, prefix) {
			return ErrConflict
		}
		if _, e = file.Seek(int64(len(prefix)), 0); e != nil {
			return e
		}
		if n, e := file.Write(want[len(prefix):]); e != nil {
			return e
		} else if n != len(want)-len(prefix) {
			return io.ErrShortWrite
		}
		if e = f.maintenancePoint("maintenance-scratch-written"); e != nil {
			return e
		}
		if e = file.Sync(); e != nil {
			return e
		}
		if e = f.maintenancePoint("maintenance-scratch-synced"); e != nil {
			return e
		}
		if e = file.Close(); e != nil {
			return e
		}
		if e = os.Rename(path, filepath.Join(f.dir, MaintenanceName)); e != nil {
			return e
		}
		if e = f.maintenancePoint("maintenance-fence-renamed"); e != nil {
			return e
		}
	}
	for n, dir := range []string{f.dir, f.root} {
		fd, e := os.Open(dir)
		if e != nil {
			return e
		}
		e = fd.Sync()
		closeErr := fd.Close()
		if e != nil || closeErr != nil {
			return errors.Join(e, closeErr)
		}
		at := "maintenance-fence-dir-synced"
		if n == 1 {
			at = "maintenance-fence-root-synced"
		}
		if e = f.maintenancePoint(at); e != nil {
			return e
		}
	}
	if e = f.maintenancePoint("maintenance-before-identity"); e != nil {
		return e
	}
	anchor, _ := json.Marshal(struct {
		Version      int    `json:"version"`
		RecordSHA256 string `json:"record_sha256"`
	}{1, maintenanceHash(r)})
	path := filepath.Join(f.root, maintenanceIdentity)
	current, e := privateRead(path)
	if os.IsNotExist(e) {
		if e = f.writeAtomic(path, ".identity-", anchor); e != nil {
			return e
		}
	} else if e != nil {
		return e
	} else if !bytes.Equal(current, anchor) {
		return ErrConflict
	}
	if e = f.maintenancePoint("maintenance-after-identity"); e != nil {
		return e
	}
	if e = f.directories(); e != nil {
		return e
	}
	got, _, e := f.readMaintenance(nil)
	if e != nil {
		return e
	}
	if got == nil || *got != r {
		return ErrConflict
	}
	return nil
}
