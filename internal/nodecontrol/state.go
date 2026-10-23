// Package nodecontrol implements the private, host-UID node admission control
// plane. Tenant credentials confer no authority here. It is not a backup or
// execution-stop certificate and never changes immutable backend budgets.
package nodecontrol

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

const ModeOpen = "open"
const ModeDrained = "drained"
const StateLimit = 4096

var hexID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var tempName = regexp.MustCompile(`^\.(state|identity)-[0-9]+$`)

type State struct {
	Version              int    `json:"version"`
	Epoch                string `json:"epoch"`
	Revision             uint64 `json:"revision"`
	Mode                 string `json:"mode"`
	LastRequestID        string `json:"last_request_id"`
	LastExpectedRevision uint64 `json:"last_expected_revision"`
}

func (s State) valid() bool {
	if s.Version != 1 || !hexID.MatchString(s.Epoch) || s.Revision == 0 || (s.Mode != ModeOpen && s.Mode != ModeDrained) {
		return false
	}
	if s.Revision == math.MaxUint64 && s.Mode != ModeDrained {
		return false
	}
	if s.Revision == 1 {
		return s.LastRequestID == "" && s.LastExpectedRevision == 0
	}
	return hexID.MatchString(s.LastRequestID) && s.LastExpectedRevision == s.Revision-1
}

type Store interface {
	Load() (State, error)
	Save(previous, next State) error
}

type FileStore struct {
	root, dir         string
	rootInfo, dirInfo os.FileInfo
	epoch             string
}

// OpenStore requires the daemon's exclusive controller.lock. Fresh, genuinely
// unused roots start open for compatibility. Missing state on a used root
// starts DRAINED with a new epoch, never silently recreating an open authority.
// Once admission.identity exists, missing/mismatched state is always an error.
func OpenStore(stateDir string) (*FileStore, error) {
	root, e := privatefile.ExistingDirectory(stateDir)
	if e != nil {
		return nil, e
	}
	_, identityErr := os.Lstat(filepath.Join(root, "admission.identity"))
	if identityErr != nil && !os.IsNotExist(identityErr) {
		return nil, identityErr
	}
	if identityErr == nil {
		if _, e = privatefile.ExistingDirectory(filepath.Join(root, "admission")); e != nil {
			return nil, e
		}
	}
	dir, e := privatefile.EnsureDirectory(filepath.Join(root, "admission"))
	if e != nil {
		return nil, e
	}
	f := &FileStore{root: root, dir: dir}
	f.rootInfo, e = os.Lstat(root)
	if e != nil {
		return nil, e
	}
	f.dirInfo, e = os.Lstat(dir)
	if e != nil {
		return nil, e
	}
	state, e := f.readState()
	if os.IsNotExist(e) {
		if identityErr == nil {
			return nil, errors.New("admission state missing for bound epoch")
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		if len(entries) != 0 {
			return nil, errors.New("uncommitted admission initialization requires recovery")
		}
		used, err := usedRoot(root)
		if err != nil {
			return nil, err
		}
		epoch, err := NewRequestID()
		if err != nil {
			return nil, err
		}
		mode := ModeOpen
		if used {
			mode = ModeDrained
		}
		state = State{Version: 1, Epoch: epoch, Revision: 1, Mode: mode}
		data, _ := json.Marshal(state)
		if err = f.writeAtomic(filepath.Join(dir, "state.json"), ".state-", data); err != nil {
			return nil, err
		}
	} else if e != nil {
		return nil, e
	}
	if identityErr == nil {
		b, err := privateRead(filepath.Join(root, "admission.identity"))
		if err != nil {
			return nil, err
		}
		var id struct {
			Version int    `json:"version"`
			Epoch   string `json:"epoch"`
		}
		if err = strictjson.Decode(b, &id); err != nil || id.Version != 1 || id.Epoch != state.Epoch {
			return nil, errors.New("admission epoch identity mismatch")
		}
	} else {
		b, _ := json.Marshal(struct {
			Version int    `json:"version"`
			Epoch   string `json:"epoch"`
		}{1, state.Epoch})
		if e = f.writeAtomic(filepath.Join(root, "admission.identity"), ".identity-", b); e != nil {
			return nil, e
		}
	}
	f.epoch = state.Epoch
	if _, e = f.Load(); e != nil {
		return nil, e
	}
	return f, nil
}
func NewRequestID() (string, error) {
	b := make([]byte, 16)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func usedRoot(root string) (bool, error) {
	for _, name := range []string{"sessions", "instances", "firecracker"} {
		if _, e := os.Lstat(filepath.Join(root, name)); e == nil {
			return true, nil
		} else if !os.IsNotExist(e) {
			return false, e
		}
	}
	entries, e := os.ReadDir(filepath.Join(root, "ledger"))
	if os.IsNotExist(e) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	return len(entries) > 0, nil
}
func privateRead(path string) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !privateSingleFile(info) {
		return nil, errors.New("control state must be a single-link caller-owned0600 regular file")
	}
	return privatefile.Read(path, StateLimit)
}
func (f *FileStore) directories() error {
	for name, info := range map[string]os.FileInfo{f.root: f.rootInfo, f.dir: f.dirInfo} {
		if _, e := privatefile.ExistingDirectory(name); e != nil {
			return e
		}
		got, e := os.Lstat(name)
		if e != nil {
			return e
		}
		if !os.SameFile(info, got) {
			return errors.New("admission directory identity changed")
		}
	}
	return nil
}
func (f *FileStore) readState() (State, error) {
	var out State
	entries, e := os.ReadDir(f.dir)
	if e != nil {
		return out, e
	}
	if len(entries) > 33 {
		return out, errors.New("admission directory bound exceeded")
	}
	for _, entry := range entries {
		if entry.Name() != "state.json" && !tempName.MatchString(entry.Name()) {
			return out, errors.New("unknown admission directory entry")
		}
		if _, e = privateRead(filepath.Join(f.dir, entry.Name())); e != nil {
			return out, e
		}
	}
	b, e := privateRead(filepath.Join(f.dir, "state.json"))
	if e != nil {
		return out, e
	}
	if e = strictjson.Decode(b, &out); e != nil {
		return out, e
	}
	if !out.valid() {
		return out, errors.New("invalid admission state")
	}
	return out, nil
}
func (f *FileStore) Load() (State, error) {
	if e := f.directories(); e != nil {
		return State{}, e
	}
	s, e := f.readState()
	if e != nil {
		return State{}, e
	}
	if s.Epoch != f.epoch {
		return State{}, errors.New("admission epoch changed")
	}
	b, e := privateRead(filepath.Join(f.root, "admission.identity"))
	if e != nil {
		return State{}, e
	}
	var id struct {
		Version int    `json:"version"`
		Epoch   string `json:"epoch"`
	}
	if e = strictjson.Decode(b, &id); e != nil || id.Version != 1 || id.Epoch != f.epoch {
		return State{}, errors.New("admission identity changed")
	}
	return s, nil
}
func (f *FileStore) Save(previous, next State) error {
	if !previous.valid() || !next.valid() || previous.Revision == math.MaxUint64 || next.Epoch != previous.Epoch || next.Revision != previous.Revision+1 || next.LastExpectedRevision != previous.Revision {
		return errors.New("invalid admission transition")
	}
	actual, e := f.Load()
	if e != nil {
		return e
	}
	if actual != previous {
		return errors.New("durable admission state changed outside controller")
	}
	b, e := json.Marshal(next)
	if e != nil {
		return e
	}
	return f.writeAtomic(filepath.Join(f.dir, "state.json"), ".state-", b)
}
func (f *FileStore) writeAtomic(target, prefix string, data []byte) error {
	if len(data) > StateLimit {
		return errors.New("control state too large")
	}
	if e := f.directories(); e != nil {
		return e
	}
	t, e := os.CreateTemp(f.dir, prefix+"*")
	if e != nil {
		return e
	}
	defer os.Remove(t.Name())
	if _, e = t.Write(data); e != nil {
		t.Close()
		return e
	}
	if e = t.Sync(); e != nil {
		t.Close()
		return e
	}
	if e = t.Close(); e != nil {
		return e
	}
	if e = os.Rename(t.Name(), target); e != nil {
		return e
	}
	for _, dir := range []string{f.dir, f.root} {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		err = d.Sync()
		closeErr := d.Close()
		if err != nil || closeErr != nil {
			return fmt.Errorf("sync control directory: %w", errors.Join(err, closeErr))
		}
	}
	return f.directories()
}
