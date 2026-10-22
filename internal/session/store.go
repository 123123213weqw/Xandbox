package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

const maxFileBytes = 128 << 10

var idPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var tempPattern = regexp.MustCompile(`^\.session-[0-9]+$`)

type envelope struct {
	Version int     `json:"version"`
	Record  *Record `json:"record"`
}

func validRef(ref sandbox.Ref) bool {
	return idPattern.MatchString(ref.ID) && idPattern.MatchString(ref.Generation)
}
func zeroRef(ref sandbox.Ref) bool     { return ref == (sandbox.Ref{}) }
func optionalRef(ref sandbox.Ref) bool { return zeroRef(ref) || validRef(ref) }

func validate(r Record) error {
	if !idPattern.MatchString(r.ID) || !(sandbox.Owner{TenantID: r.TenantID, MaxInstances: 1}).Valid() || !hashPattern.MatchString(r.CreateKeyHash) || !hashPattern.MatchString(r.CreateSpecHash) || r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() || len(r.Attempts) < 1 || len(r.Attempts) > MaxHistory || !optionalRef(r.Current) {
		return errors.New("invalid session identity/metadata")
	}
	switch r.State {
	case Creating, Active, Preparing, Prepared, Closed:
	default:
		return errors.New("unknown session state")
	}
	if r.Revision > MaxHistory || (r.Revision == 0) != zeroRef(r.Current) || (r.State == Active && r.Revision == 0) {
		return errors.New("invalid session binding")
	}
	keys := map[string]bool{}
	targets := map[sandbox.Ref]bool{}
	var revision uint64
	var current sandbox.Ref
	for n, a := range r.Attempts {
		if !hashPattern.MatchString(a.KeyHash) || !hashPattern.MatchString(a.SpecHash) || keys[a.KeyHash] || !optionalRef(a.From) || !optionalRef(a.Target) || a.StartedAt.IsZero() || a.ExpectedRevision > MaxHistory || a.ResultRevision != a.ExpectedRevision+1 {
			return errors.New("invalid session attempt")
		}
		keys[a.KeyHash] = true
		if a.ExpectedRevision != revision || a.From != current || (n > 0 && a.ExpectedRevision == 0) {
			return errors.New("session history is not a revision chain")
		}
		if !zeroRef(a.Target) {
			if a.Target == a.From || targets[a.Target] {
				return errors.New("session target reused")
			}
			targets[a.Target] = true
		}
		if (a.ExpectedRevision == 0) != zeroRef(a.From) {
			return errors.New("invalid previous binding")
		}
		switch a.State {
		case Preparing:
			if n != len(r.Attempts)-1 {
				return errors.New("unfinished nonfinal session attempt")
			}
			if !zeroRef(a.Target) {
				return errors.New("preparing attempt has durable target")
			}
		case Prepared:
			if n != len(r.Attempts)-1 {
				return errors.New("unfinished nonfinal session attempt")
			}
			if !validRef(a.Target) || a.ReadyAt.IsZero() {
				return errors.New("prepared attempt missing target")
			}
		case "COMMITTED":
			if !validRef(a.Target) || a.ReadyAt.IsZero() || a.FencedAt.IsZero() || a.CommitStartedAt.IsZero() {
				return errors.New("incomplete committed attempt")
			}
			revision, current = a.ResultRevision, a.Target
		case "FAILED":
			// A failed final write can have consumed the new revision without
			// publishing it. It is terminal/fenced, never a route to resurrect.
			if n == len(r.Attempts)-1 && r.State == Closed && !a.FencedAt.IsZero() && r.Revision == a.ResultRevision && r.Current == a.Target {
				revision, current = a.ResultRevision, a.Target
			}
		default:
			return errors.New("unknown attempt state")
		}
		if n == 0 && (a.KeyHash != r.CreateKeyHash || a.SpecHash != r.CreateSpecHash || a.ExpectedRevision != 0) {
			return errors.New("invalid initial attempt")
		}
		for _, v := range []float64{a.Timings.TotalMS, a.Timings.CandidateReadyMS, a.Timings.AdmissionRevokedMS, a.Timings.FenceToCommitMS} {
			if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
				return errors.New("invalid session timing")
			}
		}
	}
	if r.Revision != revision || r.Current != current {
		return errors.New("session current disagrees with history")
	}
	return nil
}

// FileStore shares the daemon's exclusive controller.lock. Different sessions'
// writes may run concurrently; Broker serializes one session's journal writes.
type FileStore struct{ dir string }

func NewFileStore(dir string) (*FileStore, error) {
	dir, e := privatefile.EnsureDirectory(dir)
	if e != nil {
		return nil, e
	}
	return &FileStore{dir: dir}, nil
}
func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (s *FileStore) Save(r Record) error {
	if e := validate(r); e != nil {
		return e
	}
	data, e := json.MarshalIndent(envelope{Version: 1, Record: &r}, "", "  ")
	if e != nil {
		return e
	}
	data = append(data, '\n')
	if len(data) > maxFileBytes {
		return errors.New("session record byte bound exceeded")
	}
	f, e := os.CreateTemp(s.dir, ".session-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), filepath.Join(s.dir, r.ID+".json")); e != nil {
		return e
	}
	return syncDir(s.dir)
}
func (s *FileStore) Load() ([]Record, error) {
	dir, e := os.Open(s.dir)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	var rows []Record
	var temps []string
	seen := map[string]bool{}
	count := 0
	for {
		entries, readErr := dir.ReadDir(128)
		if readErr != nil && readErr != io.EOF {
			return nil, readErr
		}
		for _, entry := range entries {
			count++
			if count > 2*MaxRecords+1024 {
				return nil, errors.New("session directory entry bound exceeded")
			}
			if !entry.Type().IsRegular() {
				return nil, errors.New("session entry is not regular")
			}
			name := entry.Name()
			path := filepath.Join(s.dir, name)
			if tempPattern.MatchString(name) {
				temps = append(temps, path)
				continue
			}
			if len(name) != 37 || !idPattern.MatchString(name[:32]) || name[32:] != ".json" || len(rows) >= MaxRecords {
				return nil, errors.New("invalid session entry or hard capacity")
			}
			data, e := privatefile.Read(path, maxFileBytes)
			if e != nil {
				return nil, e
			}
			r, e := decodeRecord(data)
			if e != nil {
				return nil, e
			}
			if name != r.ID+".json" {
				return nil, errors.New("session filename identity mismatch")
			}
			key := r.TenantID + "\x00" + r.CreateKeyHash
			if seen[key] {
				return nil, fmt.Errorf("duplicate session key")
			}
			seen[key] = true
			rows = append(rows, r)
		}
		if readErr == io.EOF {
			break
		}
	}
	for _, path := range temps {
		if e := os.Remove(path); e != nil {
			return nil, e
		}
	}
	if e := syncDir(s.dir); e != nil {
		return nil, e
	}
	return rows, nil
}

func decodeRecord(data []byte) (Record, error) {
	if len(data) > maxFileBytes {
		return Record{}, errors.New("session record byte bound exceeded")
	}
	var env envelope
	if e := strictjson.Decode(data, &env); e != nil {
		return Record{}, e
	}
	if env.Version != 1 || env.Record == nil {
		return Record{}, errors.New("unsupported session ledger version")
	}
	r := *env.Record
	return r, validate(r)
}
