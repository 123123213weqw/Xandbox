package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

const (
	LedgerVersion        = 1
	MaxLedgerRecords     = 100_000 // Hard safety ceiling, distinct from admission policy.
	MaxLedgerRecordBytes = 64 << 10
	MaxLedgerErrorBytes  = 4096
)

var tokenPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var recordTempPattern = regexp.MustCompile(`^\.record-[0-9]+$`)

func validRef(ref Ref) bool {
	return tokenPattern.MatchString(ref.ID) && tokenPattern.MatchString(ref.Generation)
}

type ledgerEnvelope struct {
	Version int     `json:"version"`
	Record  *Record `json:"record"`
}

type ledgerIdentity struct {
	Ref                                Ref
	Backend, Tenant, KeyHash, SpecHash string
}

func identityOf(r Record) ledgerIdentity {
	return ledgerIdentity{r.Ref, r.Backend, r.TenantID, r.CreateKeyHash, r.CreateSpecHash}
}

// FileStore requires exclusive controller ownership of its private directory.
// Load/Migrate must not run concurrently with Save. Different records' Saves
// may run concurrently; no filesystem I/O holds the short index mutex.
type FileStore struct {
	dir        string
	loadMu     sync.Mutex
	indexMu    sync.Mutex
	loaded     atomic.Bool
	known      map[string]ledgerIdentity
	maxRecords int
}

func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("ledger directory must be private and non-symlink")
	}
	return &FileStore{dir: dir, maxRecords: MaxLedgerRecords}, nil
}

func validateRecord(r Record) error {
	if len(r.LastError) > MaxLedgerErrorBytes || !utf8.ValidString(r.LastError) {
		return fmt.Errorf("%w: invalid ledger error size/encoding", ErrInvalid)
	}
	if !validRef(r.Ref) || !knownState(r.State) || (r.Backend != "mock" && r.Backend != "firecracker") || !tenantPattern.MatchString(r.TenantID) {
		return fmt.Errorf("%w: invalid ledger identity, state, backend or ownership", ErrInvalid)
	}
	if (r.CreateKeyHash == "") != (r.CreateSpecHash == "") || (r.CreateKeyHash != "" && (!hashPattern.MatchString(r.CreateKeyHash) || !hashPattern.MatchString(r.CreateSpecHash))) {
		return fmt.Errorf("%w: invalid ledger key hashes", ErrInvalid)
	}
	normalized, err := normalizeCreate(CreateRequest{Limits: r.Limits})
	if err != nil || normalized.Limits != r.Limits || r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() || r.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: invalid ledger limits or timestamps", ErrInvalid)
	}
	if stoppedState(r.State) && r.StoppedAt.IsZero() {
		return fmt.Errorf("%w: missing stop confirmation", ErrInvalid)
	}
	if (r.State == Reclaiming || r.State == Destroyed) && !r.DeleteRequested {
		return fmt.Errorf("%w: missing deletion intent", ErrInvalid)
	}
	if r.State == Destroyed && r.DestroyedAt.IsZero() {
		return fmt.Errorf("%w: missing destruction timestamp", ErrInvalid)
	}
	return nil
}

func decodeLedger(data []byte, allowLegacy bool) (Record, bool, error) {
	var fields map[string]json.RawMessage
	if err := strictjson.Decode(data, &fields); err != nil {
		return Record{}, false, err
	}
	_, versioned := fields["version"]
	var r Record
	if versioned {
		var envelope ledgerEnvelope
		if err := strictjson.Decode(data, &envelope); err != nil {
			return r, false, err
		}
		if envelope.Version != LedgerVersion || envelope.Record == nil {
			return r, false, errors.New("unsupported ledger version or missing record")
		}
		r = *envelope.Record
	} else {
		// Validate legacy syntax before identifying a supported v0 migration. Never
		// reinterpret an unknown envelope/field as a legacy ownership record.
		if err := strictjson.Decode(data, &r); err != nil {
			return r, false, err
		}
		if r.TenantID == "" {
			r.TenantID = "local"
		}
		r.LastError = boundedLedgerError(r.LastError)
	}
	if err := validateRecord(r); err != nil {
		return r, false, err
	}
	if !versioned && !allowLegacy {
		return Record{}, false, ErrLedgerMigrationRequired
	}
	return r, !versioned, nil
}

func boundedLedgerError(message string) string {
	message = strings.ToValidUTF8(message, "\uFFFD")
	if len(message) <= MaxLedgerErrorBytes {
		return message
	}
	const marker = "...[truncated]"
	end := MaxLedgerErrorBytes - len(marker)
	for !utf8.RuneStart(message[end]) {
		end--
	}
	return strings.Clone(message[:end]) + marker
}

func (s *FileStore) Save(r Record) error {
	if err := validateRecord(r); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ledgerEnvelope{Version: LedgerVersion, Record: &r}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > MaxLedgerRecordBytes {
		return fmt.Errorf("%w: ledger record exceeds size bound", ErrInvalid)
	}
	if !s.loaded.Load() {
		s.loadMu.Lock()
		if !s.loaded.Load() {
			_, _, err = s.load(false)
		}
		s.loadMu.Unlock()
		if err != nil {
			return err
		}
	}
	s.indexMu.Lock()
	old, exists := s.known[r.ID]
	if exists && old.Ref != r.Ref {
		s.indexMu.Unlock()
		return fmt.Errorf("%w: ledger identity cannot be reassigned", ErrStale)
	}
	if exists && old != identityOf(r) {
		s.indexMu.Unlock()
		return fmt.Errorf("%w: ledger ownership cannot change", ErrInvalid)
	}
	if !exists && len(s.known) >= s.maxRecords {
		s.indexMu.Unlock()
		return ErrMetadataCapacity
	}
	// Keep the slot even on an ambiguous write. Only a fresh exclusive Load may
	// reconstruct disk truth; live Manager reservations likewise never evaporate.
	s.known[r.ID] = identityOf(r)
	s.indexMu.Unlock()
	f, err := os.CreateTemp(s.dir, ".record-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
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
	return syncLedgerDir(s.dir)
}

func syncLedgerDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *FileStore) Load() ([]Record, error) {
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	rows, _, err := s.load(false)
	return rows, err
}

// load validates the entire bounded directory before publishing any index or
// deleting orphan temp files. An incomplete/corrupt ledger cannot partially
// launch recovery or cause a migration of its valid prefix.
func (s *FileStore) load(allowLegacy bool) ([]Record, []bool, error) {
	dir, err := os.Open(s.dir)
	if err != nil {
		return nil, nil, err
	}
	defer dir.Close()
	var records []Record
	var legacy []bool
	var temps []string
	index := make(map[string]ledgerIdentity)
	keys := make(map[string]bool)
	entriesSeen := 0
	for {
		entries, readErr := dir.ReadDir(128)
		if readErr != nil && readErr != io.EOF {
			return nil, nil, readErr
		}
		for _, entry := range entries {
			entriesSeen++
			if entriesSeen > 2*s.maxRecords+1024 {
				return nil, nil, errors.New("ledger directory entry bound exceeded")
			}
			name := entry.Name()
			if !entry.Type().IsRegular() {
				return nil, nil, errors.New("ledger entry is not a regular file")
			}
			path := filepath.Join(s.dir, name)
			if recordTempPattern.MatchString(name) {
				// No live writer is permitted during Load. Temp contents are never truth.
				temps = append(temps, path)
				continue
			}
			if len(name) != 37 || !tokenPattern.MatchString(name[:32]) || name[32:] != ".json" {
				return nil, nil, errors.New("unexpected ledger entry")
			}
			if len(records) >= s.maxRecords {
				return nil, nil, errors.New("ledger hard record bound exceeded")
			}
			data, err := privatefile.Read(path, MaxLedgerRecordBytes)
			if err != nil {
				return nil, nil, fmt.Errorf("read ledger: %w", err)
			}
			r, old, err := decodeLedger(data, allowLegacy)
			if err != nil {
				return nil, nil, fmt.Errorf("decode ledger: %w", err)
			}
			if name != r.ID+".json" {
				return nil, nil, errors.New("ledger filename identity mismatch")
			}
			if _, duplicate := index[r.ID]; duplicate {
				return nil, nil, errors.New("duplicate ledger identity")
			}
			if r.CreateKeyHash != "" {
				key := r.TenantID + "\x00" + r.CreateKeyHash
				if keys[key] {
					return nil, nil, errors.New("duplicate ledger idempotency key")
				}
				keys[key] = true
			}
			index[r.ID] = identityOf(r)
			records, legacy = append(records, r), append(legacy, old)
		}
		if readErr == io.EOF {
			break
		}
	}
	for _, path := range temps {
		if err := os.Remove(path); err != nil {
			return nil, nil, err
		}
	}
	// Also closes any previous ambiguous rename/directory-fsync window before
	// terminal records can return capacity after controller restart.
	if err := syncLedgerDir(s.dir); err != nil {
		return nil, nil, err
	}
	s.indexMu.Lock()
	s.known = index
	s.indexMu.Unlock()
	s.loaded.Store(true)
	return records, legacy, nil
}

type MigrationReport struct {
	Version  int `json:"version"`
	Records  int `json:"records"`
	Upgraded int `json:"upgraded"`
}

// Migrate is offline, forward-only and restartable. It validates all v0/v1
// records first, then atomically upgrades v0 files one by one. A crash may leave
// a mixed ledger: normal startup rejects it; rerunning Migrate completes it.
// It never starts a driver, erases an identity/key or resurrects a generation.
func (s *FileStore) Migrate(ctx context.Context) (MigrationReport, error) {
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	report := MigrationReport{Version: LedgerVersion}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	records, legacy, err := s.load(true)
	if err != nil {
		return report, err
	}
	report.Records = len(records)
	for n, r := range records {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if !legacy[n] {
			continue
		}
		if err := s.Save(r); err != nil {
			return report, err
		}
		report.Upgraded++
	}
	return report, syncLedgerDir(s.dir)
}

func knownState(s State) bool {
	switch s {
	case Creating, Ready, Stopping, Stopped, Reclaiming, Destroyed:
		return true
	default:
		return false
	}
}
