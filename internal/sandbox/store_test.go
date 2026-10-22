package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func ledgerFixture(n int) Record {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return Record{Ref: Ref{ID: fmt.Sprintf("%032x", n), Generation: strings.Repeat("a", 32)}, Backend: "mock", TenantID: "alpha", State: Destroyed, DeleteRequested: true, Limits: Limits{MaxExecMS: 5000, MaxJobs: 64, MaxOutputBytes: 16384}, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Minute), StoppedAt: now, DestroyedAt: now}
}
func ledgerStore(t *testing.T) *FileStore {
	t.Helper()
	s, err := NewFileStore(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func writeLedger(t *testing.T, s *FileStore, r Record, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(s.dir, r.ID+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}
func legacyBytes(t *testing.T, r Record) []byte {
	t.Helper()
	b, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestLedgerVersionMigrationPreservesOwnershipAndKeys(t *testing.T) {
	s := ledgerStore(t)
	r := ledgerFixture(1)
	r.TenantID = ""
	legacy := legacyBytes(t, r)
	writeLedger(t, s, r, legacy)
	if _, e := s.Load(); !errors.Is(e, ErrLedgerMigrationRequired) {
		t.Fatal("legacy startup not rejected", e)
	}
	before, _ := os.ReadFile(filepath.Join(s.dir, r.ID+".json"))
	if !bytes.Equal(before, legacy) {
		t.Fatal("normal startup modified legacy ledger")
	}
	report, e := s.Migrate(context.Background())
	if e != nil || report.Upgraded != 1 || report.Records != 1 {
		t.Fatal(report, e)
	}
	rows, e := s.Load()
	if e != nil || len(rows) != 1 || rows[0].TenantID != "local" || rows[0].Ref != r.Ref || rows[0].State != Destroyed {
		t.Fatal(rows, e)
	}
	report, e = s.Migrate(context.Background())
	if e != nil || report.Upgraded != 0 {
		t.Fatal("migration not idempotent", report, e)
	}
	data, _ := os.ReadFile(filepath.Join(s.dir, r.ID+".json"))
	var env ledgerEnvelope
	if e := json.Unmarshal(data, &env); e != nil || env.Version != 1 || env.Record == nil {
		t.Fatal("not versioned", e)
	}
	// Simulate an interruption after one atomic upgrade. A mixed directory is
	// rejected by normal startup; the same migrator finishes without new IDs.
	second := ledgerFixture(2)
	second.CreateKeyHash = strings.Repeat("b", 64)
	second.CreateSpecHash = strings.Repeat("c", 64)
	writeLedger(t, s, second, legacyBytes(t, second))
	if _, e := s.Load(); !errors.Is(e, ErrLedgerMigrationRequired) {
		t.Fatal(e)
	}
	report, e = s.Migrate(context.Background())
	if e != nil || report.Upgraded != 1 || report.Records != 2 {
		t.Fatal(report, e)
	}
	rows, e = s.Load()
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range rows {
		if row.ID == second.ID && (row.CreateKeyHash != second.CreateKeyHash || row.CreateSpecHash != second.CreateSpecHash || row.Generation != second.Generation) {
			t.Fatal("lost key ownership")
		}
	}
}

func TestLedgerMigrationPreflightNeverUpgradesValidPrefixOfCorruptDirectory(t *testing.T) {
	s := ledgerStore(t)
	r := ledgerFixture(1)
	data := legacyBytes(t, r)
	writeLedger(t, s, r, data)
	bad := ledgerFixture(2)
	writeLedger(t, s, bad, []byte(`{"version":900,"record":{}}`))
	if _, e := s.Migrate(context.Background()); e == nil {
		t.Fatal("unknown schema migrated")
	}
	got, _ := os.ReadFile(filepath.Join(s.dir, r.ID+".json"))
	if !bytes.Equal(data, got) {
		t.Fatal("prefix mutated before full preflight")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := s.Migrate(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestLedgerDecoderStrictBoundaries(t *testing.T) {
	r := ledgerFixture(1)
	valid, _ := json.Marshal(ledgerEnvelope{Version: 1, Record: &r})
	cases := [][]byte{
		[]byte(`null`), []byte(`{}`), []byte(`{"version":null,"record":{}}`), []byte(`{"version":2,"record":{}}`), []byte(`{"version":1,"record":null}`),
		bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"VERSION":1`), 1),
		bytes.Replace(valid, []byte(`"state":"DESTROYED"`), []byte(`"state":"DESTROYED","State":"READY"`), 1),
		bytes.Replace(valid, []byte(`"state":"DESTROYED"`), []byte(`"state":"UNKNOWN"`), 1),
		bytes.Replace(valid, []byte(`"tenant_id":"alpha"`), []byte(`"tenant_id":null`), 1),
		bytes.Replace(valid, []byte(`"limits":{`), []byte(`"unknown":true,"limits":{`), 1),
		append(append([]byte{}, valid...), []byte(`{}`)...),
	}
	for n, data := range cases {
		if _, _, e := decodeLedger(data, true); e == nil {
			t.Fatalf("case %d accepted %s", n, data)
		}
	}
	for _, mutate := range []func(*Record){func(r *Record) { r.Limits.MaxJobs = 0 }, func(r *Record) { r.StoppedAt = time.Time{} }, func(r *Record) { r.DestroyedAt = time.Time{} }, func(r *Record) { r.DeleteRequested = false }, func(r *Record) { r.CreateKeyHash = strings.Repeat("b", 64) }} {
		bad := r
		mutate(&bad)
		data, _ := json.Marshal(ledgerEnvelope{Version: 1, Record: &bad})
		if _, _, e := decodeLedger(data, false); e == nil {
			t.Fatal("invalid semantic record accepted")
		}
	}
}

func TestLedgerBoundedLoaderAndPrivateFiles(t *testing.T) {
	for _, mode := range []string{"oversize", "symlink", "public", "mismatch", "unexpected", "too-many"} {
		t.Run(mode, func(t *testing.T) {
			s := ledgerStore(t)
			r := ledgerFixture(1)
			data, _ := json.Marshal(ledgerEnvelope{Version: 1, Record: &r})
			path := filepath.Join(s.dir, r.ID+".json")
			switch mode {
			case "oversize":
				data = bytes.Repeat([]byte(" "), MaxLedgerRecordBytes+1)
				writeLedger(t, s, r, data)
			case "symlink":
				target := filepath.Join(t.TempDir(), "target")
				os.WriteFile(target, data, 0600)
				if e := os.Symlink(target, path); e != nil {
					t.Fatal(e)
				}
			case "public":
				writeLedger(t, s, r, data)
				os.Chmod(path, 0644)
			case "mismatch":
				writeLedger(t, s, ledgerFixture(2), data)
			case "unexpected":
				os.WriteFile(filepath.Join(s.dir, "other"), data, 0600)
			case "too-many":
				s.maxRecords = 1
				writeLedger(t, s, r, data)
				r2 := ledgerFixture(2)
				data2, _ := json.Marshal(ledgerEnvelope{Version: 1, Record: &r2})
				writeLedger(t, s, r2, data2)
			}
			if _, e := s.Load(); e == nil {
				t.Fatal("invalid ledger accepted")
			}
		})
	}
}

func TestLedgerHardCapacityIsAtomicButDoesNotBlockUpdates(t *testing.T) {
	s := ledgerStore(t)
	s.maxRecords = 2
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for n := 1; n <= 32; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			err := s.Save(ledgerFixture(n))
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrMetadataCapacity) {
				t.Error(err)
			}
		}(n)
	}
	wg.Wait()
	if accepted.Load() != 2 {
		t.Fatal("hard admission race", accepted.Load())
	}
	rows, e := s.Load()
	if e != nil || len(rows) != 2 {
		t.Fatal(rows, e)
	}
	r := rows[0]
	r.LastError = "updated at capacity"
	if e := s.Save(r); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Record){func(r *Record) { r.TenantID = "beta" }, func(r *Record) { r.Backend = "firecracker" }, func(r *Record) { r.CreateKeyHash = strings.Repeat("b", 64); r.CreateSpecHash = strings.Repeat("c", 64) }} {
		bad := r
		mutate(&bad)
		if e := s.Save(bad); !errors.Is(e, ErrInvalid) {
			t.Fatal("immutable ownership changed", e)
		}
	}
	r.Generation = strings.Repeat("b", 32)
	if e := s.Save(r); !errors.Is(e, ErrStale) {
		t.Fatal("identity reused", e)
	}
}

func TestLedgerOrphanCleanupOnlyAfterCompleteValidation(t *testing.T) {
	s := ledgerStore(t)
	tmp := filepath.Join(s.dir, ".record-123456")
	os.WriteFile(tmp, []byte("not authoritative"), 0600)
	r := ledgerFixture(1)
	writeLedger(t, s, r, []byte("{"))
	if _, e := s.Load(); e == nil {
		t.Fatal("corruption accepted")
	}
	if _, e := os.Stat(tmp); e != nil {
		t.Fatal("temp deleted before full validation")
	}
	data, _ := json.Marshal(ledgerEnvelope{Version: 1, Record: &r})
	writeLedger(t, s, r, data)
	if _, e := s.Load(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(tmp); !os.IsNotExist(e) {
		t.Fatal("orphan not removed", e)
	}
}

func FuzzLedgerDecoder(f *testing.F) {
	r := ledgerFixture(1)
	seed, _ := json.Marshal(ledgerEnvelope{Version: 1, Record: &r})
	f.Add(seed)
	f.Add([]byte(`{"version":999}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxLedgerRecordBytes {
			t.Skip()
		}
		r, old, e := decodeLedger(b, true)
		if e == nil {
			if e := validateRecord(r); e != nil {
				t.Fatal(e)
			}
			if !old {
				if _, _, e := decodeLedger(b, false); e != nil {
					t.Fatal(e)
				}
			}
		}
	})
}

func TestLedgerDuplicateKeyAndDirectoryBoundsFailBeforeMutation(t *testing.T) {
	t.Run("duplicate-key", func(t *testing.T) {
		s := ledgerStore(t)
		before := map[string][]byte{}
		for n := 1; n <= 2; n++ {
			r := ledgerFixture(n)
			r.CreateKeyHash = strings.Repeat("b", 64)
			r.CreateSpecHash = strings.Repeat("c", 64)
			data := legacyBytes(t, r)
			writeLedger(t, s, r, data)
			before[r.ID+".json"] = data
		}
		if _, e := s.Migrate(context.Background()); e == nil {
			t.Fatal("duplicate tenant key migrated")
		}
		for name, data := range before {
			got, e := os.ReadFile(filepath.Join(s.dir, name))
			if e != nil || !bytes.Equal(got, data) {
				t.Fatal("failed preflight changed records", e)
			}
		}
	})
	t.Run("directory-entries", func(t *testing.T) {
		s := ledgerStore(t)
		s.maxRecords = 1
		for n := 0; n < 2*s.maxRecords+1025; n++ {
			if e := os.WriteFile(filepath.Join(s.dir, fmt.Sprintf(".record-%d", n)), []byte("orphan"), 0600); e != nil {
				t.Fatal(e)
			}
		}
		if _, e := s.Load(); e == nil {
			t.Fatal("directory entry bound not enforced")
		}
		entries, e := os.ReadDir(s.dir)
		if e != nil || len(entries) != 2*s.maxRecords+1025 {
			t.Fatal("failed preflight pruned files", e)
		}
	})
}

func TestLedgerDirectoryMustBePrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger")
	if e := os.Mkdir(path, 0755); e != nil {
		t.Fatal(e)
	}
	if _, e := NewFileStore(path); e == nil {
		t.Fatal("public ledger directory accepted")
	}
}
