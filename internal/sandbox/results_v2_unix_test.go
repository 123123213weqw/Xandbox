//go:build linux || darwin

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestResultStoreV2ChecksumBindsReservationAndPayloadAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results")
	s := resultOpen(t, path, resultLimits())
	h := resultHeader()
	if e := s.Reserve(h); e != nil {
		t.Fatal(e)
	}
	if e := s.Complete(resultTerminal(h)); e != nil {
		t.Fatal(e)
	}
	s.Close()
	raw, e := os.ReadFile(filepath.Join(path, h.JobID+".json"))
	if e != nil {
		t.Fatal(e)
	}
	r, e := decodeResult(raw)
	if e != nil || r.Version != 2 || !hashPattern.MatchString(r.SHA256) {
		t.Fatal(r, e)
	}
	for _, kind := range []string{"stdout", "tenant", "checksum", "missing", "wrong-version"} {
		t.Run(kind, func(t *testing.T) {
			var row resultEnvelope
			if e := json.Unmarshal(raw, &row); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "stdout":
				row.Result.Stdout[0] ^= 1
			case "tenant":
				row.Reservation.TenantID = "beta"
			case "checksum":
				row.SHA256 = strings.Repeat("0", 64)
			case "missing":
				row.SHA256 = ""
			case "wrong-version":
				row.Version = 1
			}
			changed, e := json.Marshal(row)
			if e != nil {
				t.Fatal(e)
			}
			changed = append(changed, '\n')
			if _, e = decodeResult(changed); e == nil {
				t.Fatal("corrupt checksum accepted")
			}
			fixture := filepath.Join(t.TempDir(), "results")
			if e = os.Mkdir(fixture, 0700); e != nil {
				t.Fatal(e)
			}
			file := filepath.Join(fixture, h.JobID+".json")
			if e = os.WriteFile(file, changed, 0600); e != nil {
				t.Fatal(e)
			}
			if x, e := OpenResultStore(fixture, resultLimits()); e == nil {
				x.Close()
				t.Fatal("restart accepted corrupt canonical payload")
			}
			after, _ := os.ReadFile(file)
			if !bytes.Equal(after, changed) {
				t.Fatal("corrupt bytes repaired")
			}
		})
	}
	reopened := resultOpen(t, path, resultLimits())
	j, e := reopened.Get(h.Ref, h.TenantID, h.JobID)
	if e != nil || j.ResultIntegrity != "checksum_v2" || !j.ResultRetained || j.Output != resultTerminal(h).Output {
		t.Fatal(j, e)
	}
}
func TestResultStoreV2LegacyV1ReadableWithoutRewriteOrIntegrityPromotion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results")
	if e := os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	h := resultHeader()
	j := resultTerminal(h)
	r := resultEnvelope{Version: 1, Reservation: h, Result: &retainedOutput{Status: j.Status, FinishedAt: j.FinishedAt, Stdout: []byte(j.Output.Stdout), Stderr: []byte(j.Output.Stderr), ExitCode: j.Output.ExitCode}}
	raw := resultBytes(r)
	file := filepath.Join(path, h.JobID+".json")
	if e := os.WriteFile(file, raw, 0600); e != nil {
		t.Fatal(e)
	}
	s := resultOpen(t, path, resultLimits())
	got, e := s.Get(h.Ref, h.TenantID, h.JobID)
	if e != nil || !got.ResultRetained || got.ResultIntegrity != "legacy_unverified_v1" || got.Output != j.Output {
		t.Fatal(got, e)
	}
	if e = s.Complete(j); !errors.Is(e, ErrResultUnavailable) {
		t.Fatal("legacy commit silently re-signed", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	owner := resultOwner(h)
	owner.State = Destroyed
	if o, e := s.sealResults(ctx, []Record{owner}); e == nil || o != (ResultClosureObservation{}) {
		t.Fatal("unverified legacy became strong closure", o, e)
	}
	after, _ := os.ReadFile(file)
	if !bytes.Equal(after, raw) {
		t.Fatal("v1 data silently upgraded")
	}
}
func TestResultStoreV2PendingNeverReportsZeroOrAcceptsReconstructedCompletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results")
	s := resultOpen(t, path, resultLimits())
	h := resultHeader()
	if e := s.Reserve(h); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s = resultOpen(t, path, resultLimits())
	j, e := s.Get(h.Ref, h.TenantID, h.JobID)
	if e != nil || j.Status != "INTERRUPTED" || j.Output.ExitCode != -1 || j.ResultRetained || j.ResultIntegrity != "" {
		t.Fatal(j, e)
	}
	before, _ := os.ReadFile(filepath.Join(path, h.JobID+".json"))
	if e = s.Complete(resultTerminal(h)); !errors.Is(e, ErrResultUnavailable) {
		t.Fatal("reconstructed old pending outcome", e)
	}
	after, _ := os.ReadFile(filepath.Join(path, h.JobID+".json"))
	if !bytes.Equal(before, after) {
		t.Fatal("pending bytes changed")
	}
}
func TestResultStoreV2InvalidTimesRefuseBeforeAnyPanicOrRecord(t *testing.T) {
	s := resultOpen(t, filepath.Join(t.TempDir(), "results"), resultLimits())
	for _, bad := range []time.Time{time.Time{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC)} {
		h := resultHeader()
		h.StartedAt = bad
		if e := s.Reserve(h); !errors.Is(e, ErrInvalid) {
			t.Fatal(e)
		}
	}
	h := resultHeader()
	if e := s.Reserve(h); e != nil {
		t.Fatal(e)
	}
	j := resultTerminal(h)
	j.FinishedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	if e := s.Complete(j); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if len(s.entries) != 1 {
		t.Fatal("invalid time reserved capacity")
	}
}
func TestResultStoreV2SealedSnapshotBindsAllBytesAndRefusesUnknownDrift(t *testing.T) {
	for _, kind := range []string{"valid", "extra", "missing", "mode", "raw-corrupt", "between-scans", "pending", "closed", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "results")
			s := resultOpen(t, path, resultLimits())
			h := resultHeader()
			if e := s.Reserve(h); e != nil {
				t.Fatal(e)
			}
			if kind != "pending" {
				if e := s.Complete(resultTerminal(h)); e != nil {
					t.Fatal(e)
				}
			}
			file := filepath.Join(path, h.JobID+".json")
			switch kind {
			case "extra":
				os.WriteFile(filepath.Join(path, "unknown"), []byte("synthetic"), 0600)
			case "missing":
				os.Remove(file)
			case "mode":
				os.Chmod(file, 0644)
			case "raw-corrupt":
				raw, _ := os.ReadFile(file)
				raw[len(raw)-5] ^= 1
				os.WriteFile(file, raw, 0600)
			case "between-scans":
				s.point = func(stage string) error {
					if stage == "result-seal-after-first" {
						return os.Chtimes(file, time.Now(), time.Now().Add(time.Second))
					}
					return nil
				}
			case "closed":
				s.Close()
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if kind == "cancelled" {
				cancel()
			}
			owner := resultOwner(h)
			owner.State = Destroyed
			o, e := s.sealResults(ctx, []Record{owner})
			if kind != "valid" {
				if e == nil || o != (ResultClosureObservation{}) {
					t.Fatal("partial/invalid proof", o, e)
				}
				return
			}
			if e != nil || !o.Valid() || o.Records != 1 || o.Bytes <= 0 || o.ReservedBytes != h.charge() {
				t.Fatal(o, e)
			}
			if e = s.Reserve(ResultReservation{JobID: strings.Repeat("d", 32), Ref: h.Ref, TenantID: h.TenantID, MaxOutputBytes: h.MaxOutputBytes, StartedAt: h.StartedAt}); !errors.Is(e, ErrResultUnavailable) {
				t.Fatal("writer entered after seal", e)
			}
			if e = s.Complete(resultTerminal(h)); !errors.Is(e, ErrResultUnavailable) {
				t.Fatal("writer retry entered after seal", e)
			}
			got, e := s.Get(h.Ref, h.TenantID, h.JobID)
			if e != nil || got.Output != resultTerminal(h).Output {
				t.Fatal("seal disabled readonly retrieval", got, e)
			}
		})
	}
}
func TestResultStoreV2MaximumRecordAndScratchStillFitOriginalCharge(t *testing.T) {
	for _, limit := range []int{1, 64, 65_536} {
		h := resultHeader()
		h.MaxOutputBytes = limit
		r := resultEnvelope{Version: 2, Reservation: h, Result: &retainedOutput{Status: "FAILED", FinishedAt: h.StartedAt.Add(time.Second), Stdout: bytes.Repeat([]byte{255}, limit), ExitCode: -1, Error: bytes.Repeat([]byte{255}, MaxLedgerErrorBytes)}}
		raw := resultBytes(r)
		if _, e := decodeResult(raw); e != nil {
			t.Fatal(e)
		}
		if int64(len(raw)+len(resultBytes(resultEnvelope{Version: 2, Reservation: h}))) > h.charge() {
			t.Fatal("checksum increased original reservation budget")
		}
	}
}
func TestManagerResultBoundClosureRequiresActualStoreAndCompleteCurrentNamespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results")
	store := resultOpen(t, path, resultLimits())
	gate := NewAdmissionGate(true)
	m, _, _ := setup(t, Options{Results: store, AdmissionGate: gate}, nil)
	r := create(t, m, CreateRequest{})
	j := execDone(t, m, r, "echo", "known")
	if !j.ResultRetained || j.ResultIntegrity != "checksum_v2" {
		t.Fatal(j)
	}
	gate.FreezeAcceptedWork()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if e := m.Close(ctx); e != nil {
		t.Fatal(e)
	}
	if p, e := m.ClosedProof(ctx); p != nil || !errors.Is(e, ErrNotReady) {
		t.Fatal("legacy closure dropped results", p, e)
	}
	p, e := m.ClosedResultsProof(ctx)
	if e != nil || !p.For(m) || p.For(nil) || !p.Observation().Valid() || p.Observation().Results.Records != 1 || p.Observation().Core.Records != 1 {
		t.Fatal(p, e)
	}
	if q, e := m.ClosedResultsProof(context.Background()); q != nil || !errors.Is(e, ErrInvalid) {
		t.Fatal("unbounded inventory", q, e)
	}
	store.Close()
	if p.For(m) {
		t.Fatal("closed FD owner reused proof")
	}
}
func TestManagerResultBoundClosureRejectsStoreWrapperEvenWithPlausibleCounts(t *testing.T) {
	store := &gatedResultStore{ResultStore: resultOpen(t, filepath.Join(t.TempDir(), "results"), resultLimits())}
	g := NewAdmissionGate(true)
	m, _, _ := setup(t, Options{Results: store, AdmissionGate: g}, nil)
	g.FreezeAcceptedWork()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := m.Close(ctx); e != nil {
		t.Fatal(e)
	}
	if p, e := m.ClosedResultsProof(ctx); p != nil || !errors.Is(e, ErrResultUnavailable) {
		t.Fatal("caller store manufactured closure", p, e)
	}
}

func TestResultStoreV2SealRefusesInFlightWriterAndKeepsFenceWithoutWaitingIO(t *testing.T) {
	s := resultOpen(t, filepath.Join(t.TempDir(), "results"), resultLimits())
	h := resultHeader()
	if e := s.Reserve(h); e != nil {
		t.Fatal(e)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	s.point = func(stage string) error {
		if stage == "result-complete-written" {
			close(entered)
			<-release
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- s.Complete(resultTerminal(h)) }()
	<-entered
	owner := resultOwner(h)
	owner.State = Destroyed
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if o, e := s.sealResults(ctx, []Record{owner}); e == nil || o != (ResultClosureObservation{}) {
		t.Fatal("active writer produced proof", o, e)
	}
	if e := s.Reserve(ResultReservation{JobID: strings.Repeat("d", 32), Ref: h.Ref, TenantID: h.TenantID, MaxOutputBytes: 64, StartedAt: h.StartedAt}); !errors.Is(e, ErrResultUnavailable) {
		t.Fatal("failed seal reopened writer", e)
	}
	unblock()
	if e := <-done; e != nil {
		t.Fatal("pre-seal owned writer invalidated", e)
	}
	if o, e := s.sealResults(ctx, []Record{owner}); e != nil || !o.Valid() {
		t.Fatal(o, e)
	}
}
func TestResultStoreV2ReadOnlyLookupIOCannotBlockClosedWriterSnapshot(t *testing.T) {
	s := resultOpen(t, filepath.Join(t.TempDir(), "results"), resultLimits())
	h := resultHeader()
	if e := s.Reserve(h); e != nil {
		t.Fatal(e)
	}
	if e := s.Complete(resultTerminal(h)); e != nil {
		t.Fatal(e)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	s.point = func(stage string) error {
		if stage == "result-root-before-stat" && first.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { _, e := s.Get(h.Ref, h.TenantID, h.JobID); done <- e }()
	<-entered
	owner := resultOwner(h)
	owner.State = Destroyed
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	o, e := s.sealResults(ctx, []Record{owner})
	if e != nil || !o.Valid() {
		t.Fatal("readonly IO vetoed writer-free snapshot", o, e)
	}
	unblock()
	if e := <-done; e != nil {
		t.Fatal("seal invalidated readonly descriptor", e)
	}
}

type mismatchedReadbackStore struct {
	ResultStore
	entered, release chan struct{}
}

func (s *mismatchedReadbackStore) Get(ref Ref, tenant, id string) (Job, error) {
	j, e := s.ResultStore.Get(ref, tenant, id)
	if s.entered != nil {
		close(s.entered)
		<-s.release
	}
	if e == nil {
		j.Output.Stdout = "SYNTHETIC_MISMATCH"
	}
	return j, e
}
func TestManagerResultReadbackMustMatchActualDriverOutputBeforeSuccess(t *testing.T) {
	store := &mismatchedReadbackStore{ResultStore: resultOpen(t, filepath.Join(t.TempDir(), "results"), resultLimits()), entered: make(chan struct{}), release: make(chan struct{})}
	gate := NewAdmissionGate(true)
	m, _, _ := setup(t, Options{Results: store, AdmissionGate: gate}, nil)
	release := releaseResultGate(t, store.release)
	r := create(t, m, CreateRequest{})
	j, e := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo", "actual"}})
	if e != nil {
		t.Fatal(e)
	}
	<-store.entered
	gate.FreezeAcceptedWork()
	release()
	eventually(t, func() bool { return gate.AcceptedWorkStatus().Pending == 0 })
	if s := gate.AcceptedWorkStatus(); s.Complete() || s.Failed != 1 {
		t.Fatal("different stored tuple accepted", s)
	}
	if _, e = m.GetJob(r.ID, j.ID); !errors.Is(e, ErrResultUnavailable) {
		t.Fatal("mismatched output published", e)
	}
}

func TestManagerResultBoundClosureNoFailedChecksumOrLegacyStoreCanProduceAuthority(t *testing.T) {
	for _, kind := range []string{"v1", "corrupt", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "results")
			store := resultOpen(t, path, resultLimits())
			gate := NewAdmissionGate(true)
			m, _, _ := setup(t, Options{Results: store, AdmissionGate: gate}, nil)
			r := create(t, m, CreateRequest{})
			job := execDone(t, m, r, "echo", "original")
			gate.FreezeAcceptedWork()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if e := m.Close(ctx); e != nil {
				t.Fatal(e)
			}
			file := filepath.Join(path, job.ID+".json")
			raw, e := os.ReadFile(file)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "v1":
				row, e := decodeResult(raw)
				if e != nil {
					t.Fatal(e)
				}
				row.Version = 1
				row.SHA256 = ""
				raw = resultBytes(row)
				os.WriteFile(file, raw, 0600)
			case "corrupt":
				raw[len(raw)-5] ^= 1
				os.WriteFile(file, raw, 0600)
			case "unknown":
				os.WriteFile(filepath.Join(path, "unknown"), []byte("synthetic"), 0600)
			}
			if p, e := m.ClosedResultsProof(ctx); p != nil || e == nil {
				t.Fatal("unsafe result bytes produced authority", p, e)
			}
			after, _ := os.ReadFile(file)
			if !bytes.Equal(raw, after) {
				t.Fatal("refused bytes were repaired")
			}
		})
	}
}
