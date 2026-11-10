//go:build linux || darwin

package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func resultHeader() ResultReservation {
	return ResultReservation{JobID: strings.Repeat("a", 32), Ref: Ref{ID: strings.Repeat("b", 32), Generation: strings.Repeat("c", 32)}, TenantID: "alpha", MaxOutputBytes: 64, StartedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}
func resultTerminal(h ResultReservation) Job {
	return Job{ID: h.JobID, Ref: h.Ref, StartedAt: h.StartedAt, FinishedAt: h.StartedAt.Add(time.Second), Status: "EXITED", Output: Output{Stdout: "raw\xff\x00bytes", Stderr: "private-result", ExitCode: 0}}
}
func resultLimits() ResultLimits {
	return ResultLimits{Bytes: 1 << 20, TenantBytes: 1 << 19, Records: 100}
}
func resultOpen(t *testing.T, path string, l ResultLimits) *FileResultStore {
	t.Helper()
	s, e := OpenResultStore(path, l)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func resultOwner(h ResultReservation) Record {
	return Record{Ref: h.Ref, TenantID: h.TenantID, Limits: Limits{MaxOutputBytes: h.MaxOutputBytes}}
}

func TestResultStoreRawBytesSurviveReopenAndBindingsNeverAdoptForeignOwners(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results")
	s := resultOpen(t, path, resultLimits())
	h := resultHeader()
	if e := s.Reserve(h); e != nil {
		t.Fatal(e)
	}
	j, e := s.Get(h.Ref, h.TenantID, h.JobID)
	if e != nil || j.Status != "INTERRUPTED" || j.ResultRetained || j.Output.Stdout != "" {
		t.Fatal(j, e)
	}
	if u, e := s.Bind([]Record{resultOwner(h)}); e != nil || !u {
		t.Fatal(u, e)
	}
	if e = s.Complete(resultTerminal(h)); e != nil {
		t.Fatal(e)
	}
	if e = s.Complete(resultTerminal(h)); e != nil {
		t.Fatal("exact retry", e)
	}
	changed := resultTerminal(h)
	changed.Output.Stdout = "changed"
	if e = s.Complete(changed); e == nil {
		t.Fatal("terminal overwrite")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s = resultOpen(t, path, resultLimits())
	if u, e := s.Bind([]Record{resultOwner(h)}); e != nil || u {
		t.Fatal(u, e)
	}
	j, e = s.Get(h.Ref, h.TenantID, h.JobID)
	if e != nil || !j.ResultRetained || j.Output != resultTerminal(h).Output {
		t.Fatal(j, e)
	}
	if _, e = s.Get(h.Ref, "foreign", h.JobID); !errors.Is(e, ErrNotFound) {
		t.Fatal(e)
	}
	bad := h.Ref
	bad.Generation = strings.Repeat("d", 32)
	if _, e = s.Get(bad, h.TenantID, h.JobID); !errors.Is(e, ErrNotFound) {
		t.Fatal(e)
	}
	for _, r := range [][]Record{nil, {{Ref: bad, TenantID: h.TenantID, Limits: Limits{MaxOutputBytes: 64}}}, {{Ref: h.Ref, TenantID: "foreign", Limits: Limits{MaxOutputBytes: 64}}}, {{Ref: h.Ref, TenantID: h.TenantID, Limits: Limits{MaxOutputBytes: 65}}}} {
		if _, e = s.Bind(r); e == nil {
			t.Fatal("orphan/foreign/limit drift accepted")
		}
	}
}
func TestResultStorePessimisticTenantNodeRecordLimitsAndLoweredRecovery(t *testing.T) {
	h := resultHeader()
	charge := h.charge()
	for _, which := range []string{"tenant", "node", "records"} {
		t.Run(which, func(t *testing.T) {
			l := ResultLimits{Bytes: 3 * charge, TenantBytes: 3 * charge, Records: 3}
			switch which {
			case "tenant":
				l.TenantBytes = charge
			case "node":
				l.Bytes = charge
				l.TenantBytes = charge
			case "records":
				l.Records = 1
			}
			path := filepath.Join(t.TempDir(), "results")
			s := resultOpen(t, path, l)
			if e := s.Reserve(h); e != nil {
				t.Fatal(e)
			}
			if e := s.Complete(resultTerminal(h)); e != nil {
				t.Fatal(e)
			}
			next := h
			next.JobID = strings.Repeat("d", 32)
			if which == "node" {
				next.TenantID = "beta"
			}
			if e := s.Reserve(next); !errors.Is(e, ErrResultCapacity) {
				t.Fatal(e)
			}
			if e := s.Reserve(h); !errors.Is(e, ErrResultUnavailable) {
				t.Fatal("duplicate reused slot", e)
			}
			s.Close()
			s = resultOpen(t, path, ResultLimits{Bytes: 1, TenantBytes: 1, Records: 1})
			if j, e := s.Get(h.Ref, h.TenantID, h.JobID); e != nil || !j.ResultRetained {
				t.Fatal("lower cap lost retained result", e)
			}
			if e := s.Reserve(next); !errors.Is(e, ErrResultCapacity) {
				t.Fatal(e)
			}
		})
	}
	for _, l := range []ResultLimits{{}, {Bytes: -1, TenantBytes: 1, Records: 1}, {Bytes: MaxResultBytes + 1, TenantBytes: 1, Records: 1}, {Bytes: 1, TenantBytes: 2, Records: 1}, {Bytes: 1, TenantBytes: 1, Records: MaxResultRecords + 1}} {
		if s, e := OpenResultStore(filepath.Join(t.TempDir(), "invalid"), l); e == nil {
			s.Close()
			t.Fatal("invalid limits")
		}
	}
}
func TestResultStoreUnknownNamespaceCorruptionAndPartialScratchPreserved(t *testing.T) {
	for _, kind := range []string{"scratch", "unknown", "mode", "hardlink", "symlink", "malformed", "unknown-field", "oversize", "filename"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "results")
			s := resultOpen(t, path, resultLimits())
			h := resultHeader()
			if e := s.Reserve(h); e != nil {
				t.Fatal(e)
			}
			s.Close()
			target := filepath.Join(path, h.JobID+".json")
			raw, _ := os.ReadFile(target)
			switch kind {
			case "scratch":
				os.WriteFile(filepath.Join(path, "."+h.JobID+".next"), []byte("private partial"), 0600)
			case "unknown":
				os.WriteFile(filepath.Join(path, "unknown"), []byte("private unknown"), 0600)
			case "mode":
				os.Chmod(target, 0644)
			case "hardlink":
				os.Link(target, filepath.Join(filepath.Dir(path), "extra-link"))
			case "symlink":
				os.Rename(target, filepath.Join(filepath.Dir(path), "moved"))
				os.Symlink(filepath.Join(filepath.Dir(path), "moved"), target)
			case "malformed":
				os.WriteFile(target, []byte("{"), 0600)
			case "unknown-field":
				os.WriteFile(target, append([]byte(`{"unknown":true,`), raw[1:]...), 0600)
			case "oversize":
				os.WriteFile(target, bytes.Repeat([]byte("x"), 150_000), 0600)
			case "filename":
				os.Rename(target, filepath.Join(path, strings.Repeat("d", 32)+".json"))
			}
			before := map[string][]byte{}
			names, _ := os.ReadDir(path)
			for _, n := range names {
				b, _ := os.ReadFile(filepath.Join(path, n.Name()))
				before[n.Name()] = b
			}
			if x, e := OpenResultStore(path, resultLimits()); e == nil {
				x.Close()
				t.Fatal("corruption adopted")
			}
			after, _ := os.ReadDir(path)
			if len(after) != len(before) {
				t.Fatal("unknown entries removed")
			}
			for _, n := range after {
				b, _ := os.ReadFile(filepath.Join(path, n.Name()))
				if !bytes.Equal(b, before[n.Name()]) {
					t.Fatal("unknown bytes repaired")
				}
			}
		})
	}
}
func TestResultStoreLiveTamperCloseAndRootRebindingFailClosed(t *testing.T) {
	for _, kind := range []string{"bytes", "mode", "root", "closed"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "results")
			s := resultOpen(t, path, resultLimits())
			h := resultHeader()
			if e := s.Reserve(h); e != nil {
				t.Fatal(e)
			}
			j := resultTerminal(h)
			if e := s.Complete(j); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "bytes":
				r := resultEnvelope{Version: 1, Reservation: h, Result: &retainedOutput{Status: "EXITED", FinishedAt: j.FinishedAt, Stdout: []byte("other")}}
				os.WriteFile(filepath.Join(path, h.JobID+".json"), resultBytes(r), 0600)
			case "mode":
				os.Chmod(filepath.Join(path, h.JobID+".json"), 0644)
			case "root":
				os.Rename(path, path+"-old")
				os.Mkdir(path, 0700)
			case "closed":
				s.Close()
			}
			if _, e := s.Get(h.Ref, h.TenantID, h.JobID); e == nil {
				t.Fatal("changed/closed store read")
			}
			if e := s.Complete(j); e == nil {
				t.Fatal("cached retry accepted tamper")
			}
		})
	}
}
func TestResultStoreCodecStrictnessAndOutputBounds(t *testing.T) {
	h := resultHeader()
	r := resultEnvelope{Version: 1, Reservation: h}
	raw := resultBytes(r)
	for _, b := range [][]byte{nil, append(raw, raw...), append(raw, ' '), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":2`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"foreign":true`), 1)} {
		if _, e := decodeResult(b); e == nil {
			t.Fatal("noncanonical/unknown schema")
		}
	}
	s := resultOpen(t, filepath.Join(t.TempDir(), "results"), resultLimits())
	if e := s.Reserve(h); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Job){func(j *Job) { j.Output.Stdout = strings.Repeat("x", 65) }, func(j *Job) { j.Status = "RUNNING" }, func(j *Job) { j.FinishedAt = time.Time{} }, func(j *Job) { j.Output.ExitCode = 256 }, func(j *Job) { j.Ref.Generation = strings.Repeat("e", 32) }} {
		j := resultTerminal(h)
		change(&j)
		if e := s.Complete(j); e == nil {
			t.Fatal("invalid terminal result")
		}
	}
}

func TestResultStoreOwnedCrashHelper(t *testing.T) {
	path := os.Getenv("XANDBOX_RESULT_TEST_DIR")
	if path == "" {
		t.Skip("owned child helper")
	}
	stage := os.Getenv("XANDBOX_RESULT_TEST_CUT")
	allowed := false
	for _, phase := range []string{"reserve", "complete"} {
		for _, cut := range []string{"written", "synced", "renamed", "durable"} {
			if stage == "result-"+phase+"-"+cut {
				allowed = true
			}
		}
	}
	if !allowed {
		os.Exit(8)
	}
	s, e := OpenResultStore(path, resultLimits())
	if e != nil {
		os.Exit(9)
	}
	s.point = func(point string) error {
		if point == stage {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		return nil
	}
	h := resultHeader()
	if s.Reserve(h) != nil {
		os.Exit(10)
	}
	if s.Complete(resultTerminal(h)) != nil {
		os.Exit(11)
	}
	os.Exit(12)
}
func TestResultStoreActualOwnedSIGKILLPublicationCutsNeverReplayOrDeleteUnknownPrefix(t *testing.T) {
	for _, phase := range []string{"reserve", "complete"} {
		for _, cut := range []string{"written", "synced", "renamed", "durable"} {
			t.Run(phase+"-"+cut, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "results")
				cmd := exec.Command(os.Args[0], "-test.run=^TestResultStoreOwnedCrashHelper$")
				cmd.Env = append(os.Environ(), "XANDBOX_RESULT_TEST_DIR="+path, "XANDBOX_RESULT_TEST_CUT=result-"+phase+"-"+cut)
				err := cmd.Run()
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal("child did not die", err)
				}
				status, ok := exit.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
					t.Fatal("not exact owned SIGKILL", err)
				}
				names, _ := os.ReadDir(path)
				before := map[string][]byte{}
				for _, n := range names {
					b, _ := os.ReadFile(filepath.Join(path, n.Name()))
					before[n.Name()] = b
				}
				s, e := OpenResultStore(path, resultLimits())
				published := cut == "renamed" || cut == "durable"
				if !published {
					if e == nil {
						s.Close()
						t.Fatal("unknown scratch silently adopted")
					}
				} else {
					if e != nil {
						t.Fatal(e)
					}
					defer s.Close()
					h := resultHeader()
					j, e := s.Get(h.Ref, h.TenantID, h.JobID)
					if e != nil {
						t.Fatal(e)
					}
					if phase == "reserve" {
						if j.Status != "INTERRUPTED" || j.ResultRetained || j.Output.Stdout != "" {
							t.Fatal(j)
						}
					} else {
						if !j.ResultRetained || j.Output != resultTerminal(h).Output {
							t.Fatal(j)
						}
					}
				}
				after, _ := os.ReadDir(path)
				if len(after) != len(before) {
					t.Fatal("crash files deleted")
				}
				for _, n := range after {
					b, _ := os.ReadFile(filepath.Join(path, n.Name()))
					if !bytes.Equal(b, before[n.Name()]) {
						t.Fatal("crash bytes rewritten")
					}
				}
			})
		}
	}
}

func TestResultStoreConcurrentReservationsNeverOvercommitNodeBudget(t *testing.T) {
	h := resultHeader()
	l := ResultLimits{Bytes: 10 * h.charge(), TenantBytes: 10 * h.charge(), Records: 10}
	s := resultOpen(t, filepath.Join(t.TempDir(), "results"), l)
	done := make(chan error, 40)
	for n := 0; n < 40; n++ {
		go func(n int) { q := h; q.JobID = fmt.Sprintf("%032x", n+1); done <- s.Reserve(q) }(n)
	}
	successes := 0
	for n := 0; n < 40; n++ {
		e := <-done
		if e == nil {
			successes++
		} else if !errors.Is(e, ErrResultCapacity) {
			t.Fatal(e)
		}
	}
	if successes != 10 || s.bytes != l.Bytes || len(s.entries) != 10 {
		t.Fatal(successes, s.bytes, len(s.entries))
	}
}

func TestResultStoreMaximumBinaryRecordAndScratchFitPessimisticReservation(t *testing.T) {
	for _, limit := range []int{1, 64, 65_536} {
		h := resultHeader()
		h.MaxOutputBytes = limit
		r := resultEnvelope{Version: 1, Reservation: h, Result: &retainedOutput{Status: "FAILED", FinishedAt: h.StartedAt.Add(time.Second), Stdout: bytes.Repeat([]byte{255}, limit), ExitCode: -1, Error: bytes.Repeat([]byte{255}, MaxLedgerErrorBytes)}}
		raw := resultBytes(r)
		if _, e := decodeResult(raw); e != nil {
			t.Fatal(e)
		}
		if int64(len(raw)+len(resultBytes(resultEnvelope{Version: 1, Reservation: h}))) > h.charge() {
			t.Fatal("record+scratch exceeds pessimistic reservation")
		}
	}
}
func TestResultStorePreRenameDriftDoesNotOverwriteUnknownFinal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results")
	s := resultOpen(t, path, resultLimits())
	h := resultHeader()
	if e := s.Reserve(h); e != nil {
		t.Fatal(e)
	}
	foreign := []byte("SYNTHETIC_FOREIGN_PREFIX")
	s.point = func(stage string) error {
		if stage == "result-complete-synced" {
			return os.WriteFile(filepath.Join(path, h.JobID+".json"), foreign, 0600)
		}
		return nil
	}
	if e := s.Complete(resultTerminal(h)); e == nil {
		t.Fatal("foreign final overwritten")
	}
	raw, e := os.ReadFile(filepath.Join(path, h.JobID+".json"))
	if e != nil || !bytes.Equal(raw, foreign) {
		t.Fatal("foreign bytes changed", e)
	}
	if _, e = s.Get(h.Ref, h.TenantID, h.JobID); !errors.Is(e, ErrResultUnavailable) {
		t.Fatal("failed/ambiguous output published", e)
	}
}

func TestResultStoreCloseDoesNotWaitForRootMetadataIOOrReuseInflightFD(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results")
	s := resultOpen(t, path, resultLimits())
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	s.point = func(stage string) error {
		if stage == "result-root-before-stat" {
			select {
			case <-entered:
			default:
				close(entered)
			}
			<-release
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- s.Reserve(resultHeader()) }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case e := <-closed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("Close waited on pathname IO under fdMu")
	}
	// Force unrelated descriptors to exist while the writer is in flight. Its
	// owned duplicate must never use/close a reused numeric original descriptor.
	f, e := os.CreateTemp(t.TempDir(), "unrelated-")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	unblock()
	if e := <-done; e != nil {
		t.Fatal("in-flight owned descriptor was invalidated", e)
	}
	if _, e = f.WriteString("still-owned"); e != nil {
		t.Fatal("unrelated descriptor affected", e)
	}
	if _, e = s.Get(resultHeader().Ref, "alpha", resultHeader().JobID); !errors.Is(e, ErrResultUnavailable) {
		t.Fatal("new operation admitted after close", e)
	}
}
