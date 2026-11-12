//go:build linux || darwin

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func admissionResults(t *testing.T, kind string) *FileResultStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "results")
	s := resultOpen(t, path, resultLimits())
	h := resultHeader()
	for _, id := range []string{strings.Repeat("a", 32), strings.Repeat("d", 32)} {
		h.JobID = id
		if e := s.Reserve(h); e != nil {
			t.Fatal(e)
		}
		if e := s.Complete(resultTerminal(h)); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	l := resultLimits()
	switch kind {
	case "bytes":
		l.Bytes, l.TenantBytes = 2*h.charge()-1, 2*h.charge()-1
	case "tenant":
		l.TenantBytes = 2*h.charge() - 1
	case "records":
		l.Records = 1
	}
	return resultOpen(t, path, l)
}

func TestResultStoreResourceAdmissionPreservesOverBudgetImports(t *testing.T) {
	for _, kind := range []string{"fit", "bytes", "tenant", "records", "closed"} {
		t.Run(kind, func(t *testing.T) {
			s := admissionResults(t, kind)
			before := map[string][]byte{}
			for _, id := range []string{strings.Repeat("a", 32), strings.Repeat("d", 32)} {
				b, e := os.ReadFile(filepath.Join(s.path, id+".json"))
				if e != nil {
					t.Fatal(e)
				}
				before[id] = b
			}
			s.point = func(string) error { t.Fatal("capacity check performed IO/cut"); return nil }
			if kind == "closed" {
				s.Close()
			}
			e := s.CheckResourceCapacity()
			if (e == nil) != (kind == "fit") {
				t.Fatal("current logical reservations silently clamped", e)
			}
			for id, raw := range before {
				after, e := os.ReadFile(filepath.Join(s.path, id+".json"))
				if e != nil || !bytes.Equal(raw, after) {
					t.Fatal("over-budget outcome deleted/repaired")
				}
			}
		})
	}
}

type resultAdmissionProbe struct {
	Driver
	want  ResultLimits
	calls int
	deny  bool
}

func (p *resultAdmissionProbe) CheckResultAdmission(l ResultLimits) error {
	p.calls++
	if p.deny || l != p.want {
		return ErrResultCapacity
	}
	return nil
}

type resultAdmissionStoreProbe struct {
	loads, saves int
	loaded       func()
}

func (s *resultAdmissionStoreProbe) Load() ([]Record, error) {
	s.loads++
	if s.loaded != nil {
		s.loaded()
	}
	return nil, nil
}
func (s *resultAdmissionStoreProbe) Save(Record) error { s.saves++; return nil }

func TestManagerResultAdmissionRejectsBeforeLoadAndRecovery(t *testing.T) {
	for _, kind := range []string{"disabled", "matched", "mismatch", "missing-store", "foreign-store", "typed-nil", "closed", "over-budget"} {
		t.Run(kind, func(t *testing.T) {
			s := &resultAdmissionStoreProbe{}
			d := &resultAdmissionProbe{want: resultLimits()}
			var actual ResultStore
			switch kind {
			case "disabled":
				d.want = ResultLimits{}
			case "missing-store":
			case "foreign-store":
				actual = struct{ ResultStore }{}
			case "typed-nil":
				actual = (*FileResultStore)(nil)
			case "over-budget":
				actual = admissionResults(t, "records")
			default:
				f := resultOpen(t, filepath.Join(t.TempDir(), "results"), resultLimits())
				actual = f
				if kind == "closed" {
					f.Close()
				}
			}
			if kind == "mismatch" {
				d.want.Bytes--
			}
			m, e := NewManager(s, d, Options{Results: actual})
			valid := kind == "matched" || kind == "disabled"
			if (e == nil) != valid {
				t.Fatal("backend result envelope mismatch", e)
			}
			if valid {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if e := m.Close(ctx); e != nil {
					t.Fatal(e)
				}
			} else if s.loads != 0 || s.saves != 0 || m != nil {
				t.Fatal("refusal happened after recovery IO/worker construction")
			}
		})
	}
}

func TestManagerResultAdmissionRechecksAfterBindBeforeWorkers(t *testing.T) {
	d := &resultAdmissionProbe{want: resultLimits()}
	s := &resultAdmissionStoreProbe{loaded: func() { d.deny = true }}
	actual := resultOpen(t, filepath.Join(t.TempDir(), "results"), resultLimits())
	m, e := NewManager(s, d, Options{Results: actual})
	if !errors.Is(e, ErrResultCapacity) || m != nil || d.calls != 2 || s.loads != 1 || s.saves != 0 {
		t.Fatal("first memory check cached across imported binding", e)
	}
}
