package session

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func storeFixture(n int) Record {
	now := time.Date(2026, 1, 1, 0, 0, 0, 123456789, time.UTC)
	r := Record{ID: strings.Repeat("1", 32), TenantID: strings.Repeat("t", 64), State: Active, CreatedAt: now, UpdatedAt: now}
	for x := 0; x < n; x++ {
		target := sandbox.Ref{ID: fmt.Sprintf("%032x", x+1), Generation: strings.Repeat("a", 32)}
		a := Attempt{KeyHash: fmt.Sprintf("%064x", x+1), SpecHash: strings.Repeat("b", 64), ExpectedRevision: uint64(x), ResultRevision: uint64(x + 1), From: r.Current, Target: target, State: "COMMITTED", StartedAt: now, ReadyAt: now, FencedAt: now, CommitStartedAt: now, Timings: Timings{Measured: true, TotalMS: math.MaxFloat64, CandidateReadyMS: 1, FenceToCommitMS: 1}}
		r.Attempts = append(r.Attempts, a)
		r.Current = target
		r.Revision = uint64(x + 1)
	}
	r.CreateKeyHash, r.CreateSpecHash = r.Attempts[0].KeyHash, r.Attempts[0].SpecHash
	return r
}
func TestSessionMaximumHistoryFitsBoundedFormat(t *testing.T) {
	r := storeFixture(MaxHistory)
	data, e := json.MarshalIndent(envelope{Version: 1, Record: &r}, "", "  ")
	if e != nil || len(data) > maxFileBytes {
		t.Fatal("declared history exceeds byte policy", len(data), e)
	}
	s, e := NewFileStore(filepath.Join(t.TempDir(), "sessions"))
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Save(r); e != nil {
		t.Fatal(e)
	}
	rows, e := s.Load()
	if e != nil || len(rows) != 1 || len(rows[0].Attempts) != MaxHistory {
		t.Fatal(e)
	}
}
func TestSessionDecoderRejectsAmbiguousOrBrokenHistory(t *testing.T) {
	r := storeFixture(2)
	raw, _ := json.Marshal(envelope{Version: 1, Record: &r})
	for _, data := range [][]byte{[]byte("null"), []byte(`{"version":1,"record":null}`), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"VERSION":1`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":2`), 1), bytes.Replace(raw, []byte(`"revision":2`), []byte(`"revision":1`), 1), append(append([]byte{}, raw...), []byte("{}")...)} {
		if _, e := decodeRecord(data); e == nil {
			t.Fatal("invalid envelope accepted")
		}
	}
	for _, mutate := range []func(*Record){
		func(r *Record) {
			r.Attempts[1].ExpectedRevision = 0
			r.Attempts[1].ResultRevision = 1
			r.Attempts[1].From = sandbox.Ref{}
		},
		func(r *Record) { r.Attempts[1].Target = r.Attempts[0].Target; r.Current = r.Attempts[0].Target },
		func(r *Record) { r.Attempts[0].State = Prepared },
		func(r *Record) { r.Attempts[1].KeyHash = r.Attempts[0].KeyHash },
		func(r *Record) { r.Attempts[1].Timings.TotalMS = math.Inf(1) },
	} {
		bad := clone(r)
		mutate(&bad)
		if e := validate(bad); e == nil {
			t.Fatal("broken revision history accepted")
		}
	}
}
func TestSessionLoaderValidatesBeforeRemovingOrphans(t *testing.T) {
	s, e := NewFileStore(filepath.Join(t.TempDir(), "sessions"))
	if e != nil {
		t.Fatal(e)
	}
	r := storeFixture(1)
	raw, _ := json.Marshal(envelope{Version: 1, Record: &r})
	path := filepath.Join(s.dir, r.ID+".json")
	tmp := filepath.Join(s.dir, ".session-12345")
	os.WriteFile(tmp, []byte("not a commit"), 0600)
	os.WriteFile(path, []byte(`{"version":99}`), 0600)
	if _, e = s.Load(); e == nil {
		t.Fatal("unknown version accepted")
	}
	if _, e = os.Stat(tmp); e != nil {
		t.Fatal("pruned before complete validation")
	}
	os.WriteFile(path, raw, 0600)
	if _, e = s.Load(); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(tmp); !os.IsNotExist(e) {
		t.Fatal("orphan retained", e)
	}
	os.WriteFile(path, bytes.Repeat([]byte(" "), maxFileBytes+1), 0600)
	if _, e = s.Load(); e == nil {
		t.Fatal("oversized record accepted")
	}
}
func FuzzSessionRecord(f *testing.F) {
	r := storeFixture(2)
	raw, _ := json.Marshal(envelope{Version: 1, Record: &r})
	f.Add(raw)
	f.Add([]byte(`{"version":99}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFileBytes {
			t.Skip()
		}
		r, e := decodeRecord(data)
		if e == nil {
			if e := validate(r); e != nil {
				t.Fatal(e)
			}
		}
	})
}
