package installtxn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
)

// TEST-only backend metadata model. Embedded MockDriver never launches a VM or
// command. A firecracker label here is NOT backend/KVM acceptance evidence.
type terminalProjectionModelDriver struct{ sandbox.Driver }

func (d *terminalProjectionModelDriver) Name() string { return "firecracker" }

func terminalValueRows() (sandbox.Record, session.Record) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	r := sandbox.Record{Ref: sandbox.Ref{ID: strings.Repeat("1", 32), Generation: strings.Repeat("2", 32)}, Backend: "firecracker", TenantID: "alpha", CreateKeyHash: strings.Repeat("3", 64), CreateSpecHash: strings.Repeat("4", 64), State: sandbox.Destroyed, DeleteRequested: true, Limits: sandbox.Limits{MaxExecMS: 1000, MaxOutputBytes: 4096, MaxJobs: 16}, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour), StoppedAt: now, DestroyedAt: now}
	j := session.Record{ID: strings.Repeat("5", 32), TenantID: r.TenantID, CreateKeyHash: strings.Repeat("6", 64), CreateSpecHash: strings.Repeat("7", 64), Revision: 1, Current: r.Ref, State: session.Closed, CreatedAt: now, UpdatedAt: now, Attempts: []session.Attempt{{KeyHash: strings.Repeat("6", 64), SpecHash: strings.Repeat("7", 64), ResultRevision: 1, Target: r.Ref, State: "COMMITTED", StartedAt: now, ReadyAt: now, FencedAt: now, CommitStartedAt: now}}}
	return r, j
}
func terminalEnvelope(t *testing.T, r any) []byte {
	t.Helper()
	b, e := json.Marshal(struct {
		Version int `json:"version"`
		Record  any `json:"record"`
	}{1, r})
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func terminalGolden(t *testing.T, domain string, records ...any) string {
	t.Helper()
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	e := json.NewEncoder(h)
	for _, r := range records {
		if err := e.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestRuntimeCoreTerminalProjectionMatchesActualClosedActors(t *testing.T) {
	for _, populated := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "populated"}[populated], func(t *testing.T) {
			root := t.TempDir()
			ledger, e := sandbox.NewFileStore(filepath.Join(root, "ledger"))
			if e != nil {
				t.Fatal(e)
			}
			driver, e := sandbox.NewMockDriver(filepath.Join(root, "instances"))
			if e != nil {
				t.Fatal(e)
			}
			gate := sandbox.NewAdmissionGate(true)
			core, e := sandbox.NewManager(ledger, &terminalProjectionModelDriver{Driver: driver}, sandbox.Options{AdmissionGate: gate})
			if e != nil {
				t.Fatal(e)
			}
			journal, e := session.NewFileStore(filepath.Join(root, "sessions"))
			if e != nil {
				t.Fatal(e)
			}
			broker, e := session.New(core, journal, session.Options{})
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			defer core.Close(ctx)
			defer broker.Close(ctx)
			if populated {
				if _, e = broker.Open(ctx, sandbox.Owner{TenantID: "alpha", MaxInstances: 4}, "original", sandbox.CreateRequest{}); e != nil {
					t.Fatal(e)
				}
			}
			if !gate.FreezeAcceptedWork().Complete() {
				t.Fatal("unfinished actual work")
			}
			if e = broker.Close(ctx); e != nil {
				t.Fatal(e)
			}
			if e = core.Close(ctx); e != nil {
				t.Fatal(e)
			}
			cp, e := core.ClosedProof(ctx)
			if e != nil {
				t.Fatal(e)
			}
			sp, e := broker.ClosedProof(ctx)
			if e != nil {
				t.Fatal(e)
			}
			for _, isCore := range []bool{true, false} {
				dir := "sessions"
				if isCore {
					dir = "ledger"
				}
				names, e := os.ReadDir(filepath.Join(root, dir))
				if e != nil {
					t.Fatal(e)
				}
				sort.Slice(names, func(i, j int) bool { return names[i].Name() < names[j].Name() })
				p := newTerminalProjection(isCore)
				for _, name := range names {
					raw, e := os.ReadFile(filepath.Join(root, dir, name.Name()))
					if e != nil {
						t.Fatal(e)
					}
					if e = p.add(strings.TrimSuffix(name.Name(), ".json"), raw); e != nil {
						t.Fatal(e)
					}
				}
				n, h := p.observation()
				if isCore {
					if got := cp.Observation(); n != got.Records || h != got.RecordsSHA256 {
						t.Fatal("actual Core actor projection differs", n, got)
					}
				} else {
					if got := sp.Observation(); n != got.Records || h != got.RecordsSHA256 {
						t.Fatal("actual session actor projection differs", n, got)
					}
				}
			}
		})
	}
}
func TestRuntimeCoreTerminalProjectionGoldenAndFreshBytes(t *testing.T) {
	r, j := terminalValueRows()
	for _, isCore := range []bool{true, false} {
		p := newTerminalProjection(isCore)
		n, h := p.observation()
		domain := "xandbox-session-closure-v1\n"
		if isCore {
			domain = "xandbox-core-closure-v1\n"
		}
		if n != 0 || h != terminalGolden(t, domain) {
			t.Fatal("empty domain")
		}
		var row any = j
		id := j.ID
		if isCore {
			row, id = r, r.ID
		}
		raw := terminalEnvelope(t, row)
		if e := p.add(id, raw); e != nil {
			t.Fatal(e)
		}
		n, h = p.observation()
		if n != 1 || h != terminalGolden(t, domain, row) {
			t.Fatal("pinned actor Encoder wire differs")
		}
		for i := range raw {
			raw[i] = 0
		}
		if n2, h2 := p.observation(); n2 != n || h2 != h {
			t.Fatal("retained caller buffer")
		}
	}
}
func TestRuntimeCoreTerminalProjectionRejectsUnknownUnfinishedAndStickyPrefixes(t *testing.T) {
	for _, kind := range []string{"mock", "unfinished-core", "unfinished-session", "unfinished-attempt", "wrong-core-id", "wrong-session-id", "unknown", "duplicate", "legacy", "large-core", "large-session", "trailing", "bad-core-time"} {
		t.Run(kind, func(t *testing.T) {
			r, j := terminalValueRows()
			core := true
			id := r.ID
			var row any = r
			switch kind {
			case "mock":
				r.Backend = "mock"
				row = r
			case "unfinished-core":
				r.State = sandbox.Reclaiming
				r.DestroyedAt = time.Time{}
				row = r
			case "unfinished-session":
				core = false
				j.State = session.Active
				row = j
				id = j.ID
			case "unfinished-attempt":
				core = false
				j.State = session.Closed
				j.Attempts[0].State = session.Prepared
				row = j
				id = j.ID
			case "wrong-core-id":
				id = strings.Repeat("9", 32)
			case "wrong-session-id":
				core = false
				row = j
				id = strings.Repeat("9", 32)
			case "bad-core-time":
				r.StoppedAt = time.Time{}
				row = r
			}
			raw := terminalEnvelope(t, row)
			switch kind {
			case "unknown":
				raw = append([]byte(`{"unexpected":true,`), raw[1:]...)
			case "duplicate":
				raw = append([]byte(`{"version":1,`), raw[1:]...)
			case "legacy":
				raw = []byte(`{"version":0}`)
			case "large-core":
				raw = bytes.Repeat([]byte(" "), sandbox.MaxLedgerRecordBytes+1)
			case "large-session":
				core = false
				id = j.ID
				raw = bytes.Repeat([]byte(" "), session.MaxRecordBytes+1)
			case "trailing":
				raw = append(raw, []byte("{}")...)
			}
			p := newTerminalProjection(core)
			if p.add(id, raw) == nil {
				t.Fatal("invalid raw record accepted")
			}
			if n, h := p.observation(); n != 0 || h != "" {
				t.Fatal("partial report")
			}
			goodCore, goodSession := terminalValueRows()
			good, gid := terminalEnvelope(t, goodCore), goodCore.ID
			if !core {
				good, gid = terminalEnvelope(t, goodSession), goodSession.ID
			}
			if p.add(gid, good) == nil {
				t.Fatal("failed stream resumed")
			}
		})
	}
}
func TestRuntimeCoreTerminalProjectionOrderingBoundsAndDomainSeparation(t *testing.T) {
	r, j := terminalValueRows()
	for _, isCore := range []bool{true, false} {
		var row any = j
		id := j.ID
		max := session.MaxRecords
		if isCore {
			row, id, max = r, r.ID, sandbox.MaxLedgerRecords
		}
		for _, kind := range []string{"duplicate", "descending", "invalid-id", "counter-bound"} {
			p := newTerminalProjection(isCore)
			raw := terminalEnvelope(t, row)
			switch kind {
			case "duplicate":
				if e := p.add(id, raw); e != nil {
					t.Fatal(e)
				}
			case "descending":
				p.last = strings.Repeat("f", 32)
			case "invalid-id":
				id = "../foreign"
			case "counter-bound":
				p.count = max // Counter-bound model, not a 100k-file performance claim.
			}
			if p.add(id, raw) == nil {
				t.Fatal("ordering/closed bound", kind)
			}
			if _, h := p.observation(); h != "" {
				t.Fatal("failed observation")
			}
			id = j.ID
			if isCore {
				id = r.ID
			}
		}
	}
	var nilProjection *terminalProjection
	if nilProjection.add(r.ID, terminalEnvelope(t, r)) == nil {
		t.Fatal("nil")
	}
	_, coreHash := newTerminalProjection(true).observation()
	_, sessionHash := newTerminalProjection(false).observation()
	if coreHash == sessionHash {
		t.Fatal("domains alias")
	}
}
