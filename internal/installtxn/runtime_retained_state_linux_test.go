//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"golang.org/x/sys/unix"
)

type retainedRootTest struct {
	x        *stopTestModel
	s        *runtimeScope
	stop     *runtimeStoppedWorkProof
	backend  backendInspectionProofs
	cfg      firecracker.Config
	lease    nodecontrol.MaintenanceRecord
	expected sandbox.ResultBoundClosureObservation
	sessions session.ClosureObservation
	owner    sandbox.Record
	header   sandbox.ResultReservation
	raw      []byte
	file     string
}

// Explicit MODEL: the legacy stopped model is only a private format fixture.
// Results are added AFTER its stop, so this must NEVER be called evidence of an
// actual result-bound actor/Stop pipeline. No VM/systemd/quota is exercised.
func newRetainedRootTest(t *testing.T) *retainedRootTest {
	t.Helper()
	x, s, stopped, backend := closedStateModel(t)
	ctx, cancel := workStopContext(t)
	defer cancel()
	_, core, e := retainedLedgerOwners(ctx, s.state.root)
	if e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(x.f.root.Name() + stateDir + "/ledger")
	if e != nil || len(entries) != 1 {
		t.Fatal(entries, e)
	}
	raw, e := os.ReadFile(x.f.root.Name() + stateDir + "/ledger/" + entries[0].Name())
	if e != nil {
		t.Fatal(e)
	}
	owner, e := sandbox.DecodePersistedRecord(raw)
	if e != nil {
		t.Fatal(e)
	}
	h := sandbox.ResultReservation{JobID: runtimeReq("f"), Ref: owner.Ref, TenantID: owner.TenantID, MaxOutputBytes: owner.Limits.MaxOutputBytes, StartedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	root := x.f.root.Name() + stateDir
	raw = retainedTestRow(t, root+"/results", h, true)
	p := sandbox.NewResultInspectionProjection()
	if _, e = p.Add(h.JobID, raw); e != nil {
		t.Fatal(e)
	}
	results, e := p.Observation()
	if e != nil {
		t.Fatal(e)
	}
	sp, e := readTerminalProjection(ctx, &filesystem{root: s.state.root}, false)
	if e != nil {
		t.Fatal(e)
	}
	n, sh := sp.observation()
	drain, e := x.f.runtimeDrainReadIntent()
	if e != nil || drain.Maintenance == nil {
		t.Fatal(drain, e)
	}
	config, e := x.f.read(Root+"/backend.json", 16384, 0600)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := firecracker.DecodeInspectionConfig(config)
	if e != nil {
		t.Fatal(e)
	}
	return &retainedRootTest{x: x, s: s, stop: stopped, backend: backend, cfg: cfg, lease: *drain.Maintenance, expected: sandbox.ResultBoundClosureObservation{Version: 2, Core: core, Results: results}, sessions: session.ClosureObservation{Version: 1, Records: n, RecordsSHA256: sh}, owner: owner, header: h, raw: raw, file: filepath.Join(root, "results", h.JobID+".json")}
}
func retainedTestRow(t *testing.T, path string, h sandbox.ResultReservation, terminal bool) []byte {
	t.Helper()
	s, e := sandbox.OpenResultStore(path, sandbox.ResultLimits{Bytes: 4 << 20, TenantBytes: 4 << 20, Records: 10})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Reserve(h); e != nil {
		t.Fatal(e)
	}
	if terminal {
		j := sandbox.Job{ID: h.JobID, Ref: h.Ref, Status: "EXITED", StartedAt: h.StartedAt, FinishedAt: h.StartedAt.Add(time.Second), Output: sandbox.Output{Stdout: "retained\xff\x00\n", Stderr: "private-test", ExitCode: 0}}
		if e = s.Complete(j); e != nil {
			t.Fatal(e)
		}
	}
	raw, e := os.ReadFile(filepath.Join(path, h.JobID+".json"))
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func (x *retainedRootTest) read(ctx context.Context) (runtimeRetainedStateInventory, error) {
	return readClosedRetainedStateRoot(ctx, x.s.state.root, x.cfg, true, x.lease, x.expected, x.sessions)
}
func retainedRootRefuses(t *testing.T, x *retainedRootTest, ctx context.Context) {
	t.Helper()
	before := coreTree(t, x.x.f.root.Name())
	if v, e := x.read(ctx); e == nil || v != (runtimeRetainedStateInventory{}) {
		t.Fatal("accepted/partial retained root", v, e)
	}
	if !reflect.DeepEqual(before, coreTree(t, x.x.f.root.Name())) {
		t.Fatal("inspection repaired/deleted/rewrote bytes")
	}
}
func TestRuntimeRetainedRootFullReadOnlyProjectionAndLegacyFence(t *testing.T) {
	x := newRetainedRootTest(t)
	ctx, cancel := workStopContext(t)
	defer cancel()
	before := coreTree(t, x.x.f.root.Name())
	for n := 0; n < 2; n++ {
		v, e := x.read(ctx)
		if e != nil || !v.DiskResultBytesMatched || v.Results != x.expected.Results || v.CoreTerminal != x.expected.Core || v.SessionTerminal != x.sessions || v.State.Files != 11 || v.State.Sockets != 1 || !digestPattern.MatchString(v.State.digest) || v.Core.LedgerNonterminal != 0 || v.Core.SessionNonterminal != 0 || v.ResourcesReclaimed || v.ActivationAllowed || v.Core.AcceptedWorkComplete {
			t.Fatal(v, e)
		}
	}
	if v, e := readClosedStateRoot(ctx, x.s.state.root, x.cfg, true); e == nil || v != (runtimeStateFootprint{}) {
		t.Fatal("legacy root reader widened", v, e)
	}
	if v, e := inspectClosedStateModel(ctx, x.x, x.s, x.stop, x.backend); e == nil || v != (runtimeClosedStateInventory{}) {
		t.Fatal("disk report enabled old actor/Stop join", v, e)
	}
	if !reflect.DeepEqual(before, coreTree(t, x.x.f.root.Name())) || len(x.x.jobs) != 2 {
		t.Fatal("reader changed tree or ran a job")
	}
}
func TestRuntimeRetainedRootRejectsCompleteNamespaceAndOwnerDriftUnchanged(t *testing.T) {
	x := newRetainedRootTest(t)
	ctx, cancel := workStopContext(t)
	defer cancel()
	for _, kind := range []string{"scratch", "unknown-root", "missing", "public", "hardlink", "symlink", "fifo", "oversize", "filename", "malformed", "pending", "legacy", "tenant", "generation", "output-limit", "checksum", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			root := x.x.f.root.Name() + stateDir
			file := x.file
			changed := append([]byte(nil), x.raw...)
			originalExpected := x.expected
			defer func() { x.expected = originalExpected }()
			cleanup := func() {}
			switch kind {
			case "scratch":
				p := filepath.Join(root, "results", ".unknown.next")
				if e := os.WriteFile(p, []byte("UNKNOWN_TEST_PREFIX"), 0600); e != nil {
					t.Fatal(e)
				}
				cleanup = func() { _ = os.Remove(p) }
			case "unknown-root":
				p := filepath.Join(root, "catalog")
				if e := os.Mkdir(p, 0700); e != nil {
					t.Fatal(e)
				}
				cleanup = func() { _ = os.Remove(p) }
			case "missing":
				if e := os.Remove(file); e != nil {
					t.Fatal(e)
				}
			case "public":
				if e := os.Chmod(file, 0644); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				p := filepath.Join(t.TempDir(), "linked")
				if e := os.Link(file, p); e != nil {
					t.Fatal(e)
				}
				cleanup = func() { _ = os.Remove(p) }
			case "symlink", "fifo":
				if e := os.Remove(file); e != nil {
					t.Fatal(e)
				}
				if kind == "symlink" {
					p := filepath.Join(t.TempDir(), "target")
					if e := os.WriteFile(p, x.raw, 0600); e != nil {
						t.Fatal(e)
					}
					if e := os.Symlink(p, file); e != nil {
						t.Fatal(e)
					}
				} else if e := unix.Mkfifo(file, 0600); e != nil {
					t.Fatal(e)
				}
			case "oversize":
				changed = bytes.Repeat([]byte{'x'}, sandbox.MaxResultRecordBytes+1)
			case "filename":
				p := filepath.Join(root, "results", runtimeReq("e")+".json")
				if e := os.Rename(file, p); e != nil {
					t.Fatal(e)
				}
				cleanup = func() { _ = os.Remove(p) }
			case "malformed":
				changed = []byte("{")
			case "pending", "tenant", "generation", "output-limit":
				h := x.header
				switch kind {
				case "tenant":
					h.TenantID = "foreign-tenant"
				case "generation":
					h.Ref.Generation = runtimeReq("e")
				case "output-limit":
					if h.MaxOutputBytes == 65_536 {
						h.MaxOutputBytes--
					} else {
						h.MaxOutputBytes++
					}
				}
				changed = retainedTestRow(t, filepath.Join(t.TempDir(), "results"), h, kind != "pending")
				if kind != "pending" {
					// Supply a MATCHING fresh result observation: only the actual
					// ledger tenant/generation/output-limit join can reject it.
					p := sandbox.NewResultInspectionProjection()
					if _, e := p.Add(h.JobID, changed); e != nil {
						t.Fatal(e)
					}
					var e error
					x.expected.Results, e = p.Observation()
					if e != nil {
						t.Fatal(e)
					}
				}
			case "legacy":
				var row struct {
					Version     int                       `json:"version"`
					Reservation sandbox.ResultReservation `json:"reservation"`
					Result      json.RawMessage           `json:"result,omitempty"`
					SHA256      string                    `json:"sha256,omitempty"`
				}
				if e := json.Unmarshal(x.raw, &row); e != nil {
					t.Fatal(e)
				}
				row.Version, row.SHA256 = 1, ""
				var e error
				changed, e = json.Marshal(row)
				if e != nil {
					t.Fatal(e)
				}
				changed = append(changed, '\n')
			case "checksum":
				changed = bytes.Replace(changed, []byte("retained"), []byte("changed!"), 1)
				// stdout is base64; corrupt the checksum itself deterministically.
				start := bytes.LastIndex(changed, []byte(`"sha256":"`)) + len(`"sha256":"`)
				if start < len(`"sha256":"`) || start >= len(changed) {
					t.Fatal("missing checksum")
				}
				if changed[start] == '0' {
					changed[start] = '1'
				} else {
					changed[start] = '0'
				}
			case "unknown-field":
				changed = append(append([]byte(nil), x.raw[:len(x.raw)-2]...), []byte(",\"unknown\":true}\n")...)
			}
			if !bytes.Equal(changed, x.raw) {
				if e := os.WriteFile(file, changed, 0600); e != nil {
					t.Fatal(e)
				}
			}
			retainedRootRefuses(t, x, ctx)
			cleanup()
			// Exact private TEST fixture restoration, never production recovery.
			if e := os.Remove(file); e != nil && !os.IsNotExist(e) {
				t.Fatal(e)
			}
			if e := os.WriteFile(file, x.raw, 0600); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestRuntimeRetainedRootExpectedBindingsAndCanceledInputsRefuseZero(t *testing.T) {
	x := newRetainedRootTest(t)
	ctx, cancel := workStopContext(t)
	defer cancel()
	for _, kind := range []string{"unbounded", "cancelled", "root", "lease", "lease-owner", "core-version", "core-digest", "session", "result-version", "result-count", "result-bytes", "result-reservation", "result-digest"} {
		t.Run(kind, func(t *testing.T) {
			callCtx, root, lease, expected, sessions := ctx, x.s.state.root, x.lease, x.expected, x.sessions
			switch kind {
			case "unbounded":
				callCtx = context.Background()
			case "cancelled":
				var done context.CancelFunc
				callCtx, done = context.WithCancel(ctx)
				done()
			case "root":
				root = nil
			case "lease":
				lease.Version = 0
			case "lease-owner":
				lease.Request.Owner.OperationID = runtimeReq("e")
			case "core-version":
				expected.Core.Version++
			case "core-digest":
				expected.Core.RecordsSHA256 = strings.Repeat("0", 64)
			case "session":
				sessions.RecordsSHA256 = strings.Repeat("0", 64)
			case "result-version":
				expected.Results.Version++
			case "result-count":
				expected.Results.Records++
			case "result-bytes":
				expected.Results.Bytes++
			case "result-reservation":
				expected.Results.ReservedBytes++
			case "result-digest":
				expected.Results.RecordsSHA256 = strings.Repeat("0", 64)
			}
			before := coreTree(t, x.x.f.root.Name())
			if v, e := readClosedRetainedStateRoot(callCtx, root, x.cfg, true, lease, expected, sessions); e == nil || v != (runtimeRetainedStateInventory{}) {
				t.Fatal(v, e)
			}
			if !reflect.DeepEqual(before, coreTree(t, x.x.f.root.Name())) {
				t.Fatal("invalid input changed tree")
			}
		})
	}
}
func TestRuntimeRetainedRootBetweenScanMetadataRebindingAndFailureNeverPartial(t *testing.T) {
	x := newRetainedRootTest(t)
	ctx, cancel := workStopContext(t)
	defer cancel()
	for _, kind := range []string{"same-bytes-new-inode", "root-rebound", "extra", "cut-error", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			callCtx, done := context.WithCancel(ctx)
			defer done()
			cleanup := func() {}
			cut := func() error {
				calls++
				switch kind {
				case "same-bytes-new-inode":
					p := filepath.Join(t.TempDir(), "replaced")
					if e := os.WriteFile(p, x.raw, 0600); e != nil {
						return e
					}
					return os.Rename(p, x.file)
				case "root-rebound":
					root := filepath.Dir(x.file)
					p := filepath.Join(t.TempDir(), "old-results")
					if e := os.Rename(root, p); e != nil {
						return e
					}
					cleanup = func() { _ = os.Remove(x.file); _ = os.Remove(root); _ = os.Rename(p, root) }
					if e := os.Mkdir(root, 0700); e != nil {
						return e
					}
					return os.WriteFile(x.file, x.raw, 0600)
				case "extra":
					p := filepath.Join(filepath.Dir(x.file), ".unknown.next")
					cleanup = func() { _ = os.Remove(p) }
					return os.WriteFile(p, []byte("UNKNOWN_TEST_PREFIX"), 0600)
				case "cut-error":
					return errors.New("TEST_CUT_FAILURE")
				case "cancelled":
					done()
				}
				return nil
			}
			v, e := readClosedRetainedStateRootWithCut(callCtx, x.s.state.root, x.cfg, true, x.lease, x.expected, x.sessions, cut)
			if e == nil || v != (runtimeRetainedStateInventory{}) || calls != 1 {
				t.Fatal(v, e, calls)
			}
			cleanup()
		})
	}
	calls := 0
	before := coreTree(t, x.x.f.root.Name())
	if v, e := readClosedRetainedStateRootWithCut(ctx, x.s.state.root, x.cfg, true, x.lease, x.expected, x.sessions, func() error { calls++; return nil }); e != nil || !v.DiskResultBytesMatched || calls != 1 {
		t.Fatal(v, e, calls)
	}
	if !reflect.DeepEqual(before, coreTree(t, x.x.f.root.Name())) {
		t.Fatal("read-only full scans changed tree")
	}
}
