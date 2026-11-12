//go:build linux

package installtxn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
)

func terminalStoppedModel(t *testing.T, mode string) (*stopTestModel, *runtimeScope, *runtimeStoppedWorkProof) {
	t.Helper()
	return terminalStoppedModelWithInitial(t, mode, terminalActorInitialModel)
}

// TEST-only initialization seam; every original scope, maintenance, work/close,
// physical Stop and retained-state step below remains unchanged.
func terminalStoppedModelWithInitial(t *testing.T, mode string, initial func(*testing.T, string) *stopTestModel) (*stopTestModel, *runtimeScope, *runtimeStoppedWorkProof) {
	t.Helper()
	x := initial(t, mode)
	s := x.scope(t)
	x.maintain(t, s)
	ctx, cancel := workStopContext(t)
	defer cancel()
	proof, e := finishStopModel(ctx, x, s)
	if e != nil || proof == nil {
		t.Fatal(proof, e)
	}
	return x, s, proof
}
func inspectTerminalModel(ctx context.Context, x *stopTestModel, s *runtimeScope, p *runtimeStoppedWorkProof) (runtimeTerminalInventory, error) {
	return s.inspectClosedTerminalWithProof(ctx, digest(encode(x.tx)), runtimeReq("b"), p, x.manager, x.proof.empty)
}
func terminalRecordPath(t *testing.T, x *stopTestModel, core bool) string {
	t.Helper()
	dir := "sessions"
	if core {
		dir = "ledger"
	}
	dir = x.f.root.Name() + stateDir + "/" + dir
	names, e := os.ReadDir(dir)
	if e != nil || len(names) != 1 {
		t.Fatal(names, e)
	}
	return filepath.Join(dir, names[0].Name())
}
func mutateTerminalRecord(t *testing.T, path string, core bool) {
	t.Helper()
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var row any
	if core {
		r, e := sandbox.DecodePersistedRecord(raw)
		if e != nil {
			t.Fatal(e)
		}
		r.LastError = "same-count different terminal record"
		row = r
	} else {
		r, e := session.DecodePersistedRecord(raw)
		if e != nil {
			t.Fatal(e)
		}
		r.Attempts[0].Timings.TotalMS += 1
		row = r
	}
	if e = os.WriteFile(path, terminalEnvelope(t, row), 0600); e != nil {
		t.Fatal(e)
	}
}
func TestRuntimeCoreTerminalOriginalHeldV4MatchesActualRecordBytesReadOnly(t *testing.T) {
	for _, mode := range []string{"", "terminal-firecracker-model"} {
		t.Run(map[string]string{"": "empty", "terminal-firecracker-model": "populated-model"}[mode], func(t *testing.T) {
			x, s, p := terminalStoppedModel(t, mode)
			ctx, cancel := workStopContext(t)
			defer cancel()
			before := coreTree(t, x.f.root.Name())
			_, closed := closeRecordTest(t, x.f)
			for n := 0; n < 2; n++ {
				v, e := inspectTerminalModel(ctx, x, s, p)
				if e != nil || !v.RawTerminalMatched || !v.Core.CoreAuthorityParsed || v.CoreTerminal != closed.Core || v.SessionTerminal != closed.Sessions || v.ResourcesReclaimed || v.ActivationAllowed || v.Core.AcceptedWorkComplete || v.Core.ResourcesReclaimed || v.Core.ActivationAllowed {
					t.Fatal(v, e)
				}
			}
			if len(x.jobs) != 2 || !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("inspection mutated original tree or jobs")
			}
			if v, e := s.inspectClosedTerminal(ctx, digest(encode(x.tx)), runtimeReq("b"), p, x.manager); e == nil || v != (runtimeTerminalInventory{}) {
				t.Fatal("production accepted fake kernel domain", v, e)
			}
		})
	}
}
func TestRuntimeCoreTerminalRejectsUnboundedCanceledForeignOrClosedScope(t *testing.T) {
	x, s, p := terminalStoppedModel(t, "")
	ctx, cancel := workStopContext(t)
	defer cancel()
	tests := []struct {
		name string
		ctx  context.Context
		s    *runtimeScope
		p    *runtimeStoppedWorkProof
	}{
		{"unbounded", context.Background(), s, p}, {"nil-proof", ctx, s, nil}, {"wrong-scope", ctx, &runtimeScope{fs: x.f}, p},
	}
	canceled, done := context.WithCancel(ctx)
	done()
	tests = append(tests, struct {
		name string
		ctx  context.Context
		s    *runtimeScope
		p    *runtimeStoppedWorkProof
	}{"canceled", canceled, s, p})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := coreTree(t, x.f.root.Name())
			if v, e := inspectTerminalModel(test.ctx, x, test.s, test.p); e == nil || v != (runtimeTerminalInventory{}) {
				t.Fatal(v, e)
			}
			if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("refusal wrote")
			}
		})
	}
	s.close()
	if v, e := inspectTerminalModel(ctx, x, s, p); e == nil || v != (runtimeTerminalInventory{}) {
		t.Fatal("closed scope", v, e)
	}
}
func TestRuntimeCoreTerminalEveryOpaqueLinkAndHeldStateMustMatch(t *testing.T) {
	x, s, p := terminalStoppedModel(t, "")
	ctx, cancel := workStopContext(t)
	defer cancel()
	for _, field := range []string{"intent", "completion", "closure", "stop", "state"} {
		t.Run(field, func(t *testing.T) {
			copy := *p
			switch field {
			case "intent":
				copy.intent = strings.Repeat("0", 64)
			case "completion":
				copy.completion = strings.Repeat("0", 64)
			case "closure":
				copy.closure = strings.Repeat("0", 64)
			case "stop":
				copy.stop = strings.Repeat("0", 64)
			case "state":
				copy.state.LockInode++
			}
			before := coreTree(t, x.f.root.Name())
			if v, e := inspectTerminalModel(ctx, x, s, &copy); e == nil || v != (runtimeTerminalInventory{}) {
				t.Fatal("unbound proof", v, e)
			}
			if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("failure wrote")
			}
		})
	}
}
func TestRuntimeCoreTerminalSameCountsChangedRecordsAndUnknownPathsNeverMatch(t *testing.T) {
	for _, kind := range []string{"core-value", "session-value", "mock-backend", "unknown", "mode", "hardlink", "symlink", "malformed", "filename", "close-anchor"} {
		t.Run(kind, func(t *testing.T) {
			mode := "terminal-firecracker-model"
			if kind == "mock-backend" {
				mode = "populated"
			}
			x, s, p := terminalStoppedModel(t, mode)
			ctx, cancel := workStopContext(t)
			defer cancel()
			core := terminalRecordPath(t, x, true)
			switch kind {
			case "core-value":
				mutateTerminalRecord(t, core, true)
			case "session-value":
				mutateTerminalRecord(t, terminalRecordPath(t, x, false), false)
			case "unknown":
				if e := os.WriteFile(filepath.Dir(core)+"/unknown", []byte("untouched"), 0600); e != nil {
					t.Fatal(e)
				}
			case "mode":
				if e := os.Chmod(core, 0644); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(core, filepath.Dir(core)+"/unknown"); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Rename(core, core+".original"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(core+".original", core); e != nil {
					t.Fatal(e)
				}
			case "malformed":
				if e := os.WriteFile(core, []byte("{}"), 0600); e != nil {
					t.Fatal(e)
				}
			case "filename":
				if e := os.Rename(core, filepath.Dir(core)+"/"+runtimeReq("0")+".json"); e != nil {
					t.Fatal(e)
				}
			case "close-anchor":
				if e := os.WriteFile(x.f.root.Name()+runtimeCloseAnchor, []byte(strings.Repeat("0", 64)+"\n"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			before := coreTree(t, x.f.root.Name())
			if v, e := inspectTerminalModel(ctx, x, s, p); e == nil || v != (runtimeTerminalInventory{}) {
				t.Fatal("unknown/changed records matched", v, e)
			}
			if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("inspection repaired failure")
			}
		})
	}
}
func TestRuntimeCoreTerminalBoundaryDriftAndReadErrorsNeverPublishPartial(t *testing.T) {
	for _, kind := range []string{"core", "sessions", "raw-format", "raw-after-bound", "source", "close", "root", "cancel", "read-error"} {
		t.Run(kind, func(t *testing.T) {
			x, s, p := terminalStoppedModel(t, "terminal-firecracker-model")
			ctx, cancel := workStopContext(t)
			defer cancel()
			hit := false
			stage := "runtime-terminal-after-before"
			if kind == "sessions" {
				stage = "runtime-terminal-after-core"
			}
			if kind == "raw-after-bound" {
				stage = "runtime-terminal-after-bound"
			}
			if kind == "source" || kind == "close" {
				stage = "runtime-terminal-after-projection"
			}
			x.f.hook = func(at string) error {
				if at != stage || hit {
					return nil
				}
				hit = true
				switch kind {
				case "core", "raw-after-bound":
					mutateTerminalRecord(t, terminalRecordPath(t, x, true), true)
				case "raw-format":
					path := terminalRecordPath(t, x, true)
					raw, e := os.ReadFile(path)
					if e != nil {
						return e
					}
					return os.WriteFile(path, append([]byte(" \n"), raw...), 0600)
				case "sessions":
					mutateTerminalRecord(t, terminalRecordPath(t, x, false), false)
				case "source":
					path := x.f.root.Name() + rolePath("daemon")
					if e := os.Chmod(path, 0755); e != nil {
						return e
					}
					return os.WriteFile(path, []byte("changed-source"), 0755)
				case "close":
					return os.WriteFile(x.f.root.Name()+runtimeCloseAnchor, []byte(strings.Repeat("0", 64)+"\n"), 0600)
				case "root":
					return os.Rename(x.f.root.Name()+stateDir, x.f.root.Name()+stateDir+".rebound")
				case "cancel":
					cancel()
				case "read-error":
					return interrupted
				}
				return nil
			}
			v, e := inspectTerminalModel(ctx, x, s, p)
			x.f.hook = nil
			if !hit || e == nil || v != (runtimeTerminalInventory{}) {
				t.Fatal("boundary produced partial report", v, e, hit)
			}
			if kind == "read-error" && !errors.Is(e, interrupted) {
				t.Fatal(e)
			}
			if len(x.jobs) != 2 {
				t.Fatal("inspection issued a new Stop")
			}
		})
	}
}
func TestRuntimeCoreTerminalFreshScopeRejoinsKnownCloseButOldProofNeverTransfers(t *testing.T) {
	x, s, p := terminalStoppedModel(t, "terminal-firecracker-model")
	s.close()
	ctx, cancel := workStopContext(t)
	defer cancel()
	next, e := x.f.beginRuntimeScope(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer next.close()
	if v, e := inspectTerminalModel(ctx, x, next, p); e == nil || v != (runtimeTerminalInventory{}) {
		t.Fatal("old scope capability transferred", v, e)
	}
	known, e := next.finishAndStopWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), nil, x.manager, x.proof)
	if e != nil || known == nil {
		t.Fatal(known, e)
	}
	before := coreTree(t, x.f.root.Name())
	if v, e := inspectTerminalModel(ctx, x, next, known); e != nil || !v.RawTerminalMatched {
		t.Fatal(v, e)
	}
	if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
		t.Fatal("rejoin inspection wrote")
	}
}
func TestRuntimeCoreTerminalMatchNeverUnfencesStartupOrAuthorizesRawFiles(t *testing.T) {
	x, s, p := terminalStoppedModel(t, "")
	ctx, cancel := workStopContext(t)
	defer cancel()
	v, e := inspectTerminalModel(ctx, x, s, p)
	if e != nil || !v.RawTerminalMatched || v.ResourcesReclaimed || v.ActivationAllowed {
		t.Fatal(v, e)
	}
	if _, e = x.f.startupFilesLocked(ctx); !errors.Is(e, ErrInventory) {
		t.Fatal("terminal match unfenced startup", e)
	}
	s.close()
	bounded, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if _, e = runtimeApply(bounded, x.f, x.tx, 0, runtimeReq("c"), "forward", nil); !errors.Is(e, ErrInventory) {
		t.Fatal("terminal match authorized raw files", e)
	}
}
