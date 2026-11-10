//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
)

func closeRecordTest(t *testing.T, f *filesystem) (runtimeCloseIntent, runtimeCloseCompletion) {
	t.Helper()
	var p runtimeCloseIntent
	var r runtimeCloseCompletion
	if ok, e := f.readCloseRecord("intent.json", &p); e != nil || !ok {
		t.Fatal(ok, e)
	}
	if ok, e := f.readCloseRecord("complete.json", &r); e != nil || !ok {
		t.Fatal(ok, e)
	}
	_, w, e := f.closeWorkLink(p)
	if e != nil || !r.valid(p, w) {
		t.Fatal(r, e)
	}
	return p, r
}
func closeCutTest(t *testing.T, x *stopTestModel, s *runtimeScope, cut string) {
	t.Helper()
	ctx, cancel := workStopContext(t)
	defer cancel()
	hit := false
	x.f.hook = func(at string) error {
		if at == cut {
			hit = true
			return interrupted
		}
		return nil
	}
	if proof, e := finishStopModel(ctx, x, s); proof != nil || !errors.Is(e, interrupted) || !hit || len(x.jobs) != 0 {
		t.Fatal(proof, e, hit, x.jobs)
	}
	x.f.hook = nil
}
func killCloseOriginalsTest(t *testing.T, x *stopTestModel) {
	t.Helper()
	for _, unit := range []string{MainUnit, IngressUnit} {
		if e := x.children[unit].Process.Kill(); e != nil {
			t.Fatal(e)
		}
		if e := x.children[unit].Wait(); e == nil {
			t.Fatal("owned helper did not die")
		}
		x.alive[unit] = false
	}
}

func TestRuntimeWorkCloseDurableIntentBeforeActualRPCAndAnchoredOutcomeBeforeSignals(t *testing.T) {
	x := stopModel(t, "")
	x.client.Close()
	old := x.children[MainUnit]
	_ = old.Process.Kill()
	_ = old.Wait()
	x.children[MainUnit] = runtimeStopChildMode(t, x.f.root.Name(), "main", "populated")
	var setupErr error
	x.client, setupErr = nodecontrol.NewPinnedClient(x.f.root.Name()+stateDir, x.children[MainUnit].Process.Pid)
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	defer x.client.Close()
	s := x.scope(t)
	x.maintain(t, s)
	protected := runtimeProtectedBytes(t, x.f, x.tx)
	before, after, stops := 0, 0, 0
	x.f.hook = func(at string) error {
		if at == "runtime-close-before-begin" {
			before++
			var p runtimeCloseIntent
			ok, e := x.f.readCloseRecord("intent.json", &p)
			if e != nil || !ok {
				return ErrInventory
			}
			if e = x.f.exact(runtimeCloseRoot+"/intent.json", encode(p), 0600); e != nil {
				return e
			}
			work, _, e := x.f.closeWorkLink(p)
			if e != nil {
				return e
			}
			reply, e := x.client.RuntimeClose(context.Background(), *work.Drain.Maintenance, false)
			if e != nil || reply.Phase != "idle" || reply.Core != nil {
				return ErrConflict
			}
			// This actual RPC runs WITHOUT file flock; original operation EX remains.
			done, e := x.f.existingLock(context.Background(), true)
			if e != nil {
				return e
			}
			done()
			bounded, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			if done, e := x.f.operationLock(bounded, false); e == nil {
				done()
				return ErrConflict
			} else if !errors.Is(e, context.DeadlineExceeded) {
				return e
			}
		}
		if at == "runtime-close-after-terminal" {
			after++
		}
		if strings.HasPrefix(at, "runtime-stop-before-") {
			stops++
			stop, e := x.f.readRuntimeStop()
			if e != nil || stop.Version != 4 || x.f.closeStopLink(stop) != nil {
				return ErrInventory
			}
			if s.state != nil {
				return ErrConflict
			}
			p, r := closeRecordTest(t, x.f)
			if r.Core.Records != 1 || r.Sessions.Records != 1 || p.Stop.Version != 3 {
				return ErrInventory
			}
		}
		return nil
	}
	ctx, cancel := workStopContext(t)
	defer cancel()
	proof, e := finishStopModel(ctx, x, s)
	if e != nil || proof == nil || !digestPattern.MatchString(proof.closure) || before != 1 || after != 1 || stops != 2 {
		t.Fatal(proof, e, before, after, stops)
	}
	if len(x.jobs) != 2 || s.state == nil || proof.state != s.state.id {
		t.Fatal("lost stopped original state")
	}
	unchangedRuntimeProtected(t, x.f, protected)
}

var runtimeCloseCuts = []string{
	"runtime-close-intent-written", "runtime-close-intent-synced", "runtime-close-intent-renamed", "runtime-close-intent-durable",
	"runtime-close-before-begin", "runtime-close-after-terminal",
	"runtime-close-complete-written", "runtime-close-complete-synced", "runtime-close-complete-renamed", "runtime-close-complete-durable",
	"runtime-close-anchor-written", "runtime-close-anchor-synced", "runtime-close-anchor-renamed", "runtime-close-anchor-durable",
}

func TestRuntimeWorkCloseAllWriteAheadCutsRetrySameOriginalAndNeverStopEarly(t *testing.T) {
	for _, cut := range runtimeCloseCuts {
		t.Run(cut, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			x.maintain(t, s)
			closeCutTest(t, x, s, cut)
			var original runtimeCloseIntent
			ok, e := x.f.readCloseRecord("intent.json", &original)
			if e != nil || !ok {
				t.Fatal(e)
			}
			s.close()
			fresh, e := os.Open(x.f.root.Name())
			if e != nil {
				t.Fatal(e)
			}
			defer fresh.Close()
			f := &filesystem{root: fresh}
			ctx, cancel := workStopContext(t)
			defer cancel()
			next, e := f.beginRuntimeScope(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer next.close()
			proof, e := next.finishAndStopWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), x.client, systemManager{f, x.manager.command}, x.proof)
			if e != nil || proof == nil || next.state == nil || len(x.jobs) != 2 {
				t.Fatal(proof, e, x.jobs)
			}
			p, r := closeRecordTest(t, f)
			if !bytes.Equal(encode(original), encode(p)) || proof.closure != digest(encode(r)) {
				t.Fatal("recaptured original close authority")
			}
		})
	}
}
func TestRuntimeWorkCloseUnanchoredDeathRefusesAndKnownAnchoredDeathRecovers(t *testing.T) {
	for _, cut := range []string{"runtime-close-intent-durable", "runtime-close-after-terminal", "runtime-close-complete-durable", "runtime-close-anchor-written", "runtime-close-anchor-renamed", "runtime-close-anchor-durable"} {
		t.Run(cut, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			x.maintain(t, s)
			closeCutTest(t, x, s, cut)
			killCloseOriginalsTest(t, x)
			before := coreTree(t, x.f.root.Name())
			ctx, cancel := workStopContext(t)
			defer cancel()
			proof, e := s.finishAndStopWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), nil, x.manager, x.proof)
			known := strings.HasPrefix(cut, "runtime-close-anchor-")
			if (e == nil) != known || (proof != nil) != known || len(x.jobs) != 0 {
				t.Fatal(proof, e, known, x.jobs)
			}
			if !known && !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("unknown death repaired")
			}
			if known && (s.state == nil || proof.state != s.state.id) {
				t.Fatal("missing original state")
			}
		})
	}
}
func TestRuntimeWorkCloseUnknownOrCorruptAuthorityNeverRepairsOrStops(t *testing.T) {
	for _, kind := range []string{"empty", "partial-intent", "unknown-field", "foreign-owner", "work-link", "state", "unexpected", "mode", "alias", "duplicate-scratch", "orphan-anchor", "partial-complete", "unknown-complete"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			x.maintain(t, s)
			closeCutTest(t, x, s, "runtime-close-intent-durable")
			name := x.f.root.Name() + runtimeCloseRoot + "/intent.json"
			raw, e := os.ReadFile(name)
			if e != nil {
				t.Fatal(e)
			}
			var p runtimeCloseIntent
			_, _ = x.f.readCloseRecord("intent.json", &p)
			switch kind {
			case "empty":
				e = os.Remove(name)
			case "partial-intent":
				e = os.WriteFile(name, raw[:15], 0600)
			case "unknown-field":
				e = os.WriteFile(name, append([]byte(`{"unknown":true,`), raw[1:]...), 0600)
			case "foreign-owner":
				p.Stop.Request = runtimeReq("e")
				e = os.WriteFile(name, encode(p), 0600)
			case "work-link":
				p.Input = strings.Repeat("e", 64)
				e = os.WriteFile(name, encode(p), 0600)
			case "state":
				p.Stop.State.LockInode++
				e = os.WriteFile(name, encode(p), 0600)
			case "unexpected":
				e = os.WriteFile(x.f.root.Name()+runtimeCloseRoot+"/foreign", nil, 0600)
			case "mode":
				e = os.Chmod(name, 0644)
			case "alias":
				e = os.Link(name, x.f.root.Name()+runtimeCloseRoot+"/alias")
			case "duplicate-scratch":
				e = os.WriteFile(x.f.root.Name()+runtimeCloseRoot+"/.intent.json.next", raw, 0600)
			case "orphan-anchor":
				e = os.WriteFile(x.f.root.Name()+runtimeCloseAnchor, []byte(strings.Repeat("e", 64)+"\n"), 0600)
			case "partial-complete":
				e = os.WriteFile(x.f.root.Name()+runtimeCloseRoot+"/.complete.json.next", []byte("{"), 0600)
			case "unknown-complete":
				e = os.WriteFile(x.f.root.Name()+runtimeCloseRoot+"/complete.json", []byte("{}\n"), 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			before := coreTree(t, x.f.root.Name())
			ctx, cancel := workStopContext(t)
			defer cancel()
			if proof, e := finishStopModel(ctx, x, s); proof != nil || e == nil || len(x.jobs) != 0 || !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal(proof, e, x.jobs)
			}
		})
	}
}
func TestRuntimeWorkCloseAfterTerminalRejoinsSourceWorkManagerAndOriginalState(t *testing.T) {
	for _, kind := range []string{"source", "work-anchor", "manager", "state-path", "original-death", "foreign-close-intent"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			x.maintain(t, s)
			hit := false
			x.f.hook = func(at string) error {
				if at != "runtime-close-after-terminal" {
					return nil
				}
				hit = true
				switch kind {
				case "source":
					return os.WriteFile(x.f.root.Name()+rolePath("daemon"), []byte("changed"), 0755)
				case "work-anchor":
					return os.WriteFile(x.f.root.Name()+runtimeWorkStopAnchor, []byte(strings.Repeat("e", 64)+"\n"), 0600)
				case "manager":
					x.alive[MainUnit] = false
				case "state-path":
					return os.Rename(x.f.root.Name()+stateDir+"/controller.lock", x.f.root.Name()+stateDir+"/old.lock")
				case "original-death":
					killCloseOriginalsTest(t, x)
				case "foreign-close-intent":
					return os.WriteFile(x.f.root.Name()+runtimeCloseRoot+"/intent.json", []byte("{}\n"), 0600)
				}
				return nil
			}
			ctx, cancel := workStopContext(t)
			defer cancel()
			if proof, e := finishStopModel(ctx, x, s); proof != nil || e == nil || !hit || len(x.jobs) != 0 {
				t.Fatal(proof, e, hit, x.jobs)
			}
			for _, path := range []string{runtimeCloseRoot + "/complete.json", runtimeCloseAnchor, runtimeStopRoot} {
				if yes, e := x.f.exists(path); e != nil || yes {
					t.Fatal("late drift persisted success", path, e)
				}
			}
		})
	}
}
func TestRuntimeWorkCloseCanceledBeforeBeginIsRetryableOnlyOnSameOriginal(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	x.maintain(t, s)
	ctx, cancel := workStopContext(t)
	x.f.hook = func(at string) error {
		if at == "runtime-close-before-begin" {
			cancel()
		}
		return nil
	}
	proof, e := finishStopModel(ctx, x, s)
	if proof != nil || !errors.Is(e, context.Canceled) || len(x.jobs) != 0 {
		t.Fatal(proof, e)
	}
	x.f.hook = nil
	p := readWorkStopIntentTest(t, x.f)
	reply, e := x.client.RuntimeClose(context.Background(), *p.Drain.Maintenance, false)
	if e != nil || reply.Phase != "idle" {
		t.Fatal(reply, e)
	}
	ctx, cancel = workStopContext(t)
	defer cancel()
	if proof, e = finishStopModel(ctx, x, s); e != nil || proof == nil {
		t.Fatal(proof, e)
	}
}
func TestRuntimeWorkCloseUnsupportedOriginalNeverFallsBackToPhysicalStop(t *testing.T) {
	x := stopModel(t, "")
	x.client.Close()
	old := x.children[MainUnit]
	_ = old.Process.Kill()
	_ = old.Wait()
	x.children[MainUnit] = runtimeStopChildMode(t, x.f.root.Name(), "main", "unsupported")
	var e error
	x.client, e = nodecontrol.NewPinnedClient(x.f.root.Name()+stateDir, x.children[MainUnit].Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	defer x.client.Close()
	s := x.scope(t)
	x.maintain(t, s)
	ctx, cancel := workStopContext(t)
	defer cancel()
	proof, e := finishStopModel(ctx, x, s)
	if proof != nil || !errors.Is(e, nodecontrol.ErrRuntimeCloseUnsupported) || len(x.jobs) != 0 || s.state != nil {
		t.Fatal(proof, e, x.jobs)
	}
	if yes, e := x.f.exists(runtimeCloseAnchor); e != nil || yes {
		t.Fatal("unsupported original created completion", e)
	}
}
func TestRuntimeWorkCloseActualCoordinatorSIGKILLRecoversDurableActuatorOutcome(t *testing.T) {
	runRuntimeStopCrashRecoveryMode(t, func(x *stopTestModel, s *runtimeScope) { x.maintain(t, s) }, []string{"runtime-close-intent-durable", "runtime-close-after-terminal", "runtime-close-complete-durable", "runtime-close-anchor-renamed"}, true)
}
func TestRuntimeWorkCloseNamespacesFenceActualStartupAndRawFileEngine(t *testing.T) {
	for _, path := range []string{runtimeCloseRoot, runtimeCloseAnchor, runtimeCloseAnchorScratch} {
		t.Run(strings.TrimPrefix(path, "/etc/"), func(t *testing.T) {
			f, tx, targets := runtimeModel(t)
			var e error
			if path == runtimeCloseRoot {
				e = os.Mkdir(f.root.Name()+path, 0700)
			} else {
				e = os.WriteFile(f.root.Name()+path, []byte("unknown"), 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			before := coreTree(t, f.root.Name())
			if _, e = f.startupFilesLocked(context.Background()); !errors.Is(e, ErrInventory) {
				t.Fatal(e)
			}
			if _, e = runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", targets); !errors.Is(e, ErrInventory) {
				t.Fatal(e)
			}
			if _, e = f.inspectionBase(context.Background(), UpdateInspectionPlan{InstallCommitSHA256: digest(encode(tx)), RetainedRelease: tx.Plan.Release, ReleaseRevision: tx.Plan.ReleaseRevision + 1}); !errors.Is(e, ErrInventory) {
				t.Fatal("inspection ignored close namespace", e)
			}
			if !reflect.DeepEqual(before, coreTree(t, f.root.Name())) {
				t.Fatal("guard changed authority")
			}
		})
	}
}
func TestRuntimeWorkCloseExplicitV4CannotDowngradeOrAlterLegacyCanonicalBytes(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	x.maintain(t, s)
	closeCutTest(t, x, s, "runtime-work-stop-publish-durable")
	stop, e := x.f.readRuntimeStop()
	if e != nil || stop.Version != 4 || x.f.closeStopLink(stop) != nil {
		t.Fatal(stop, e)
	}
	// An independent historical shape, not the extended struct with fields zeroed.
	type legacy struct {
		Version int                          `json:"version"`
		Base    string                       `json:"base_commit_sha256"`
		Request string                       `json:"request_id"`
		Drain   string                       `json:"drain_intent_sha256"`
		Main    nodecontrol.ProcessIdentity  `json:"main"`
		Ingress *nodecontrol.ProcessIdentity `json:"ingress,omitempty"`
		State   *runtimeStateIdentity        `json:"state_identity,omitempty"`
		Work    string                       `json:"work_completion_sha256,omitempty"`
	}
	for version := 1; version <= 3; version++ {
		p := stop
		p.Version, p.Close = version, ""
		if version < 3 {
			p.Work = ""
		}
		if version == 1 {
			p.State = nil
		}
		old := legacy{p.Version, p.Base, p.Request, p.Drain, p.Main, p.Ingress, p.State, p.Work}
		if !validRuntimeStop(p) || !bytes.Equal(encode(p), encode(old)) {
			t.Fatal("legacy canonical bytes changed", version)
		}
		p.Close = stop.Close
		if validRuntimeStop(p) {
			t.Fatal("legacy version adopted new closure field", version)
		}
	}
	for _, kind := range []string{"no-close", "no-work", "no-state", "foreign-close", "foreign-work", "foreign-process"} {
		t.Run(kind, func(t *testing.T) {
			p := stop
			switch kind {
			case "no-close":
				p.Close = ""
			case "no-work":
				p.Work = ""
			case "no-state":
				p.State = nil
			case "foreign-close":
				p.Close = strings.Repeat("e", 64)
			case "foreign-work":
				p.Work = strings.Repeat("e", 64)
			case "foreign-process":
				p.Main.StartTicks++
			}
			if validRuntimeStop(p) && x.f.closeStopLink(p) == nil {
				t.Fatal("foreign or incomplete v4 adopted")
			}
		})
	}
}

func TestRuntimeWorkCloseFailedActualCleanupNeverAuthorizesStop(t *testing.T) {
	x := stopModel(t, "")
	x.client.Close()
	old := x.children[MainUnit]
	_ = old.Process.Kill()
	_ = old.Wait()
	x.children[MainUnit] = runtimeStopChildMode(t, x.f.root.Name(), "main", "cleanup-failed")
	var e error
	x.client, e = nodecontrol.NewPinnedClient(x.f.root.Name()+stateDir, x.children[MainUnit].Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	defer x.client.Close()
	s := x.scope(t)
	x.maintain(t, s)
	ctx, cancel := workStopContext(t)
	defer cancel()
	proof, e := finishStopModel(ctx, x, s)
	if proof != nil || e == nil || len(x.jobs) != 0 || s.state != nil {
		t.Fatal(proof, e, x.jobs)
	}
	p := readWorkStopIntentTest(t, x.f)
	r, e := x.client.RuntimeClose(ctx, *p.Drain.Maintenance, false)
	if e != nil || r.Phase != "fenced" || r.Core != nil || r.Sessions != nil {
		t.Fatal(r, e)
	}
	for _, path := range []string{runtimeCloseRoot + "/complete.json", runtimeCloseAnchor, runtimeStopRoot} {
		if yes, e := x.f.exists(path); e != nil || yes {
			t.Fatal("failed cleanup created authority", path, e)
		}
	}
}
func TestRuntimeWorkCloseKnownReceiptCorruptionOrReplacementNeverBecomesStop(t *testing.T) {
	for _, kind := range []string{"receipt", "anchor", "missing-anchor-dead", "scratch-prefix", "duplicate-anchor", "replacement"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			x.maintain(t, s)
			closeCutTest(t, x, s, "runtime-close-anchor-durable")
			_, r := closeRecordTest(t, x.f)
			var e error
			switch kind {
			case "receipt":
				r.Core.Records++
				e = os.WriteFile(x.f.root.Name()+runtimeCloseRoot+"/complete.json", encode(r), 0600)
			case "anchor":
				e = os.WriteFile(x.f.root.Name()+runtimeCloseAnchor, []byte(strings.Repeat("e", 64)+"\n"), 0600)
			case "missing-anchor-dead":
				e = os.Remove(x.f.root.Name() + runtimeCloseAnchor)
				killCloseOriginalsTest(t, x)
			case "scratch-prefix":
				e = os.Rename(x.f.root.Name()+runtimeCloseAnchor, x.f.root.Name()+runtimeCloseAnchorScratch)
				if e == nil {
					e = os.WriteFile(x.f.root.Name()+runtimeCloseAnchorScratch, []byte("e"), 0600)
				}
			case "duplicate-anchor":
				e = os.WriteFile(x.f.root.Name()+runtimeCloseAnchorScratch, []byte(digest(encode(r))+"\n"), 0600)
			case "replacement":
				killCloseOriginalsTest(t, x)
				x.children[MainUnit] = runtimeStopChildMode(t, x.f.root.Name(), "main", "unsupported")
				x.alive[MainUnit] = true
			}
			if e != nil {
				t.Fatal(e)
			}
			before := coreTree(t, x.f.root.Name())
			ctx, cancel := workStopContext(t)
			defer cancel()
			if proof, e := finishStopModel(ctx, x, s); proof != nil || e == nil || len(x.jobs) != 0 || !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal(proof, e, x.jobs)
			}
		})
	}
}
