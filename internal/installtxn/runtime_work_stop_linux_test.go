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

	"golang.org/x/sys/unix"
)

func finishStopModel(ctx context.Context, x *stopTestModel, s *runtimeScope) (*runtimeStoppedWorkProof, error) {
	return s.finishAndStopWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), x.client, x.manager, x.proof)
}
func workStopContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 15*time.Second)
}
func readWorkStopIntentTest(t *testing.T, f *filesystem) runtimeWorkStopIntent {
	t.Helper()
	var p runtimeWorkStopIntent
	ok, e := f.readWorkStopRecord("intent.json", &p)
	if e != nil || !ok || !p.valid() {
		t.Fatal(p, ok, e)
	}
	return p
}
func runtimeWorkCompletionFromTest(t *testing.T, f *filesystem) runtimeWorkCompletion {
	t.Helper()
	var r runtimeWorkCompletion
	ok, e := f.readWorkStopRecord("complete.json", &r)
	if e != nil || !ok {
		t.Fatal(e)
	}
	return r
}
func workStopKnownBeforeSignal(t *testing.T, x *stopTestModel) {
	t.Helper()
	stop, e := x.f.readRuntimeStop()
	if e != nil || stop.Version != 4 || x.f.closeStopLink(stop) != nil {
		t.Fatal("Stop lacks exact anchored completion", stop, e)
	}
}

func TestRuntimeWorkStopCompletionPrecedesSignalsAndOriginalStateRemainsHeld(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	x.maintain(t, s)
	protected := runtimeProtectedBytes(t, x.f, x.tx)
	cuts := 0
	x.f.hook = func(at string) error {
		if strings.HasPrefix(at, "runtime-stop-before-") {
			cuts++
			workStopKnownBeforeSignal(t, x)
			if s.state != nil {
				return errors.New("daemon state acquired before death")
			}
		}
		return nil
	}
	ctx, cancel := workStopContext(t)
	defer cancel()
	proof, e := finishStopModel(ctx, x, s)
	if e != nil || proof == nil || proof.scope != s || s.state == nil || proof.state != s.state.id || cuts != 2 || strings.Join(x.jobs, ",") != IngressUnit+","+MainUnit {
		t.Fatal(proof, e, cuts, x.jobs)
	}
	p := readWorkStopIntentTest(t, x.f)
	var r runtimeWorkCompletion
	if ok, e := x.f.readWorkStopRecord("complete.json", &r); e != nil || !ok || !r.valid(p) || proof.completion != digest(encode(r)) || proof.intent != digest(encode(p)) {
		t.Fatal(r, e)
	}
	other, e := x.f.openRuntimeState()
	if e != nil {
		t.Fatal(e)
	}
	if e = acquireRuntimeState(other); !errors.Is(e, unix.EWOULDBLOCK) {
		other.close()
		t.Fatal("original state lease lost", e)
	}
	other.close()
	if _, e = x.f.startupFilesLocked(ctx); !errors.Is(e, ErrInventory) {
		t.Fatal("work proof enabled startup", e)
	}
	unchangedRuntimeProtected(t, x.f, protected)
	s.close()
	other, e = x.f.openRuntimeState()
	if e != nil {
		t.Fatal(e)
	}
	defer other.close()
	if e = acquireRuntimeState(other); e != nil {
		t.Fatal("scope did not release original state", e)
	}
}

func TestRuntimeWorkStopActualPendingAndNonzeroNeverAuthorizePhysicalStop(t *testing.T) {
	for _, kind := range []string{"pending-then-success", "nonzero"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, "")
			outcome := "success"
			if kind == "nonzero" {
				outcome = "failed"
			}
			input, _ := runtimeWorkChild(t, x, outcome)
			s := x.scope(t)
			x.maintain(t, s)
			p, e := x.f.runtimeDrainReadIntent()
			if e != nil {
				t.Fatal(e)
			}
			frozen, e := x.client.QuiesceMaintenance(context.Background(), *p.Maintenance)
			if e != nil || frozen.Work.Pending != 1 {
				t.Fatal(frozen, e)
			}
			if kind == "nonzero" {
				if _, e = input.Write([]byte("finish\n")); e != nil {
					t.Fatal(e)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			proof, e := finishStopModel(ctx, x, s)
			cancel()
			if proof != nil || e == nil || len(x.jobs) != 0 || s.state != nil {
				t.Fatal("unfinished/failed call stopped", proof, e, x.jobs)
			}
			if kind == "nonzero" && !errors.Is(e, errAcceptedWork) {
				t.Fatal(e)
			}
			if kind == "pending-then-success" && !errors.Is(e, context.DeadlineExceeded) {
				t.Fatal(e)
			}
			for _, path := range []string{runtimeStopRoot, runtimeWorkStopRoot + "/complete.json", runtimeWorkStopAnchor} {
				if yes, e := x.f.exists(path); e != nil || yes {
					t.Fatal("premature durable success", path, e)
				}
			}
			original := readWorkStopIntentTest(t, x.f)
			if kind == "pending-then-success" {
				if _, e = input.Write([]byte("finish\n")); e != nil {
					t.Fatal(e)
				}
				ctx, cancel = workStopContext(t)
				defer cancel()
				proof, e = finishStopModel(ctx, x, s)
				if e != nil || proof == nil || len(x.jobs) != 2 {
					t.Fatal(proof, e, x.jobs)
				}
				if !bytes.Equal(encode(original), encode(readWorkStopIntentTest(t, x.f))) {
					t.Fatal("retry recaptured identities")
				}
			}
		})
	}
}

var workStopCuts = []string{"runtime-work-stop-intent-written", "runtime-work-stop-intent-synced", "runtime-work-stop-intent-renamed", "runtime-work-stop-intent-durable", "runtime-work-stop-complete-written", "runtime-work-stop-complete-synced", "runtime-work-stop-complete-renamed", "runtime-work-stop-complete-durable", "runtime-work-stop-anchor-written", "runtime-work-stop-anchor-synced", "runtime-work-stop-anchor-renamed", "runtime-work-stop-anchor-durable", "runtime-work-stop-publish-written", "runtime-work-stop-publish-synced", "runtime-work-stop-publish-renamed", "runtime-work-stop-publish-durable"}

func TestRuntimeWorkStopWriteAheadCutsRecoverExactPlanWithoutEarlyStop(t *testing.T) {
	for _, cut := range workStopCuts {
		t.Run(cut, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			x.maintain(t, s)
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
			if p, e := finishStopModel(ctx, x, s); p != nil || !errors.Is(e, interrupted) || !hit || len(x.jobs) != 0 {
				t.Fatal(p, e, hit, x.jobs)
			}
			x.f.hook = nil
			original := readWorkStopIntentTest(t, x.f)
			s.close()
			fresh, e := os.Open(x.f.root.Name())
			if e != nil {
				t.Fatal(e)
			}
			defer fresh.Close()
			f := &filesystem{root: fresh}
			next, e := f.beginRuntimeScope(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer next.close()
			m := systemManager{f, x.manager.command}
			proof, e := next.finishAndStopWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), x.client, m, x.proof)
			if e != nil || proof == nil || next.state == nil || len(x.jobs) != 2 {
				t.Fatal(proof, e, x.jobs)
			}
			if !bytes.Equal(encode(original), encode(readWorkStopIntentTest(t, f))) {
				t.Fatal("fresh scope guessed original identities")
			}
		})
	}
}

func TestRuntimeWorkStopUnknownIntentAndOrphanAnchorRefuseWithoutRepair(t *testing.T) {
	for _, kind := range []string{"empty-namespace", "partial-intent", "intent-scratch", "unknown-field", "policy", "orphan-anchor", "anchor-scratch", "foreign-operation", "foreign-process", "state-rebind", "complete-without-intent"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			x.maintain(t, s)
			ctx, cancel := workStopContext(t)
			defer cancel()
			p, e := s.workStopInput(ctx, digest(encode(x.tx)), runtimeReq("b"), x.client, x.manager, x.proof)
			if e != nil {
				t.Fatal(e)
			}
			path := x.f.root.Name() + runtimeWorkStopRoot + "/intent.json"
			switch kind {
			case "empty-namespace":
				e = os.Remove(path)
			case "partial-intent":
				e = os.WriteFile(path, encode(p)[:17], 0600)
			case "intent-scratch":
				e = os.Rename(path, x.f.root.Name()+runtimeWorkStopRoot+"/.intent.json.next")
				if e == nil {
					e = os.WriteFile(x.f.root.Name()+runtimeWorkStopRoot+"/.intent.json.next", []byte("{"), 0600)
				}
			case "unknown-field":
				raw := encode(p)
				raw = append([]byte(`{"unknown":true,`), raw[1:]...)
				e = os.WriteFile(path, raw, 0600)
			case "policy":
				p.Policy = "kill-is-success"
				e = os.WriteFile(path, encode(p), 0600)
			case "orphan-anchor":
				e = os.WriteFile(x.f.root.Name()+runtimeWorkStopAnchor, []byte(strings.Repeat("a", 64)+"\n"), 0600)
			case "anchor-scratch":
				e = os.WriteFile(x.f.root.Name()+runtimeWorkStopAnchorScratch, []byte("a"), 0600)
			case "foreign-operation":
				p.Drain.Request = runtimeReq("d")
				e = os.WriteFile(path, encode(p), 0600)
			case "foreign-process":
				p.Stop.Main.StartTicks++
				e = os.WriteFile(path, encode(p), 0600)
			case "state-rebind":
				e = os.Rename(x.f.root.Name()+stateDir+"/controller.lock", x.f.root.Name()+stateDir+"/old.lock")
				if e == nil {
					e = os.WriteFile(x.f.root.Name()+stateDir+"/controller.lock", nil, 0600)
				}
			case "complete-without-intent":
				e = os.Remove(path)
				if e == nil {
					e = os.WriteFile(x.f.root.Name()+runtimeWorkStopRoot+"/complete.json", []byte("{}\n"), 0600)
				}
			}
			if e != nil {
				t.Fatal(e)
			}
			before := coreTree(t, x.f.root.Name())
			if proof, e := finishStopModel(ctx, x, s); proof != nil || e == nil || len(x.jobs) != 0 || !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("unknown authority repaired/adopted", proof, e, x.jobs)
			}
		})
	}
}

func TestRuntimeWorkStopUnanchoredOutcomeNeverRecoveredFromDeadOrReplacementNode(t *testing.T) {
	for _, kind := range []string{"unanchored-dead", "anchored-dead", "anchored-scratch-dead", "replacement"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			x.maintain(t, s)
			ctx, cancel := workStopContext(t)
			defer cancel()
			cut := "runtime-work-stop-anchor-durable"
			if kind == "unanchored-dead" {
				cut = "runtime-work-stop-complete-durable"
			}
			if kind == "anchored-scratch-dead" {
				cut = "runtime-work-stop-anchor-written"
			}
			x.f.hook = func(at string) error {
				if at == cut {
					return interrupted
				}
				return nil
			}
			if p, e := finishStopModel(ctx, x, s); p != nil || !errors.Is(e, interrupted) {
				t.Fatal(p, e)
			}
			x.f.hook = nil
			original := readWorkStopIntentTest(t, x.f)
			for _, unit := range []string{MainUnit, IngressUnit} {
				if e := x.children[unit].Process.Kill(); e != nil {
					t.Fatal(e)
				}
				if e := x.children[unit].Wait(); e == nil {
					t.Fatal("own helper not dead")
				}
				x.alive[unit] = false
			}
			if kind == "replacement" {
				x.children[MainUnit] = runtimeStopChild(t, x.f.root.Name(), "main")
				x.alive[MainUnit] = true
			}
			proof, e := s.finishAndStopWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), nil, x.manager, x.proof)
			// A historical anchored WORK result remains readable, but cannot
			// replace the new runtime-close receipt after the daemon dies.
			if kind == "anchored-dead" {
				if e := x.f.workStopLink(original.stopped(runtimeWorkCompletionFromTest(t, x.f))); e != nil {
					t.Fatal(e)
				}
			}
			want := false
			if (e == nil) != want || (proof != nil) != want || len(x.jobs) != 0 {
				t.Fatal(kind, proof, e, x.jobs)
			}
			if want && (s.state == nil || proof.state != s.state.id) {
				t.Fatal("missing original state lease")
			}
			if !bytes.Equal(encode(original), encode(readWorkStopIntentTest(t, x.f))) {
				t.Fatal("dead process identity regenerated")
			}
		})
	}
}

func TestRuntimeWorkStopCompletionCorruptionAndPhysicalOnlyStopCannotCreateProof(t *testing.T) {
	for _, kind := range []string{"completion", "anchor", "missing-anchor", "work-mode", "work-link", "physical-only", "late-corruption"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			x.maintain(t, s)
			ctx, cancel := workStopContext(t)
			defer cancel()
			if kind == "physical-only" {
				if _, e := s.workStopInput(ctx, digest(encode(x.tx)), runtimeReq("b"), x.client, x.manager, x.proof); e != nil {
					t.Fatal(e)
				}
				if _, e := x.stop(ctx, s, x.client); e != nil {
					t.Fatal(e)
				}
				if p, e := finishStopModel(ctx, x, s); p != nil || e == nil || len(x.jobs) != 2 {
					t.Fatal("physical Stop became work success", p, e)
				}
				return
			}
			if kind == "late-corruption" {
				x.f.hook = func(at string) error {
					if at == "runtime-state-locked" {
						return os.WriteFile(x.f.root.Name()+runtimeWorkStopAnchor, []byte(strings.Repeat("a", 64)+"\n"), 0600)
					}
					return nil
				}
				if p, e := finishStopModel(ctx, x, s); p != nil || e == nil {
					t.Fatal("late corrupt link certified", p, e)
				}
				return
			}
			x.f.hook = func(at string) error {
				if at == "runtime-work-stop-anchor-durable" {
					return interrupted
				}
				return nil
			}
			if p, e := finishStopModel(ctx, x, s); p != nil || !errors.Is(e, interrupted) {
				t.Fatal(p, e)
			}
			x.f.hook = nil
			var r runtimeWorkCompletion
			_, e := x.f.readWorkStopRecord("complete.json", &r)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "completion":
				r.Work.Succeeded++
				e = os.WriteFile(x.f.root.Name()+runtimeWorkStopRoot+"/complete.json", encode(r), 0600)
			case "anchor":
				e = os.WriteFile(x.f.root.Name()+runtimeWorkStopAnchor, []byte(strings.Repeat("a", 64)+"\n"), 0600)
			case "missing-anchor":
				e = os.Remove(x.f.root.Name() + runtimeWorkStopAnchor)
				if e == nil {
					e = x.children[MainUnit].Process.Kill()
				}
				if e == nil {
					_ = x.children[MainUnit].Wait()
					x.alive[MainUnit] = false
				}
			case "work-mode":
				e = os.Chmod(x.f.root.Name()+runtimeWorkStopRoot+"/complete.json", 0644)
			case "work-link":
				e = os.Link(x.f.root.Name()+runtimeWorkStopRoot+"/complete.json", x.f.root.Name()+runtimeWorkStopRoot+"/alias")
			}
			if e != nil {
				t.Fatal(e)
			}
			before := coreTree(t, x.f.root.Name())
			if p, e := finishStopModel(ctx, x, s); p != nil || e == nil || len(x.jobs) != 0 || !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("corrupt authority repaired/adopted", p, e, x.jobs)
			}
		})
	}
}

func TestRuntimeWorkStopNewNamespacesKeepActualStartupAndFileEngineFenced(t *testing.T) {
	for _, path := range []string{runtimeWorkStopRoot, runtimeWorkStopAnchor, runtimeWorkStopAnchorScratch} {
		t.Run(strings.TrimPrefix(path, "/etc/"), func(t *testing.T) {
			f, tx, targets := runtimeModel(t)
			var e error
			if path == runtimeWorkStopRoot {
				e = os.Mkdir(f.root.Name()+path, 0700)
			} else {
				e = os.WriteFile(f.root.Name()+path, []byte("unknown"), 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			before := coreTree(t, f.root.Name())
			if _, e = f.startupFilesLocked(context.Background()); !errors.Is(e, ErrInventory) {
				t.Fatal("startup ignored work namespace", e)
			}
			if _, e = runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", targets); !errors.Is(e, ErrInventory) {
				t.Fatal("raw file engine ignored work namespace", e)
			}
			if !reflect.DeepEqual(before, coreTree(t, f.root.Name())) {
				t.Fatal("guard changed authority")
			}
		})
	}
}

func TestRuntimeWorkStopExplicitV3BindsCompletionWithoutChangingV1OrV2Bytes(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	x.maintain(t, s)
	ctx, cancel := workStopContext(t)
	defer cancel()
	x.f.hook = func(at string) error {
		if at == "runtime-work-stop-publish-durable" {
			return interrupted
		}
		return nil
	}
	if p, e := finishStopModel(ctx, x, s); p != nil || !errors.Is(e, interrupted) {
		t.Fatal(p, e)
	}
	x.f.hook = nil
	stop, e := x.f.readRuntimeStop()
	if e == nil && stop.Version == 4 && digestPattern.MatchString(stop.Close) {
		stop.Version, stop.Close = 3, ""
	} else {
		t.Fatal("missing current v4 closure", stop, e)
	}
	if e != nil || stop.Version != 3 || !digestPattern.MatchString(stop.Work) {
		t.Fatal(stop, e)
	}
	if e = x.f.workStopLink(stop); e != nil {
		t.Fatal(e)
	}
	v2 := stop
	v2.Version = 2
	v2.Work = ""
	if !validRuntimeStop(v2) || bytes.Contains(encode(v2), []byte("work_completion_sha256")) {
		t.Fatal("v2 changed")
	}
	v1 := v2
	v1.Version = 1
	v1.State = nil
	if !validRuntimeStop(v1) || bytes.Contains(encode(v1), []byte("state_identity")) || bytes.Contains(encode(v1), []byte("work_completion_sha256")) {
		t.Fatal("v1 changed")
	}
	for _, kind := range []string{"v2-with-work", "v3-without-work", "v3-without-state", "wrong-work", "foreign-plan"} {
		t.Run(kind, func(t *testing.T) {
			p := stop
			switch kind {
			case "v2-with-work":
				p.Version = 2
			case "v3-without-work":
				p.Work = ""
			case "v3-without-state":
				p.State = nil
			case "wrong-work":
				p.Work = strings.Repeat("e", 64)
			case "foreign-plan":
				p.Request = runtimeReq("e")
			}
			if validRuntimeStop(p) && x.f.workStopLink(p) == nil {
				t.Fatal("unsupported or foreign link accepted", kind)
			}
		})
	}
}

func TestRuntimeWorkStopUnboundedCanceledOrRealProofRefusesBeforeNewNamespace(t *testing.T) {
	for _, kind := range []string{"unbounded", "canceled", "real-proof", "foreign-manager"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			x.maintain(t, s)
			ctx, cancel := workStopContext(t)
			defer cancel()
			if kind == "unbounded" {
				ctx = context.Background()
			}
			if kind == "canceled" {
				cancel()
			}
			m := x.manager
			proof := x.proof
			if kind == "real-proof" {
				proof.process = runtimeProcessProof
			}
			if kind == "foreign-manager" {
				m.fs = nil
			}
			before := coreTree(t, x.f.root.Name())
			if p, e := s.finishAndStopWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), x.client, m, proof); p != nil || e == nil || len(x.jobs) != 0 || !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal(p, e, x.jobs)
			}
		})
	}
}

// The original parent/child protocol, actual BSD/OFD/pidfd behavior and all old
// vectors stay unchanged. Only this new mode calls the composed entry point.
func TestRuntimeWorkStopActualCoordinatorSIGKILLRecoversKnownOutcomesAndState(t *testing.T) {
	runRuntimeStopCrashRecoveryMode(t, func(x *stopTestModel, s *runtimeScope) { x.maintain(t, s) }, []string{"runtime-work-stop-intent-durable", "runtime-work-stop-complete-durable", "runtime-work-stop-anchor-renamed", "runtime-stop-after-" + IngressUnit, "runtime-state-locked"}, true)
}
