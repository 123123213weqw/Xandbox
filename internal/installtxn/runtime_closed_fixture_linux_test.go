//go:build linux

package installtxn

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
)

// Use the existing strict EMPTY-state TEST seed, not a second initialization
// policy. The selected helper is still the original populated explicit model;
// no admission state/identity, actor close receipt or backend proof is invented.
func closedStateSeededInitial(t *testing.T, f *filesystem, tx transaction) (*stopTestModel, resultsWALFixtureSeed) {
	t.Helper()
	var seed resultsWALFixtureSeed
	x := stopModelInstalledWithMain(t, "", f, tx, func() *exec.Cmd {
		var e error
		seed, e = seedResultsWALOriginalState(f)
		if e != nil {
			t.Fatal("fresh closed-state TEST seed failed", e)
		}
		return runtimeStopChildMode(t, f.root.Name(), "main", "closed-state-firecracker-model")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	status, e := x.client.Status(ctx)
	if e != nil || status.Control != seed.before || !x.client.Identity().Valid() || x.client.Identity().PID != x.children[MainUnit].Process.Pid {
		t.Fatal("actual closed-state TEST actor did not reload entire original seed", status.Control, seed.before, e)
	}
	return x, seed
}
func closedStateInitialModel(t *testing.T, f *filesystem, tx transaction) *stopTestModel {
	t.Helper()
	x, _ := closedStateSeededInitial(t, f, tx)
	return x
}

func TestRuntimeCoreClosedFixtureInitialActorAndStateSeedRemainOriginal(t *testing.T) {
	for _, metrics := range []bool{false, true} {
		name := "metrics-disabled"
		if metrics {
			name = "metrics-enabled"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := workStopContext(t)
			defer cancel()
			initialCalls := 0
			x, s, p, proof := closedStateModelMetricsWithInitial(t, metrics, func(t *testing.T, f *filesystem, tx transaction) *stopTestModel {
				initialCalls++
				x, seed := closedStateSeededInitial(t, f, tx)
				if len(x.children) != 2 || !x.alive[MainUnit] || !x.alive[IngressUnit] || x.children[MainUnit].Process.Pid == x.children[IngressUnit].Process.Pid {
					t.Fatal("expected only actual model main and original ingress")
				}
				if _, e := os.Lstat(f.root.Name() + stateDir + "/instances"); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("unused ordinary backend must never be created or deleted", e)
				}
				if e := f.runtimeStateOwnedBy(ctx, seed.state, x.client.Identity()); e != nil {
					t.Fatal("actual actor lacks original seed FD-local BSD owner", e)
				}
				return x
			})
			if initialCalls != 1 || s.state == nil || len(x.children) != 2 || !reflect.DeepEqual(x.jobs, []string{IngressUnit, MainUnit}) {
				t.Fatal("original shared physical Stop/retained state path changed", initialCalls, x.jobs)
			}
			before := coreTree(t, x.f.root.Name())
			v, e := inspectClosedStateModel(ctx, x, s, p, proof)
			if e != nil || !v.ClosedStateJoined || !v.Terminal.RawTerminalMatched || !v.Backend.BackendResourcesAbsent || v.Terminal.Core != v.Backend.Core || v.Terminal.CoreTerminal.Records != 1 || v.Terminal.SessionTerminal.Records != 1 || v.State.Files != 10 || v.State.Sockets != 1 || v.ResourcesReclaimed || v.ActivationAllowed || !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("strict complete closed-state MODEL join changed tree or authority", v, e)
			}
		})
	}
}

// Keep the formerly implicit THREE-helper old-main death/reload separately.
// The ordinary main creates only its own empty TEST backend directory. The
// original test setup removes that EMPTY artifact; production readers continue
// to reject this namespace and never delete/repair it. Default fixtures now
// never create it at all. No observer lock FD is retained across operator Stop.
func TestRuntimeCoreClosedFixtureBootstrapSIGKILLReloadCoverageRetained(t *testing.T) {
	for _, metrics := range []bool{false, true} {
		name := "metrics-disabled"
		if metrics {
			name = "metrics-enabled"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := workStopContext(t)
			defer cancel()
			restarts := 0
			x, s, p, proof := closedStateModelMetricsWithInitial(t, metrics, func(t *testing.T, f *filesystem, tx transaction) *stopTestModel {
				x := stopModelInstalled(t, "", f, tx)
				old := x.children[MainUnit]
				watch, e := nodecontrol.NewProcessWatch(old.Process.Pid)
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(watch.Close)
				before, e := x.client.Status(ctx)
				if e != nil {
					t.Fatal(e)
				}
				state, e := f.openRuntimeState()
				if e != nil {
					t.Fatal(e)
				}
				stateID := state.id
				state.close() // Observation value, NOT a retained operator FD.
				x.client.Close()
				if e := old.Process.Kill(); e != nil {
					t.Fatal(e)
				}
				if e := old.Wait(); e == nil {
					t.Fatal("owned bootstrap did not die from its SIGKILL")
				}
				if exited, e := watch.Exited(); e != nil || !exited {
					t.Fatal("original pidfd did not independently observe bootstrap death", exited, e)
				}
				if e := os.Remove(f.root.Name() + stateDir + "/instances"); e != nil {
					t.Fatal("original EMPTY test-only backend artifact no longer removable", e)
				}
				x.children[MainUnit] = runtimeStopChildMode(t, f.root.Name(), "main", "closed-state-firecracker-model")
				x.client, e = nodecontrol.NewPinnedClient(f.root.Name()+stateDir, x.children[MainUnit].Process.Pid)
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(x.client.Close)
				after, e := x.client.Status(ctx)
				if e != nil || after.Control != before.Control || x.client.Identity() == watch.Identity() {
					t.Fatal("explicit restart changed original control status or incarnation", after.Control, before.Control, e)
				}
				if e := f.runtimeStateOwnedBy(ctx, stateID, x.client.Identity()); e != nil {
					t.Fatal("reloaded model actor lost original state inode BSD owner", e)
				}
				restarts++
				return x
			})
			if restarts != 1 || s.state == nil || !reflect.DeepEqual(x.jobs, []string{IngressUnit, MainUnit}) {
				t.Fatal("original restart lost physical Stop/retained state", restarts, x.jobs)
			}
			before := coreTree(t, x.f.root.Name())
			v, e := inspectClosedStateModel(ctx, x, s, p, proof)
			if e != nil || !v.ClosedStateJoined || !v.Terminal.RawTerminalMatched || !v.Backend.BackendResourcesAbsent || v.Terminal.CoreTerminal.Records != 1 || v.Terminal.SessionTerminal.Records != 1 || v.ResourcesReclaimed || v.ActivationAllowed || !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("explicit restart did not preserve complete strict read-only MODEL join", v, e)
			}
		})
	}
}
