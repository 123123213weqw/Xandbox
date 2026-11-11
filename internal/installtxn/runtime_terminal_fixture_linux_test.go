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

// The original factory is retained verbatim for default/other modes. In
// particular unsupported must retain the old bootstrap's empty runtime dirs.
func terminalActorOriginalInitial(t *testing.T, mode string) *stopTestModel {
	t.Helper()
	x := stopModel(t, "")
	if mode != "" {
		x.client.Close()
		old := x.children[MainUnit]
		_ = old.Process.Kill()
		_ = old.Wait()
		x.children[MainUnit] = runtimeStopChildMode(t, x.f.root.Name(), "main", mode)
		var e error
		x.client, e = nodecontrol.NewPinnedClient(x.f.root.Name()+stateDir, x.children[MainUnit].Process.Pid)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(x.client.Close)
	}
	return x
}

func terminalActorInitialModel(t *testing.T, mode string) *stopTestModel {
	t.Helper()
	switch mode {
	case "populated", "terminal-firecracker-model", "cleanup-failed":
		x, _ := terminalActorSeededInitial(t, mode)
		return x
	default:
		return terminalActorOriginalInitial(t, mode)
	}
}

// Fresh EMPTY private TEST state only, using the existing strict ordinary-store
// seed, not a second constructor or acceptance policy. The intended actual
// actor reopens the same inode. No unused core/backend/server is started first.
func terminalActorSeededInitial(t *testing.T, mode string) (*stopTestModel, resultsWALFixtureSeed) {
	t.Helper()
	switch mode {
	case "populated", "terminal-firecracker-model", "cleanup-failed":
	default:
		t.Fatal("fixed seeded TEST mode required")
	}
	f, tx := runtimeShortInstall(t)
	var seed resultsWALFixtureSeed
	calls := 0
	x := stopModelInstalledWithMain(t, "", f, tx, func() *exec.Cmd {
		calls++
		var err error
		seed, err = seedResultsWALOriginalState(f)
		if err != nil {
			t.Fatal("fresh original terminal TEST seed failed", err)
		}
		return runtimeStopChildMode(t, f.root.Name(), "main", mode)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	status, err := x.client.Status(ctx)
	if err != nil || status.Control != seed.before || !x.client.Identity().Valid() || x.client.Identity().PID != x.children[MainUnit].Process.Pid || calls != 1 {
		t.Fatal("intended actor did not reload original seed/status/PID exactly once", status.Control, seed.before, err, calls)
	}
	if err := f.runtimeStateOwnedBy(ctx, seed.state, x.client.Identity()); err != nil {
		t.Fatal("actual original seed inode lacks unique FD-local BSD owner", err)
	}
	return x, seed
}

func terminalFixtureProtocol(t *testing.T, x *stopTestModel, mode string) {
	t.Helper()
	s := x.scope(t)
	x.maintain(t, s)
	ctx, cancel := workStopContext(t)
	defer cancel()
	proof, err := finishStopModel(ctx, x, s)
	if mode == "cleanup-failed" || mode == "unsupported" {
		if proof != nil || err == nil || len(x.jobs) != 0 || s.state != nil {
			t.Fatal("failed/unsupported actor authorized physical Stop", proof, err, x.jobs)
		}
		if mode == "unsupported" && !errors.Is(err, nodecontrol.ErrRuntimeCloseUnsupported) {
			t.Fatal(err)
		}
		return
	}
	if err != nil || proof == nil || s.state == nil || !reflect.DeepEqual(x.jobs, []string{IngressUnit, MainUnit}) {
		t.Fatal("original complete Stop/state sequence changed", proof, err, x.jobs)
	}
	before := coreTree(t, x.f.root.Name())
	v, err := inspectTerminalModel(ctx, x, s, proof)
	if mode == "populated" {
		if err == nil || v != (runtimeTerminalInventory{}) {
			t.Fatal("mock backend promoted to terminal authority", v, err)
		}
	} else {
		want := 0
		if mode == "terminal-firecracker-model" {
			want = 1
		}
		if err != nil || !v.RawTerminalMatched || v.CoreTerminal.Records != want || v.SessionTerminal.Records != want || v.ResourcesReclaimed || v.ActivationAllowed {
			t.Fatal("complete original terminal MODEL join changed", v, err)
		}
	}
	if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
		t.Fatal("terminal observation mutated original tree")
	}
}

func TestRuntimeCoreTerminalFixtureIntendedActorReloadsOriginalSeed(t *testing.T) {
	for _, mode := range []string{"populated", "terminal-firecracker-model", "cleanup-failed"} {
		t.Run(mode, func(t *testing.T) {
			x, seed := terminalActorSeededInitial(t, mode)
			if len(x.children) != 2 || !x.alive[MainUnit] || !x.alive[IngressUnit] || x.children[MainUnit].Process.Pid == x.children[IngressUnit].Process.Pid || len(x.jobs) != 0 {
				t.Fatal("only intended main and original ingress expected")
			}
			// Each intended actor creates the same full actual runtime namespaces that
			// the old warm bootstrap and replacement left. Not an empty/easier scenario.
			for _, name := range []string{"instances", "ledger", "sessions"} {
				st, err := os.Lstat(x.f.root.Name() + stateDir + "/" + name)
				if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
					t.Fatal("original runtime namespace missing", name, err)
				}
			}
			ctx, cancel := workStopContext(t)
			defer cancel()
			if err := x.f.runtimeStateOwnedBy(ctx, seed.state, x.client.Identity()); err != nil {
				t.Fatal(err)
			}
			terminalFixtureProtocol(t, x, mode)
		})
	}
}

// Keep the formerly implicit bootstrap SIGKILL/reap/reload as explicit coverage
// for EVERY optimized mode, including an independent pidfd and exact old state.
// No observation FD survives into the operator's unique retained-state lease.
func TestRuntimeCoreTerminalFixtureBootstrapSIGKILLReloadCoverageRetained(t *testing.T) {
	for _, mode := range []string{"populated", "terminal-firecracker-model", "cleanup-failed"} {
		t.Run(mode, func(t *testing.T) {
			x := stopModel(t, "")
			ctx, cancel := workStopContext(t)
			defer cancel()
			old := x.children[MainUnit]
			watch, err := nodecontrol.NewProcessWatch(old.Process.Pid)
			if err != nil {
				t.Fatal(err)
			}
			defer watch.Close()
			before, err := x.client.Status(ctx)
			if err != nil {
				t.Fatal(err)
			}
			state, err := x.f.openRuntimeState()
			if err != nil {
				t.Fatal(err)
			}
			id := state.id
			state.close()
			x.client.Close()
			if err := old.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := old.Wait(); err == nil {
				t.Fatal("owned original bootstrap did not die from SIGKILL")
			}
			if exited, err := watch.Exited(); err != nil || !exited {
				t.Fatal("pidfd did not independently observe bootstrap death", exited, err)
			}
			x.children[MainUnit] = runtimeStopChildMode(t, x.f.root.Name(), "main", mode)
			x.client, err = nodecontrol.NewPinnedClient(x.f.root.Name()+stateDir, x.children[MainUnit].Process.Pid)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(x.client.Close)
			after, err := x.client.Status(ctx)
			if err != nil || after.Control != before.Control || x.client.Identity() == watch.Identity() {
				t.Fatal("restart changed original control state/incarnation", after.Control, before.Control, err)
			}
			if err := x.f.runtimeStateOwnedBy(ctx, id, x.client.Identity()); err != nil {
				t.Fatal("replacement lost original BSD lock inode", err)
			}
			terminalFixtureProtocol(t, x, mode)
		})
	}
}

func TestRuntimeCoreTerminalFixtureDefaultAndUnsupportedRemainOriginal(t *testing.T) {
	for _, mode := range []string{"", "unsupported"} {
		name := "default-empty"
		if mode != "" {
			name = mode
		}
		t.Run(name, func(t *testing.T) {
			x := terminalActorInitialModel(t, mode)
			for _, name := range []string{"instances", "ledger", "sessions"} {
				st, err := os.Lstat(x.f.root.Name() + stateDir + "/" + name)
				if err != nil || !st.IsDir() {
					t.Fatal("old bootstrap namespace was removed or omitted", name, err)
				}
			}
			terminalFixtureProtocol(t, x, mode)
		})
	}
}
