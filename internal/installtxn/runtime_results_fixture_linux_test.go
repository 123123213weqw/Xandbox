//go:build linux

package installtxn

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

type resultsWALFixtureSeed struct {
	before nodecontrol.Status
	state  runtimeStateIdentity
}

// TEST-only first initialization, NOT a recovery/production adoption path.
// Refuse ANY existing entry before creating the original private BSD lock. Use
// the actual store/controller to durably seed precisely the old revision-one
// admission state, but do not start an unused core, broker, server or backend.
// The real results actor must reopen that same existing lock and state itself.
func seedResultsWALOriginalState(f *filesystem) (resultsWALFixtureSeed, error) {
	var zero resultsWALFixtureSeed
	dir, e := f.directory(stateDir)
	if e != nil {
		return zero, e
	}
	defer dir.Close()
	var st unix.Stat_t
	if e = unix.Fstat(int(dir.Fd()), &st); e != nil {
		return zero, e
	}
	if st.Mode != unix.S_IFDIR|0700 || st.Uid != uint32(os.Geteuid()) {
		return zero, ErrInventory
	}
	names, e := dir.Readdirnames(1)
	if e != nil && !errors.Is(e, io.EOF) {
		return zero, e
	}
	if len(names) != 0 {
		return zero, ErrInventory
	}
	fd, e := unix.Openat(int(dir.Fd()), "controller.lock", unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return zero, e
	}
	lock := os.NewFile(uintptr(fd), "TEST-original-results-fixture-lock")
	defer lock.Close() // Release the parent's BSD lease BEFORE the actor starts.
	if e = trustedStat(fd, false, 0600); e != nil {
		return zero, e
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return zero, e
	}
	id, e := stateIdentity(dir, lock)
	if e != nil {
		return zero, e
	}
	if e = f.runtimeStateMatches(id); e != nil {
		return zero, e
	}
	store, e := nodecontrol.OpenStore(f.root.Name() + stateDir)
	if e != nil {
		return zero, e
	}
	c, e := nodecontrol.New(store, sandbox.NewAdmissionGate(false))
	if e != nil {
		return zero, e
	}
	defer c.FenceClose() // No attached actors/server, and no persistence mutation.
	before := c.Status()
	if !before.Committed.Valid() || before.Committed.Revision != 1 || before.Committed.Mode != nodecontrol.ModeOpen || before.Committed.LastRequestID != "" || before.Committed.LastExpectedRevision != 0 || before.Version != 1 || before.Phase != "ready" || before.DesiredMode != nodecontrol.ModeOpen || before.PendingRequestID != "" || !before.AdmissionOpen || before.PendingSessionReservations != 0 {
		return zero, ErrInventory
	}
	if e = f.runtimeStateMatches(id); e != nil {
		return zero, e
	}
	return resultsWALFixtureSeed{before: before, state: id}, nil
}

func resultsWALInitialModel(t *testing.T, mode string) (*stopTestModel, resultsWALFixtureSeed) {
	t.Helper()
	f, tx := runtimeShortInstall(t)
	var seed resultsWALFixtureSeed
	x := stopModelInstalledWithMain(t, "", f, tx, func() *exec.Cmd {
		var e error
		seed, e = seedResultsWALOriginalState(f)
		if e != nil {
			t.Fatal("fresh TEST state seed failed", e)
		}
		return resultsWALDaemon(t, f.root.Name(), mode)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	status, e := x.client.Status(ctx)
	if e != nil || status.Control != seed.before || x.client.Identity().PID != x.children[MainUnit].Process.Pid || !x.client.Identity().Valid() {
		t.Fatal("actual original actor did not reload the entire seeded status", status.Control, seed.before, e)
	}
	return x, seed
}

func TestRuntimeResultsWALFixtureInitialActorReloadsExactSeedWithoutUnusedBackend(t *testing.T) {
	x, seed := resultsWALInitialModel(t, "retained")
	ctx, cancel := workStopContext(t)
	defer cancel()
	if len(x.children) != 2 || !x.alive[MainUnit] || !x.alive[IngressUnit] || x.children[MainUnit].Process.Pid == x.children[IngressUnit].Process.Pid {
		t.Fatal("expected exactly the actual results main and original ingress")
	}
	if _, e := os.Lstat(x.f.root.Name() + stateDir + "/instances"); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("unused legacy backend was created (must not be deleted to pass)", e)
	}
	if e := x.f.runtimeStateOwnedBy(ctx, seed.state, x.client.Identity()); e != nil {
		t.Fatal("same seeded inode lacks actual actor FD-local exclusive BSD ownership", e)
	}
	s := x.scope(t)
	x.maintain(t, s)
	p, e := finishResultsWAL(ctx, x, s)
	if e != nil || p == nil || p.observation.Core.Results.Records != 1 || len(x.jobs) != 0 {
		t.Fatal("seeded actual actor did not complete original result-close protocol", p, e)
	}
	resultsWALRecords(t, x)
}

// Minimal private filesystem fixtures exercise only the bootstrap's refusal
// boundary, not installed-state acceptance. No child or runtime is started.
func TestRuntimeResultsWALFixtureBootstrapRefusesEveryPreexistingNamespaceWithoutRepair(t *testing.T) {
	for _, kind := range []string{"empty-lock", "nonempty-lock", "symlink-lock", "hardlink-lock", "directory-lock", "unknown-file", "unknown-directory", "admission-prefix", "admission-identity", "session-prefix", "result-prefix", "legacy-instance-prefix", "state-mode", "symlink-state", "already-seeded"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			state := root + stateDir
			if e := os.MkdirAll(state, 0700); e != nil {
				t.Fatal(e)
			}
			fd, e := os.Open(root)
			if e != nil {
				t.Fatal(e)
			}
			defer fd.Close()
			f := &filesystem{root: fd}
			write := func(path string, b []byte) {
				t.Helper()
				if e := os.WriteFile(path, b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			mkdir := func(name string) {
				t.Helper()
				if e := os.Mkdir(filepath.Join(state, name), 0700); e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "empty-lock":
				write(state+"/controller.lock", nil)
			case "nonempty-lock":
				write(state+"/controller.lock", []byte("UNKNOWN_TEST_LOCK"))
			case "symlink-lock", "hardlink-lock":
				target := root + "/TEST-foreign-lock"
				write(target, []byte("PRESERVE_TEST_TARGET"))
				link := os.Symlink
				if kind == "hardlink-lock" {
					link = os.Link
				}
				if e := link(target, state+"/controller.lock"); e != nil {
					t.Fatal(e)
				}
			case "directory-lock":
				mkdir("controller.lock")
			case "unknown-file":
				write(state+"/.unknown.next", []byte("PRESERVE_TEST_PREFIX"))
			case "unknown-directory":
				mkdir("unknown")
			case "admission-prefix":
				mkdir("admission")
			case "admission-identity":
				write(state+"/admission.identity", []byte("PRESERVE_TEST_IDENTITY"))
			case "session-prefix":
				mkdir("sessions")
			case "result-prefix":
				mkdir("results")
			case "legacy-instance-prefix":
				mkdir("instances")
			case "state-mode":
				if e := os.Chmod(state, 0750); e != nil {
					t.Fatal(e)
				}
			case "symlink-state":
				target := root + "/TEST-state-target"
				if e := os.Rename(state, target); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(target, state); e != nil {
					t.Fatal(e)
				}
			case "already-seeded":
				if _, e := seedResultsWALOriginalState(f); e != nil {
					t.Fatal(e)
				}
			}
			before := coreTree(t, root)
			seed, e := seedResultsWALOriginalState(f)
			if e == nil || seed != (resultsWALFixtureSeed{}) || !reflect.DeepEqual(before, coreTree(t, root)) {
				t.Fatal("bootstrap adopted, repaired or mutated preexisting TEST state", seed, e)
			}
		})
	}
}

// Retain the formerly implicit old-main -> SIGKILL/reap -> results-main reload
// as an explicit test. The redundant ordinary core/server is no longer started
// at EVERY result-close/Stop fault case, but actual restart coverage is not lost.
func TestRuntimeResultsWALFixtureOriginalBootstrapDeathRetainsReloadCoverage(t *testing.T) {
	x := stopModel(t, "")
	ctx, cancel := workStopContext(t)
	defer cancel()
	old := x.children[MainUnit]
	watch, e := nodecontrol.NewProcessWatch(old.Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	defer watch.Close()
	before, e := x.client.Status(ctx)
	if e != nil {
		t.Fatal(e)
	}
	state, e := x.f.openRuntimeState()
	if e != nil {
		t.Fatal(e)
	}
	defer state.close()
	x.client.Close()
	if e := old.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if e := old.Wait(); e == nil {
		t.Fatal("owned original helper unexpectedly exited without its SIGKILL")
	}
	if exited, e := watch.Exited(); e != nil || !exited {
		t.Fatal("original pidfd did not independently observe bootstrap death", exited, e)
	}
	x.children[MainUnit] = resultsWALDaemon(t, x.f.root.Name(), "retained")
	x.client, e = nodecontrol.NewPinnedClient(x.f.root.Name()+stateDir, x.children[MainUnit].Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(x.client.Close)
	after, e := x.client.Status(ctx)
	if e != nil || after.Control != before.Control || x.client.Identity() == watch.Identity() {
		t.Fatal("explicit restart lost original committed status or incarnation boundary", after.Control, before.Control, e)
	}
	if e := x.f.runtimeStateOwnedBy(ctx, state.id, x.client.Identity()); e != nil {
		t.Fatal("replacement TEST actor lost same original state inode", e)
	}
	if _, e := os.Lstat(x.f.root.Name() + stateDir + "/instances"); e != nil {
		t.Fatal("explicit old bootstrap namespace was silently removed", e)
	}
	s := x.scope(t)
	x.maintain(t, s)
	p, e := stopResultsModel(ctx, x, s)
	if e != nil || p == nil || s.state == nil || s.state.id != state.id || !reflect.DeepEqual(x.jobs, []string{IngressUnit, MainUnit}) {
		t.Fatal("explicit restart failed original result-bound physical Stop/lease model", p, e, x.jobs)
	}
}
