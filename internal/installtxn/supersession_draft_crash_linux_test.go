//go:build linux

package installtxn

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Only the test ELF has alternate-root/environment controls. Actual test process
// exit proves descriptor/lock release, NOT power-loss durability or real cgroups.
func TestSupersessionDraftCrashProcessHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_TEST_DRAFT_ROOT")
	if root == "" {
		return
	}
	dir, e := os.Open(root)
	if e != nil {
		os.Exit(71)
	}
	defer dir.Close()
	f := &filesystem{root: dir}
	f.hook = func(at string) error {
		if at == os.Getenv("XANDBOX_TEST_DRAFT_STAGE") {
			os.Exit(77)
		}
		return nil
	}
	tx, e := f.readTransaction("commit")
	if e != nil {
		os.Exit(72)
	}
	m := &recoveryModelManager{rotationModelManager: &rotationModelManager{managedModelManager: &managedModelManager{modelManager: &modelManager{}}}, t: t, fs: f}
	state := &supModel{high: 1}
	_, confirm := supPrimitives(t, f, tx, m, state)
	_, e = discardSupersessionDraftOperation(context.Background(), f, 1, os.Getenv("XANDBOX_TEST_DRAFT_PENDING"), os.Getenv("XANDBOX_TEST_DRAFT_SHA"), m, confirm)
	if e != nil {
		os.Exit(73)
	}
	os.Exit(0)
}

func TestSupersessionDraftActualProcessDeathAtEveryBoundarySourceFreeRetry(t *testing.T) {
	for _, stage := range draftStages {
		t.Run(stage, func(t *testing.T) {
			f, tx, m, state, pending, sha, confirm := draftFixture(t, []byte("partial declaration"))
			before := draftRootBytes(t, f)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSupersessionDraftCrashProcessHelper$")
			c.Env = []string{"GOMAXPROCS=2", "XANDBOX_TEST_DRAFT_ROOT=" + f.root.Name(), "XANDBOX_TEST_DRAFT_STAGE=" + stage, "XANDBOX_TEST_DRAFT_PENDING=" + pending, "XANDBOX_TEST_DRAFT_SHA=" + sha}
			b, e := c.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 77 || len(b) != 0 {
				t.Fatal("actual process cut not reached", e, string(b))
			}
			assertDraftFence(t, f, tx, before)
			out, e := discardSupersessionDraftOperation(ctx, f, 1, pending, sha, m, confirm)
			wantRemoved := stage == draftStages[0] || stage == draftStages[1]
			if e != nil || out.DraftRemoved != wantRemoved || !out.DraftAbsent || state.high != 1 || state.advances != 0 {
				t.Fatal("actual process-death retry", out, e)
			}
			assertDraftFence(t, f, tx, before)
		})
	}
}
