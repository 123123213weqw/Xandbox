//go:build linux

package installtxn

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"golang.org/x/sys/unix"
)

// Only a test child may select this shadow root. Its operator server lives in
// the parent test process, so coordinator death does not change the pinned peer.
func TestRuntimeDrainCrashHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_TEST_DRAIN_ROOT")
	if root == "" {
		return
	}
	peer, e := strconv.Atoi(os.Getenv("XANDBOX_TEST_DRAIN_PEER"))
	if e != nil {
		os.Exit(71)
	}
	dir, e := os.Open(root)
	if e != nil {
		os.Exit(72)
	}
	f := &filesystem{root: dir, hook: func(at string) error {
		if at == os.Getenv("XANDBOX_TEST_DRAIN_CUT") {
			_ = unix.Kill(os.Getpid(), unix.SIGKILL)
			select {}
		}
		return nil
	}}
	client, e := nodecontrol.NewPinnedClient(root+stateDir, peer)
	if e != nil {
		os.Exit(73)
	}
	_, e = f.runtimeDrainAdmission(context.Background(), os.Getenv("XANDBOX_TEST_DRAIN_BASE"), runtimeReq("b"), client)
	if e != nil {
		os.Exit(74)
	}
	os.Exit(0)
}
func TestRuntimeDrainActualSIGKILLRecoversWriteAheadCommand(t *testing.T) {
	for _, cut := range []string{"runtime-drain-intent-durable", "runtime-drain-after-rpc", "runtime-drain-receipt-renamed"} {
		t.Run(cut, func(t *testing.T) {
			f, tx, client, c := drainModel(t, nil)
			before := runtimeProtectedBytes(t, f, tx)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRuntimeDrainCrashHelper$")
			cmd.Env = []string{"GOMAXPROCS=2", "XANDBOX_TEST_DRAIN_ROOT=" + f.root.Name(), "XANDBOX_TEST_DRAIN_PEER=" + strconv.Itoa(os.Getpid()), "XANDBOX_TEST_DRAIN_CUT=" + cut, "XANDBOX_TEST_DRAIN_BASE=" + digest(encode(tx))}
			out, e := cmd.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(e, &exited) || len(out) != 0 {
				t.Fatal("actual child death not observed", e, len(out))
			}
			status, ok := exited.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("not actual SIGKILL")
			}
			fresh, e := os.Open(f.root.Name())
			if e != nil {
				t.Fatal(e)
			}
			defer fresh.Close()
			f = &filesystem{root: fresh}
			r, e := drainApply(ctx, f, tx, client)
			if e != nil || !r.AdmissionDrained || r.Revision != 2 || c.Status().Committed.Revision != 2 {
				t.Fatal("process death duplicated or lost drain", r, e)
			}
			unchangedRuntimeProtected(t, f, before)
			if _, e = f.startupFilesLocked(ctx); e == nil {
				t.Fatal("coordinator death recovery allowed startup")
			}
		})
	}
}
