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

// Actual coordinator test process only. Main is another test-owned ELF with
// a real private operator/FileStore/BSD lock; manager/image are explicit models.
func TestRuntimeMaintenanceCrashHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_TEST_MAINT_ADAPTER_ROOT")
	if root == "" {
		return
	}
	peer, e := strconv.Atoi(os.Getenv("XANDBOX_TEST_MAINT_ADAPTER_PEER"))
	if e != nil {
		os.Exit(71)
	}
	dir, e := os.Open(root)
	if e != nil {
		os.Exit(72)
	}
	defer dir.Close()
	f := &filesystem{root: dir, hook: func(at string) error {
		if at == os.Getenv("XANDBOX_TEST_MAINT_ADAPTER_CUT") {
			_ = unix.Kill(os.Getpid(), unix.SIGKILL)
			select {}
		}
		return nil
	}}
	c, e := nodecontrol.NewPinnedClient(root+stateDir, peer)
	if e != nil {
		os.Exit(73)
	}
	defer c.Close()
	m := systemManager{f, func(_ context.Context, args []string) ([]byte, error) {
		if args[0] != "show" || args[len(args)-1] != MainUnit {
			return nil, ErrPolicy
		}
		return observationBytes(MainUnit, "loaded", "active", "enabled", peer), nil
	}}
	proof := func(_ context.Context, _ transaction, unit string, id nodecontrol.ProcessIdentity) error {
		if unit != MainUnit || id.PID != peer {
			return ErrConflict
		}
		return nil
	}
	s, e := f.beginRuntimeScope(context.Background())
	if e != nil {
		os.Exit(74)
	}
	defer s.close()
	if _, e = s.maintainWithProof(context.Background(), os.Getenv("XANDBOX_TEST_MAINT_ADAPTER_BASE"), runtimeReq("b"), c, m, proof); e != nil {
		os.Exit(75)
	}
	os.Exit(76) // Requested real self-SIGKILL must be reached, not fake exit137.
}
func TestRuntimeMaintenanceActualCoordinatorSIGKILLRecoversOriginalV2Owner(t *testing.T) {
	for _, cut := range []string{"runtime-maintenance-intent-written", "runtime-maintenance-intent-durable", "runtime-maintenance-after-rpc", "runtime-maintenance-receipt-renamed"} {
		t.Run(cut, func(t *testing.T) {
			x := stopModel(t, "")
			protected := runtimeProtectedBytes(t, x.f, x.tx)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRuntimeMaintenanceCrashHelper$")
			child.Env = []string{"GOMAXPROCS=2", "XANDBOX_TEST_MAINT_ADAPTER_ROOT=" + x.f.root.Name(), "XANDBOX_TEST_MAINT_ADAPTER_PEER=" + strconv.Itoa(x.children[MainUnit].Process.Pid), "XANDBOX_TEST_MAINT_ADAPTER_CUT=" + cut, "XANDBOX_TEST_MAINT_ADAPTER_BASE=" + digest(encode(x.tx))}
			out, e := child.CombinedOutput()
			var exited *exec.ExitError
			if ctx.Err() != nil || !errors.As(e, &exited) || len(out) != 0 {
				t.Fatal("not observed own child death", ctx.Err(), e, string(out))
			}
			status, ok := exited.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL || child.ProcessState == nil {
				t.Fatal("not reaped actual SIGKILL", e)
			}
			original, pending, e := x.f.readMaintenanceIntent()
			if e != nil || !pending {
				t.Fatal(e)
			}
			s := x.scope(t)
			r, e := maintainModel(context.Background(), x, s)
			if e != nil || !r.MaintenanceHeld || r.Revision != 2 || r.StopObserved || r.ActivationAllowed {
				t.Fatal(r, e)
			}
			p, e := x.f.runtimeDrainReadIntent()
			if e != nil || string(encode(p)) != string(encode(original)) {
				t.Fatal("coordinator death regenerated owner", e)
			}
			if _, e = x.f.startupFilesLocked(context.Background()); !errors.Is(e, ErrInventory) {
				t.Fatal("recovery opened startup", e)
			}
			unchangedRuntimeProtected(t, x.f, protected)
		})
	}
}

func TestRuntimeMaintenanceActualStopSIGKILLRetainsV2FenceAndStateLock(t *testing.T) {
	runRuntimeStopCrashRecovery(t, func(x *stopTestModel, s *runtimeScope) { x.maintain(t, s) }, []string{"runtime-stop-after-" + IngressUnit, "runtime-state-locked"})
}
