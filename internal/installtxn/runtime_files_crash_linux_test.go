//go:build linux

package installtxn

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

type runtimeCrashInput struct {
	Base    string        `json:"base_commit_sha256"`
	Targets []modelTarget `json:"targets"`
}

// Only a test ELF has this entry and its rooted-filesystem injection. This
// helper self-SIGKILLs, bypassing ALL Go defers and releasing kernel locks by
// process death. No production CLI, system service or VMM is invoked.
func TestRuntimeFileCrashHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_TEST_RUNTIME_FILES_ROOT")
	if root == "" {
		return
	}
	raw, e := os.ReadFile(root + "/runtime-model.json")
	if e != nil {
		os.Exit(71)
	}
	var input runtimeCrashInput
	if strictjson.Decode(raw, &input) != nil {
		os.Exit(72)
	}
	dir, e := os.Open(root)
	if e != nil {
		os.Exit(73)
	}
	f := &filesystem{root: dir}
	f.hook = func(at string) error {
		if at == os.Getenv("XANDBOX_TEST_RUNTIME_FILES_CUT") {
			_ = unix.Kill(os.Getpid(), unix.SIGKILL)
			select {} // A returned error or os.Exit is NOT abrupt-death proof.
		}
		return nil
	}
	var targets []target
	for _, v := range input.Targets {
		targets = append(targets, target{file: v.File, data: v.Data})
	}
	_, e = f.runtimeFileExchange(context.Background(), input.Base, 0, runtimeReq("b"), "forward", targets, stoppedModel)
	if e != nil {
		os.Exit(74)
	}
	os.Exit(0)
}

func TestRuntimeFileActualSIGKILLFreshDescriptorRecovery(t *testing.T) {
	for _, cut := range []string{"runtime-intent-durable", "runtime-startup-fence-durable", "runtime-swap-sandboxd-renamed", "runtime-head-renamed", "runtime-head-durable", "runtime-intent-unlinked"} {
		t.Run(cut, func(t *testing.T) {
			f, tx, targets := runtimeModel(t)
			before := runtimeProtectedBytes(t, f, tx)
			input := runtimeCrashInput{Base: digest(encode(tx))}
			for _, v := range targets {
				input.Targets = append(input.Targets, modelTarget{v.file, v.data})
			}
			if e := os.WriteFile(f.root.Name()+"/runtime-model.json", encode(input), 0600); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRuntimeFileCrashHelper$")
			cmd.Env = []string{"GOMAXPROCS=2", "XANDBOX_TEST_RUNTIME_FILES_ROOT=" + f.root.Name(), "XANDBOX_TEST_RUNTIME_FILES_CUT=" + cut}
			output, e := cmd.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(e, &exited) || len(output) != 0 {
				t.Fatalf("abrupt process death not observed: %v, output bytes %d", e, len(output))
			}
			status, ok := exited.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("not an actual SIGKILL")
			}
			freshRoot, e := os.Open(f.root.Name())
			if e != nil {
				t.Fatal(e)
			}
			defer freshRoot.Close()
			fresh := &filesystem{root: freshRoot}
			// Before the first target mutation the producer can be needed to
			// complete a sealed object. Thereafter all source FDs/data can vanish.
			recoveryTargets := targets
			if cut != "runtime-intent-durable" {
				recoveryTargets = runtimeNoSources(targets)
			}
			result, e := runtimeApply(ctx, fresh, tx, 0, runtimeReq("b"), "forward", recoveryTargets)
			if e != nil || result.Revision != 1 || !result.FilesSelected || !result.StartupBlocked || result.ActivationAllowed {
				t.Fatal("fresh process-death recovery", result, e)
			}
			unchangedRuntimeProtected(t, fresh, before)
			if e := fresh.verifyTransaction(ctx, tx); e == nil {
				t.Fatal("process death recovery removed startup fence")
			}
		})
	}
}
