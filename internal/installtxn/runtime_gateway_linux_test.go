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
)

func TestRuntimeStartupChildDirectoryErrorCutsRecoverAndReseal(t *testing.T) {
	for _, cut := range []string{"runtime-child-writable", "runtime-child-writable-durable", "runtime-child-sealed", "runtime-child-sealed-durable"} {
		t.Run(cut, func(t *testing.T) {
			f, tx, targets := runtimeStartupFixture(t, false)
			hit := false
			f.hook = func(at string) error {
				if at == cut && !hit {
					hit = true
					return interrupted
				}
				return nil
			}
			if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", targets); !errors.Is(e, interrupted) || !hit {
				t.Fatal("directory cut", e)
			}
			f.hook = nil
			if _, e := f.runtimeSelectedFiles(context.Background()); e == nil {
				t.Fatal("pending permission change accepted")
			}
			fresh, e := os.Open(f.root.Name())
			if e != nil {
				t.Fatal(e)
			}
			defer fresh.Close()
			f = &filesystem{root: fresh}
			if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", runtimeNoSources(targets)); e != nil {
				t.Fatal("producer-free directory recovery", e)
			}
			if e := f.privateDirectory(childRoot, 0555); e != nil {
				t.Fatal("child not resealed", e)
			}
			if _, e := f.runtimeSelectedFiles(context.Background()); e != nil {
				t.Fatal("recovered composition", e)
			}
			if _, e := f.startupFilesLocked(context.Background()); e == nil {
				t.Fatal("recovery unfenced startup")
			}
		})
	}
}

func TestRuntimeStartupChildDirectoryActualSIGKILLReseals(t *testing.T) {
	for _, cut := range []string{"runtime-child-writable-durable", "runtime-child-sealed-durable"} {
		t.Run(cut, func(t *testing.T) {
			f, tx, targets := runtimeStartupFixture(t, false)
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
			out, e := cmd.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(e, &exited) || len(out) != 0 {
				t.Fatal("actual child death not observed", e, len(out))
			}
			status, ok := exited.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("not SIGKILL")
			}
			if cut == "runtime-child-writable-durable" {
				if e := f.privateDirectory(childRoot, 0700); e != nil {
					t.Fatal("writable cut not observed", e)
				}
			}
			fresh, e := os.Open(f.root.Name())
			if e != nil {
				t.Fatal(e)
			}
			defer fresh.Close()
			f = &filesystem{root: fresh}
			if _, e := runtimeApply(ctx, f, tx, 0, runtimeReq("b"), "forward", runtimeNoSources(targets)); e != nil {
				t.Fatal("actual death recovery", e)
			}
			if e := f.privateDirectory(childRoot, 0555); e != nil {
				t.Fatal("not durably resealed", e)
			}
			if _, e := f.runtimeSelectedFiles(ctx); e != nil {
				t.Fatal("recovered composition", e)
			}
			unchangedRuntimeProtected(t, f, before)
			if _, e := f.startupFilesLocked(ctx); e == nil {
				t.Fatal("abrupt death recovery allowed startup")
			}
		})
	}
}

func TestRuntimeStartupUnsealedChildWithoutBoundIntentIsNotRepaired(t *testing.T) {
	f, tx, targets := runtimeStartupFixture(t, false)
	runtimeSelectStartup(t, f, tx, targets)
	if e := os.Chmod(f.root.Name()+childRoot, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", runtimeNoSources(targets)); e == nil {
		t.Fatal("unbound directory mode adopted")
	}
	if _, e := f.runtimeSelectedFiles(context.Background()); e == nil {
		t.Fatal("unsealed child accepted")
	}
	if e := f.privateDirectory(childRoot, 0700); e != nil {
		t.Fatal("unknown permission drift repaired", e)
	}
}
