//go:build linux

package installtxn

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

type modelInput struct {
	Plan    Plan
	Release Release
	Targets []modelTarget
}
type modelTarget struct {
	File File
	Data []byte
}

func writeModelInput(t *testing.T, f *filesystem, p *prepared) {
	t.Helper()
	in := modelInput{Plan: p.plan, Release: p.release}
	for _, v := range p.targets {
		in.Targets = append(in.Targets, modelTarget{v.file, v.data})
	}
	if e := os.WriteFile(f.root.Name()+"/model-input.json", encode(in), 0600); e != nil {
		t.Fatal(e)
	}
}

// Only a test ELF can enter this helper. Neither model FD-root nor persistence
// hooks are exposed by the production installer. os.Exit bypasses Go defers.
func TestInstallCrashHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_TEST_INSTALL_ROOT")
	if root == "" {
		return
	}
	raw, e := os.ReadFile(root + "/model-input.json")
	if e != nil {
		os.Exit(71)
	}
	var input modelInput
	if strictjson.Decode(raw, &input) != nil {
		os.Exit(72)
	}
	dir, e := os.Open(root)
	if e != nil {
		os.Exit(73)
	}
	f := &filesystem{root: dir}
	f.hook = func(at string) error {
		if at == os.Getenv("XANDBOX_TEST_INSTALL_STAGE") {
			os.Exit(77)
		}
		return nil
	}
	p := &prepared{plan: input.Plan, release: input.Release}
	for _, v := range input.Targets {
		p.targets = append(p.targets, target{file: v.File, data: v.Data})
	}
	_, e = applyModel(context.Background(), f, p, os.Getenv("XANDBOX_TEST_INSTALL_REQUEST"), &modelManager{})
	if errors.Is(e, ErrConflict) {
		os.Exit(78)
	}
	if e != nil {
		os.Exit(74)
	}
	os.Exit(0)
}
func modelCommand(ctx context.Context, root, stage, request string) *exec.Cmd {
	c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInstallCrashHelper$")
	c.Env = []string{"GOMAXPROCS=2", "XANDBOX_TEST_INSTALL_ROOT=" + root, "XANDBOX_TEST_INSTALL_STAGE=" + stage, "XANDBOX_TEST_INSTALL_REQUEST=" + request}
	return c
}
func TestAbruptInstallerProcessDeathFreshHandleRecovery(t *testing.T) {
	for _, stage := range []string{"intent-written", "intent-renamed", "file-sandboxd-written", "file-xandbox.service-sealed", "commit-written", "commit-renamed", "commit-durable", "intent-removed"} {
		t.Run(stage, func(t *testing.T) {
			f, p, _ := fixture(t)
			writeModelInput(t, f, p)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			output, e := modelCommand(ctx, f.root.Name(), stage, request()).CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 77 || len(output) != 0 {
				t.Fatalf("crash not reached: %v, output bytes %d", e, len(output))
			}
			dir, e := os.Open(f.root.Name())
			if e != nil {
				t.Fatal(e)
			}
			defer dir.Close()
			recovered := &filesystem{root: dir}
			m := &modelManager{}
			tx, e := applyModel(ctx, recovered, p, request(), m)
			if e != nil {
				t.Fatal("fresh-handle same request recovery", e)
			}
			if e = recovered.verifyTransaction(ctx, tx); e != nil {
				t.Fatal(e)
			}
			if m.reconcileCalls != 0 {
				t.Fatal("file recovery activated a manager")
			}
		})
	}
}
func TestIndependentInstallerProcessesSerializeWithoutReplacement(t *testing.T) {
	for _, same := range []bool{true, false} {
		t.Run(map[bool]string{true: "same-request", false: "competing-requests"}[same], func(t *testing.T) {
			f, p, _ := fixture(t)
			writeModelInput(t, f, p)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			commands := make([]*exec.Cmd, 4)
			for i := range commands {
				req := request()
				if !same {
					req = strings.Repeat(string(rune('a'+i)), 32)
				}
				commands[i] = modelCommand(ctx, f.root.Name(), "", req)
				if e := commands[i].Start(); e != nil {
					t.Fatal(e)
				}
			}
			winners := 0
			for _, c := range commands {
				e := c.Wait()
				if e == nil {
					winners++
					continue
				}
				var exit *exec.ExitError
				if same || !errors.As(e, &exit) || exit.ExitCode() != 78 {
					t.Fatal("unexpected contender outcome", e)
				}
			}
			if (same && winners != 4) || (!same && winners != 1) {
				t.Fatal("incorrect serialized winners", winners)
			}
			tx, e := f.readTransaction("commit")
			if e != nil {
				t.Fatal(e)
			}
			if e = f.verifyTransaction(ctx, tx); e != nil {
				t.Fatal(e)
			}
		})
	}
}
