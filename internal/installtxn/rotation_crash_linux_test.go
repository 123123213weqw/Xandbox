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
)

// Only this test ELF accepts the shadow root and persistence cuts. The real
// public installer has neither model roots nor hooks nor a synthetic ACK route.
func TestRotationCrashHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_TEST_ROTATION_ROOT")
	if root == "" {
		return
	}
	b, e := os.ReadFile(root + "/rotation-input.json")
	if e != nil {
		os.Exit(71)
	}
	p, e := DecodeRotation(b)
	if e != nil {
		os.Exit(72)
	}
	dir, e := os.Open(root)
	if e != nil {
		os.Exit(73)
	}
	f := &filesystem{root: dir}
	f.hook = func(at string) error {
		if at == os.Getenv("XANDBOX_TEST_ROTATION_STAGE") {
			os.Exit(77)
		}
		return nil
	}
	tx, e := f.readTransaction("commit")
	if e != nil {
		os.Exit(74)
	}
	request := os.Getenv("XANDBOX_TEST_ROTATION_REQUEST")
	_, e = rotateModel(context.Background(), f, tx, p, 1, request, func() error { return nil })
	if errors.Is(e, ErrConflict) {
		os.Exit(78)
	}
	if e != nil {
		os.Exit(75)
	}
	if os.Getenv("XANDBOX_TEST_ROTATION_STAGE") == "policy-intent-removed" {
		m := &rotationModelManager{managedModelManager: &managedModelManager{modelManager: &modelManager{}, active: true}}
		if _, e = reconcileRotation(context.Background(), f, request, m); e != nil {
			os.Exit(76)
		}
	}
	os.Exit(0)
}
func rotationCommand(ctx context.Context, root, stage, request string) *exec.Cmd {
	c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRotationCrashHelper$")
	c.Env = []string{"GOMAXPROCS=2", "XANDBOX_TEST_ROTATION_ROOT=" + root, "XANDBOX_TEST_ROTATION_STAGE=" + stage, "XANDBOX_TEST_ROTATION_REQUEST=" + request}
	return c
}
func TestAbruptRotationProcessDeathAndSourceIndependentFinalReceiptRecovery(t *testing.T) {
	stages := []string{"rotation-intent-written", "rotation-intent-synced", "rotation-intent-renamed", "rotation-intent-durable", "policy-written", "policy-synced", "policy-prepared", "policy-renamed", "policy-durable", "policy-confirmed", "policy-intent-removed"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			f, tx, p := rotationFixture(t, stage == "policy-intent-removed")
			if os.WriteFile(f.root.Name()+"/rotation-input.json", encode(p), 0600) != nil {
				t.Fatal("fixture")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			req := strings.Repeat("b", 32)
			output, e := rotationCommand(ctx, f.root.Name(), stage, req).CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 77 || len(output) != 0 {
				t.Fatalf("crash not reached: %v, output bytes %d", e, len(output))
			}
			if strings.HasPrefix(stage, "policy-") {
				os.Remove(f.root.Name() + p.Policy.Path)
			}
			dir, e := os.Open(f.root.Name())
			if e != nil {
				t.Fatal(e)
			}
			defer dir.Close()
			fresh := &filesystem{root: dir}
			if _, e = rotateModel(ctx, fresh, tx, p, 1, req, nil); e != nil {
				t.Fatal("crash recovery", e)
			}
			if fresh.verifyTransaction(ctx, tx) != nil {
				t.Fatal("crash recovery full proof")
			}
			if stage == "policy-intent-removed" {
				m := &rotationModelManager{managedModelManager: &managedModelManager{modelManager: &modelManager{}, active: true}}
				if _, e = reconcileRotation(ctx, fresh, req, m); e != nil {
					t.Fatal("lost final receipt", e)
				}
			}
		})
	}
}
func TestIndependentRotationProcessesSerializeExactOrCompetingRequests(t *testing.T) {
	for _, same := range []bool{true, false} {
		t.Run(map[bool]string{true: "same", false: "competing"}[same], func(t *testing.T) {
			f, tx, p := rotationFixture(t, false)
			if os.WriteFile(f.root.Name()+"/rotation-input.json", encode(p), 0600) != nil {
				t.Fatal("fixture")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			commands := make([]*exec.Cmd, 4)
			for i := range commands {
				req := strings.Repeat("b", 32)
				if !same {
					req = strings.Repeat(string(rune('b'+i)), 32)
				}
				commands[i] = rotationCommand(ctx, f.root.Name(), "", req)
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
					t.Fatal("unexpected contender result", e)
				}
			}
			if same && winners != 4 || !same && winners != 1 {
				t.Fatal("wrong winners", winners)
			}
			if f.verifyTransaction(ctx, tx) != nil {
				t.Fatal("serialized full proof")
			}
		})
	}
}
