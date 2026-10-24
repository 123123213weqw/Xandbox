//go:build linux

package installtxn

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/gateway"
)

// ONLY the test ELF accepts a shadow root. The separate test marker below is
// a MODEL of high-water progress, NOT the real gateway store/identity. Real
// gateway durability is tested in package gateway; root integration remains an
// owned-L1 gate. Journal, policy, intent, OFD exclusion and process exits are real.
func TestRecoveryCrashProcessHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_TEST_RECOVERY_ROOT")
	if root == "" {
		return
	}
	b, e := os.ReadFile(root + "/recovery-input.json")
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
		if at == os.Getenv("XANDBOX_TEST_RECOVERY_STAGE") {
			os.Exit(77)
		}
		return nil
	}
	m := &recoveryModelManager{rotationModelManager: &rotationModelManager{managedModelManager: &managedModelManager{modelManager: &modelManager{}}}, t: t, fs: f, allowACK: true}
	advance := func(c gateway.Config, _ []byte, payload []byte, base string) error {
		current, e := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
		if e != nil || string(current) != string(payload) {
			return ErrInventory
		}
		p, e := gateway.DecodeManagedEnvelope(c, payload, base)
		if e != nil {
			return e
		}
		if !m.inside || p.Revision != 2 {
			return ErrInventory
		}
		marker, e := os.OpenFile(root+"/model-advance.json", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if e != nil {
			return e
		}
		defer marker.Close()
		if _, e = marker.Write(encode(struct{ Revision uint64 }{2})); e != nil {
			return e
		}
		if e = marker.Sync(); e != nil {
			return e
		}
		return dir.Sync()
	}
	_, e = recoveryOperation(context.Background(), f, p, 2, os.Getenv("XANDBOX_TEST_RECOVERY_REQUEST"), strings.Repeat("b", 32), m, advance)
	if errors.Is(e, ErrConflict) {
		os.Exit(78)
	}
	if e != nil {
		os.Exit(74)
	}
	os.Exit(0)
}
func recoveryCommand(ctx context.Context, root, stage, request string) *exec.Cmd {
	c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRecoveryCrashProcessHelper$")
	c.Env = []string{"GOMAXPROCS=2", "XANDBOX_TEST_RECOVERY_ROOT=" + root, "XANDBOX_TEST_RECOVERY_STAGE=" + stage, "XANDBOX_TEST_RECOVERY_REQUEST=" + request}
	return c
}
func TestRecoveryActualTestProcessDeathEveryBoundaryAndLostReceipt(t *testing.T) {
	for _, stage := range recoveryStages {
		t.Run(stage, func(t *testing.T) {
			f, tx, p, m, advance, high := recoveryFixture(t)
			if e := os.WriteFile(f.root.Name()+"/recovery-input.json", encode(p), 0600); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			req, old := strings.Repeat("c", 32), strings.Repeat("b", 32)
			output, e := recoveryCommand(ctx, f.root.Name(), stage, req).CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 77 || len(output) != 0 {
				t.Fatal("process cut not reached", e)
			}
			if b, e := os.ReadFile(f.root.Name() + "/model-advance.json"); e == nil {
				var marker struct{ Revision uint64 }
				if json.Unmarshal(b, &marker) != nil || marker.Revision != 2 {
					t.Fatal("bad test marker")
				}
				*high = 2
			} else if !os.IsNotExist(e) {
				t.Fatal(e)
			}
			// Source removal is guaranteed only after a complete candidate exists.
			if stage == "recovery-policy-written" || stage == "recovery-policy-synced" || stage == "recovery-policy-prepared" || stage == "policy-renamed" || stage == "policy-durable" || strings.HasPrefix(stage, "recovery-intent") || stage == "recovery-files-confirmed" || stage == "recovery-record-removed" || stage == "policy-intent-removed" {
				os.Remove(f.root.Name() + p.Policy.Path)
			}
			if _, e = recoveryOperation(ctx, f, p, 2, req, old, m, advance); e != nil {
				t.Fatal("fresh process recovery", e)
			}
			if *high != 2 || f.verifyTransaction(ctx, tx) != nil {
				t.Fatal("crash recovery proof")
			}
		})
	}
}
func TestRecoveryFourProcessesExactOrCompetingWholeOperation(t *testing.T) {
	for _, same := range []bool{true, false} {
		t.Run(map[bool]string{true: "same", false: "competing"}[same], func(t *testing.T) {
			f, tx, p, _, _, _ := recoveryFixture(t)
			if e := os.WriteFile(f.root.Name()+"/recovery-input.json", encode(p), 0600); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			commands := make([]*exec.Cmd, 4)
			for i := range commands {
				req := strings.Repeat("c", 32)
				if !same {
					req = strings.Repeat(string(rune('c'+i)), 32)
				}
				commands[i] = recoveryCommand(ctx, f.root.Name(), "", req)
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
					t.Fatal("unexpected contender exit", e)
				}
			}
			if same && winners != 4 || !same && winners != 1 {
				t.Fatal("wrong recovery winner count", winners)
			}
			if f.verifyTransaction(ctx, tx) != nil {
				t.Fatal("concurrent final full proof")
			}
		})
	}
}
