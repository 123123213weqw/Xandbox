//go:build linux

package installtxn

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/gateway"
)

// ONLY the test ELF accepts an alternate root. The synced scalar marker is a
// MODEL of predecessor-store durability, not a real gateway record or ACK.
func TestSupersessionCrashProcessHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_TEST_SUP_ROOT")
	if root == "" {
		return
	}
	b, e := os.ReadFile(root + "/sup-input.json")
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
	defer dir.Close()
	f := &filesystem{root: dir}
	f.hook = func(at string) error {
		if at == os.Getenv("XANDBOX_TEST_SUP_STAGE") {
			os.Exit(77)
		}
		return nil
	}
	m := &recoveryModelManager{rotationModelManager: &rotationModelManager{managedModelManager: &managedModelManager{modelManager: &modelManager{}}}, t: t, fs: f, allowACK: true}
	state := &supModel{high: 1}
	if b, e := os.ReadFile(root + "/model-sup-high"); e == nil {
		n, e := strconv.ParseUint(string(b), 10, 64)
		if e != nil {
			os.Exit(75)
		}
		state.high = n
	} else if !os.IsNotExist(e) {
		os.Exit(75)
	}
	tx, e := f.readTransaction("commit")
	if e != nil {
		os.Exit(76)
	}
	advance, confirm := supPrimitives(t, f, tx, m, state)
	persist := func(c gateway.Config, a, b []byte, base string) error {
		if e := advance(c, a, b, base); e != nil {
			return e
		}
		marker, e := os.OpenFile(root+"/model-sup-high", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if e != nil {
			return e
		}
		_, e = marker.WriteString(strconv.FormatUint(state.high, 10))
		if e == nil {
			e = marker.Sync()
		}
		closeErr := marker.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		return dir.Sync()
	}
	n, e := strconv.ParseUint(os.Getenv("XANDBOX_TEST_SUP_EXPECTED"), 10, 64)
	if e != nil {
		os.Exit(76)
	}
	_, e = supersessionOperation(context.Background(), f, p, n, os.Getenv("XANDBOX_TEST_SUP_REQUEST"), os.Getenv("XANDBOX_TEST_SUP_REPLACES"), m, persist, confirm)
	if errors.Is(e, ErrConflict) {
		os.Exit(78)
	}
	if e != nil {
		os.Exit(74)
	}
	os.Exit(0)
}
func supCommand(ctx context.Context, root, stage, request, replaces string, expected uint64) *exec.Cmd {
	c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSupersessionCrashProcessHelper$")
	c.Env = []string{"GOMAXPROCS=2", "XANDBOX_TEST_SUP_ROOT=" + root, "XANDBOX_TEST_SUP_STAGE=" + stage, "XANDBOX_TEST_SUP_REQUEST=" + request, "XANDBOX_TEST_SUP_REPLACES=" + replaces, "XANDBOX_TEST_SUP_EXPECTED=" + strconv.FormatUint(expected, 10)}
	return c
}
func TestSupersessionActualTestProcessDeathEveryBoundaryAndSourceFreeRetry(t *testing.T) {
	for _, stage := range supersessionStages {
		t.Run(stage, func(t *testing.T) {
			f, tx, p, m, state, n, old, advance, confirm := supFixture(t, false)
			if e := os.WriteFile(f.root.Name()+"/sup-input.json", encode(p), 0600); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			req := strings.Repeat("d", 32)
			output, e := supCommand(ctx, f.root.Name(), stage, req, old, n).CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 77 || len(output) != 0 {
				t.Fatal("actual process cut not reached", e)
			}
			if stage == "supersession-policy-written" || stage == "supersession-policy-synced" || stage == "supersession-policy-prepared" || stage == "policy-renamed" || stage == "policy-durable" || stage == "supersession-files-confirmed" || stage == "supersession-record-removed" || stage == "policy-intent-removed" {
				os.Remove(f.root.Name() + p.Policy.Path)
			}
			if _, e = supersessionOperation(ctx, f, p, n, req, old, m, advance, confirm); e != nil {
				t.Fatal("fresh process exact retry", e)
			}
			if state.high != n || state.advances != 0 || f.verifyTransaction(ctx, tx) != nil {
				t.Fatal("crash skipped current authority")
			}
		})
	}
}
func TestSupersessionActualRecoverySettlementProcessCuts(t *testing.T) {
	for _, stage := range []string{"supersession-predecessor-durable", "supersession-intent-renamed", "recovery-record-removed"} {
		t.Run(stage, func(t *testing.T) {
			f, tx, p, m, state, n, old, advance, confirm := supFixture(t, true)
			os.WriteFile(f.root.Name()+"/sup-input.json", encode(p), 0600)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			req := strings.Repeat("d", 32)
			out, e := supCommand(ctx, f.root.Name(), stage, req, old, n).CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 77 || len(out) != 0 {
				t.Fatal("real settlement cut not reached", e)
			}
			b, e := os.ReadFile(f.root.Name() + "/model-sup-high")
			if e != nil || string(b) != "2" {
				t.Fatal("model predecessor advancement not durable")
			}
			state.high = 2
			if f.verifyTransaction(ctx, tx) == nil {
				t.Fatal("old credential startup across cut")
			}
			if _, e = supersessionOperation(ctx, f, p, n, req, old, m, advance, confirm); e != nil {
				t.Fatal("real settlement retry", e)
			}
		})
	}
}
func TestSupersessionFourProcessesExactAndCompetingRequests(t *testing.T) {
	for _, same := range []bool{true, false} {
		t.Run(map[bool]string{true: "same", false: "competing"}[same], func(t *testing.T) {
			f, tx, p, _, _, n, old, _, _ := supFixture(t, false)
			os.WriteFile(f.root.Name()+"/sup-input.json", encode(p), 0600)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			commands := make([]*exec.Cmd, 4)
			for i := range commands {
				req := strings.Repeat("d", 32)
				if !same {
					req = strings.Repeat(string(rune('c'+i)), 32)
				}
				commands[i] = supCommand(ctx, f.root.Name(), "", req, old, n)
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
			if (same && winners != 4) || (!same && winners != 1) || f.verifyTransaction(ctx, tx) != nil {
				t.Fatal("incorrect winner/full proof", winners)
			}
		})
	}
}
