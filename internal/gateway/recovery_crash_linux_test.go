//go:build linux

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// This is a test ELF only. The fixture file lives OUTSIDE the closed policy
// inventory. Production has no arbitrary-state path or environment dispatch.
func TestAdvanceCrashProcessHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_TEST_ADVANCE_ROOT")
	if root == "" {
		return
	}
	raw, e := os.ReadFile(filepath.Join(root, "input.json"))
	if e != nil {
		os.Exit(71)
	}
	var s Snapshot
	if strictjson.Decode(raw, &s) != nil {
		os.Exit(72)
	}
	authority, e := access.New(access.Config{Version: 1, Keys: []access.Key{{TokenSHA256: tokenHash(testBackend), TenantID: "alpha", MaxInstances: 2}}})
	if e != nil {
		os.Exit(73)
	}
	state, e := openExistingPolicyState(filepath.Join(root, "policy"), strings.Repeat("a", 64))
	if e != nil {
		os.Exit(74)
	}
	if os.Getenv("XANDBOX_TEST_ADVANCE_STAGE") == "before-commit" {
		os.Exit(77)
	}
	if e = advancePolicyState(state, s, authority); e != nil {
		os.Exit(75)
	}
	if os.Getenv("XANDBOX_TEST_ADVANCE_STAGE") == "after-commit" {
		os.Exit(77)
	}
	os.Exit(0) // skips state.Close: actual process death releases its lock
}

func TestAdvanceAbruptProcessDeathBeforeAndAfterDurableCommit(t *testing.T) {
	for _, stage := range []string{"before-commit", "after-commit"} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "policy")
			if e := os.Mkdir(dir, 0700); e != nil {
				t.Fatal(e)
			}
			s, authority := testSnapshot(t)
			state, e := openPolicyState(dir, strings.Repeat("a", 64))
			if e != nil {
				t.Fatal(e)
			}
			if e = state.Commit(s); e != nil {
				t.Fatal(e)
			}
			state.Close()
			s.Epoch = 2
			s = snapshotWithValidity(t, s, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), nil)
			raw, e := json.Marshal(s)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(root, "input.json"), raw, 0600); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAdvanceCrashProcessHelper$")
			cmd.Env = []string{"GOMAXPROCS=2", "XANDBOX_TEST_ADVANCE_ROOT=" + root, "XANDBOX_TEST_ADVANCE_STAGE=" + stage}
			output, e := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 77 || len(output) != 0 {
				t.Fatal("actual process cut not reached", e)
			}
			cold, e := openExistingPolicyState(dir, strings.Repeat("a", 64))
			if e != nil {
				t.Fatal(e)
			}
			defer cold.Close()
			want := uint64(1)
			if stage == "after-commit" {
				want = 2
			}
			if cold.record.Revision != want {
				t.Fatal("cut point durable epoch mismatch")
			}
			if e = advancePolicyState(cold, s, authority); e != nil {
				t.Fatal("fresh process recovery/exact replay", e)
			}
			if cold.record.Revision != 2 {
				t.Fatal("advance lost after child death")
			}
			if _, e = NewPolicy(s, authority, time.Now()); e == nil {
				t.Fatal("crash recovery authorized expired serving")
			}
		})
	}
}
