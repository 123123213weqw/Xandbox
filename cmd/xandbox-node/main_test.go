package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func TestOperatorCLIStatusDrainResumeAndExactRetry(t *testing.T) {
	root, e := os.MkdirTemp("", "xb-cli-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(root)
	store, e := nodecontrol.OpenStore(root)
	if e != nil {
		t.Fatal(e)
	}
	c, e := nodecontrol.New(store, sandbox.NewAdmissionGate(false))
	if e != nil {
		t.Fatal(e)
	}
	s, e := nodecontrol.Start(root, c, func() sandbox.Stats { return sandbox.Stats{Backend: "mock"} })
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.Close(ctx)
	}()
	call := func(args ...string) nodecontrol.Reply {
		t.Helper()
		var out, log bytes.Buffer
		if e := run(append([]string{"-state-dir", root}, args...), &out, &log); e != nil {
			t.Fatal(e)
		}
		var r nodecontrol.Reply
		if e = json.Unmarshal(out.Bytes(), &r); e != nil {
			t.Fatal(e)
		}
		return r
	}
	status := call("status")
	epoch := status.Control.Committed.Epoch
	drained := call("-epoch", epoch, "-revision", "1", "-request-id", strings.Repeat("b", 32), "drain")
	if drained.Control.AdmissionOpen || drained.Control.Committed.Revision != 2 {
		t.Fatal(drained)
	}
	replay := call("-epoch", epoch, "-revision", "1", "-request-id", strings.Repeat("b", 32), "drain")
	if replay.Control != drained.Control {
		t.Fatal("CLI retry was not idempotent")
	}
	opened := call("-epoch", epoch, "-revision", "2", "-request-id", strings.Repeat("c", 32), "resume")
	if !opened.Control.AdmissionOpen {
		t.Fatal(opened)
	}
	var out, log bytes.Buffer
	if e = run([]string{"-state-dir", root, "-epoch", epoch, "-revision", "1", "-request-id", strings.Repeat("d", 32), "resume"}, &out, &log); e == nil || !strings.Contains(e.Error(), "CONFLICT") {
		t.Fatal("stale CLI resumed", e)
	}
	if out.Len() != 0 {
		t.Fatal("failed command emitted success JSON")
	}
}
func TestOperatorCLIRejectsNonFixedCommandsAndMutationConfusion(t *testing.T) {
	for _, args := range [][]string{
		{}, {"-state-dir", "/no-creation", "exec"}, {"-state-dir", "/no-creation", "status", "extra"},
		{"-state-dir", "/no-creation", "-epoch", strings.Repeat("a", 32), "status"},
		{"-state-dir", "/no-creation", "-timeout", "61s", "status"},
		{"-state-dir", "/no-creation", "-epoch", "invalid", "-revision", "1", "drain"},
	} {
		var out, log bytes.Buffer
		if e := run(args, &out, &log); e == nil {
			t.Fatal("invalid operator args accepted", args)
		}
	}
}
