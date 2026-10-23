package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/diagnostics"
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

func TestDiagnosticsCLIReadOnlyOfflineAndRejectsMutationOrTimeout(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "diagnostics")
	logger, e := diagnostics.Start(dir)
	if e != nil {
		t.Fatal(e)
	}
	logger.Emit(diagnostics.ServiceMock, diagnostics.Other)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e = logger.Close(ctx); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(filepath.Join(dir, "events.ring"))
	if e != nil {
		t.Fatal(e)
	}
	var out, log bytes.Buffer
	if e = run([]string{"-state-dir", root, "diagnostics"}, &out, &log); e != nil {
		t.Fatal(e)
	}
	if log.Len() != 0 || out.Len() > 32768 || !strings.Contains(out.String(), `"kind":"service_mock"`) || strings.Contains(out.String(), root) {
		t.Fatal("private bounded view")
	}
	for _, args := range [][]string{
		{"-epoch", strings.Repeat("a", 32), "diagnostics"},
		{"-revision", "1", "diagnostics"},
		{"-request-id", strings.Repeat("b", 32), "diagnostics"},
		{"-timeout", "5s", "diagnostics"},
	} {
		out.Reset()
		log.Reset()
		if e = run(append([]string{"-state-dir", root}, args...), &out, &log); e == nil || out.Len() != 0 {
			t.Fatal("read-only confusion")
		}
	}
	after, _ := os.ReadFile(filepath.Join(dir, "events.ring"))
	if !bytes.Equal(before, after) {
		t.Fatal("reader wrote state")
	}
	absent := filepath.Join(root, "absent")
	out.Reset()
	log.Reset()
	if e = run([]string{"-state-dir", absent, "diagnostics"}, &out, &log); e == nil || out.Len() != 0 {
		t.Fatal("missing view accepted")
	}
	if _, e = os.Stat(absent); !os.IsNotExist(e) {
		t.Fatal("reader created directory")
	}
	if _, e = os.Stat(filepath.Join(root, "controller.lock")); !os.IsNotExist(e) {
		t.Fatal("reader touched controller authority")
	}
}
