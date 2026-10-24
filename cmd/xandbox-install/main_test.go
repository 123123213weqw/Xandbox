package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/installtxn"
)

func TestFixedCLIAndNoSensitiveErrorOutput(t *testing.T) {
	calls := 0
	op := operations{apply: func(context.Context, string, uint64, string) (installtxn.Result, error) {
		calls++
		return installtxn.Result{}, errors.New("secret raw path credential")
	}, reconcile: func(context.Context, string) (installtxn.Result, error) {
		calls++
		return installtxn.Result{Version: 1}, nil
	}, status: func(context.Context) (installtxn.Result, error) { calls++; return installtxn.Result{Version: 1}, nil }, verify: func(context.Context) error { calls++; return nil }}
	for _, args := range [][]string{nil, {"--help"}, {"verify", "sh"}, {"status", "extra"}, {"apply", "-plan", "/private", "-expected-revision", "1", "-request-id", "id"}, {"apply", "-plan", "/private", "-expected-revision", "00", "-request-id", "id"}, {"reconcile", "-unit", "other.service"}} {
		var out, errout bytes.Buffer
		if run(args, &out, &errout, op) != 1 || out.Len() != 0 || calls != 0 {
			t.Fatal("invalid operation reached")
		}
	}
	var out, errout bytes.Buffer
	if run([]string{"apply", "-plan", "/private", "-expected-revision", "0", "-request-id", strings.Repeat("a", 32)}, &out, &errout, op) != 1 || out.Len() != 0 || strings.Contains(errout.String(), "secret") {
		t.Fatal("raw failure leaked")
	}
	out.Reset()
	errout.Reset()
	if run([]string{"verify"}, &out, &errout, op) != 0 || out.Len() != 0 || errout.Len() != 0 {
		t.Fatal("startup gate must be silent")
	}
	if run([]string{"reconcile", "-request-id", strings.Repeat("a", 32)}, &out, &errout, op) != 0 || !strings.Contains(out.String(), `"production_ready":false`) {
		t.Fatal("result maturity inflated")
	}
}

func TestFixedReconfigurationCLIRevisionAndClosedOutput(t *testing.T) {
	calls := 0
	op := operations{reconfigure: func(_ context.Context, path string, expected uint64, request string) (installtxn.Result, error) {
		calls++
		if path != "/private/plan" || expected != 1 || request != strings.Repeat("b", 32) {
			t.Fatal("arguments changed")
		}
		return installtxn.Result{}, errors.New("PRIVATE_CREDENTIAL_PATH")
	}}
	for _, expected := range []string{"0", "01", "+1", "-1", " 1", "18446744073709551615", "18446744073709551616"} {
		var out, errout bytes.Buffer
		if run([]string{"reconfigure", "-plan", "/private/plan", "-expected-revision", expected, "-request-id", strings.Repeat("b", 32)}, &out, &errout, op) != 1 || calls != 0 || out.Len() != 0 {
			t.Fatal("invalid revision reached operation")
		}
	}
	var out, errout bytes.Buffer
	if run([]string{"reconfigure", "-plan", "/private/plan", "-expected-revision", "1", "-request-id", strings.Repeat("b", 32)}, &out, &errout, op) != 1 || calls != 1 || out.Len() != 0 || strings.Contains(errout.String(), "PRIVATE") {
		t.Fatal("failure payload escaped")
	}
}

func TestFixedRecoveryCLIRequiresExplicitSupersessionAndKeepsErrorsClosed(t *testing.T) {
	calls := 0
	req, old := strings.Repeat("c", 32), strings.Repeat("b", 32)
	op := operations{recoverPolicy: func(_ context.Context, path string, expected uint64, request, supersedes string) (installtxn.Result, error) {
		calls++
		if path != "/private/plan" || expected != 2 || request != req || supersedes != old {
			t.Fatal("argument mapping changed")
		}
		return installtxn.Result{}, errors.New("PRIVATE_KEY_PATH_TOKEN")
	}}
	base := []string{"recover-policy", "-plan", "/private/plan", "-expected-revision", "2", "-request-id", req, "-supersedes-request-id", old}
	for _, kind := range []string{"1", "02", "+2", "-2", "18446744073709551615", "18446744073709551616", "request", "supersedes", "equal", "extra", "missing", "flag"} {
		args := append([]string(nil), base...)
		switch kind {
		case "request":
			args[6] = "BAD"
		case "supersedes":
			args[8] = strings.Repeat("A", 32)
		case "equal":
			args[8] = req
		case "extra":
			args = append(args, "--force")
		case "missing":
			args = args[:7]
		case "flag":
			args[7] = "-unit"
		default:
			args[4] = kind
		}
		var out, errout bytes.Buffer
		if run(args, &out, &errout, op) != 1 || calls != 0 || out.Len() != 0 {
			t.Fatal("invalid recovery reached effect", kind)
		}
	}
	var out, errout bytes.Buffer
	if run(base, &out, &errout, op) != 1 || calls != 1 || out.Len() != 0 || strings.Contains(errout.String(), "PRIVATE") {
		t.Fatal("recovery error leaked")
	}
}
