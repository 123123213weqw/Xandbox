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
