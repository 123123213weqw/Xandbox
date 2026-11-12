package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/123123213weqw/Xandbox/internal/installtxn"
	"strings"
	"testing"
)

func TestResultBootstrapCLIExplicitGrammarAndFailure(t *testing.T) {
	for _, name := range []string{"apply", "reconcile", "status", "verify", "failure", "revision", "request", "extra", "nil-operation"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			check := func(ctx context.Context) {
				t.Helper()
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("missing fixed deadline")
				}
				calls++
			}
			ops := resultOperations{apply: func(ctx context.Context, p string, n uint64, id string) (installtxn.Result, error) {
				check(ctx)
				if p != "/private/plan" || n != 0 || id != strings.Repeat("a", 32) {
					t.Fatal("arguments changed")
				}
				return installtxn.Result{Version: 1}, nil
			}, reconcile: func(ctx context.Context, id string) (installtxn.Result, error) {
				check(ctx)
				return installtxn.Result{Version: 1}, nil
			}, status: func(ctx context.Context) (installtxn.Result, error) {
				check(ctx)
				return installtxn.Result{Version: 1}, nil
			}, verify: func(ctx context.Context) error { check(ctx); return nil }}
			args := []string{"apply-results", "-plan", "/private/plan", "-expected-revision", "0", "-request-id", strings.Repeat("a", 32)}
			want := 0
			switch name {
			case "reconcile":
				args = []string{"reconcile-results", "-request-id", strings.Repeat("a", 32)}
			case "status":
				args = []string{"status-results"}
			case "verify":
				args = []string{"verify-results"}
			case "failure":
				ops.apply = func(ctx context.Context, _ string, _ uint64, _ string) (installtxn.Result, error) {
					check(ctx)
					return installtxn.Result{}, errors.New("private test error must not escape")
				}
				want = 1
			case "revision":
				args[4] = "1"
				want = 1
			case "request":
				args[6] = strings.Repeat("A", 32)
				want = 1
			case "extra":
				args = append(args, "host-command")
				want = 1
			case "nil-operation":
				ops.apply = nil
				want = 1
			}
			var out, errout bytes.Buffer
			got := runWithResults(args, &out, &errout, ops, operations{})
			if got != want || strings.Contains(errout.String(), "private test error") {
				t.Fatal(got, want, errout.String())
			}
			valid := name == "apply" || name == "reconcile" || name == "status" || name == "verify" || name == "failure"
			if (calls == 1) != valid {
				t.Fatal("unexpected operation", calls)
			}
			if name == "verify" && out.Len() != 0 {
				t.Fatal("verify was not silent")
			}
		})
	}
}
