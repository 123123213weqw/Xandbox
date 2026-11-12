package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/installtxn"
)

func TestResultPolicyCLIExplicitGrammarAndFailure(t *testing.T) {
	for _, name := range []string{"advance", "reconcile", "failure", "revision-zero", "revision-leading-zero", "revision-overflow", "revision-max", "request-upper", "request-short", "extra", "nil-operation", "plan-empty", "wrong-flag", "fallback-status", "fallback-verify-results"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			check := func(ctx context.Context) {
				t.Helper()
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("missing fixed deadline")
				}
				calls++
			}
			ops := resultPolicyOperations{reconfigure: func(ctx context.Context, p string, n uint64, id string) (installtxn.Result, error) {
				check(ctx)
				if p != "/private/result-policy-plan" || n != 2 || id != strings.Repeat("b", 32) {
					t.Fatal("arguments changed")
				}
				return installtxn.Result{Version: 1, Revision: 3}, nil
			}, reconcile: func(ctx context.Context, id string) (installtxn.Result, error) {
				check(ctx)
				if id != strings.Repeat("b", 32) {
					t.Fatal("request changed")
				}
				return installtxn.Result{Version: 1, Revision: 3}, nil
			}}
			bootstrap := resultOperations{verify: func(ctx context.Context) error { check(ctx); return nil }}
			old := operations{status: func(ctx context.Context) (installtxn.Result, error) {
				check(ctx)
				return installtxn.Result{Version: 1}, nil
			}}
			args := []string{"reconfigure-results", "-plan", "/private/result-policy-plan", "-expected-revision", "2", "-request-id", strings.Repeat("b", 32)}
			want := 1
			valid := false
			switch name {
			case "advance":
				want = 0
				valid = true
			case "reconcile":
				args = []string{"reconcile-results-policy", "-request-id", strings.Repeat("b", 32)}
				want = 0
				valid = true
			case "failure":
				ops.reconfigure = func(ctx context.Context, _ string, _ uint64, _ string) (installtxn.Result, error) {
					check(ctx)
					return installtxn.Result{}, errors.New("private-result-policy-error-must-not-escape")
				}
				valid = true
			case "revision-zero":
				args[4] = "0"
			case "revision-leading-zero":
				args[4] = "02"
			case "revision-overflow":
				args[4] = "18446744073709551616"
			case "revision-max":
				args[4] = "18446744073709551615"
			case "request-upper":
				args[6] = strings.Repeat("B", 32)
			case "request-short":
				args[6] = "b"
			case "extra":
				args = append(args, "host-command")
			case "nil-operation":
				ops.reconfigure = nil
			case "plan-empty":
				args[2] = ""
			case "wrong-flag":
				args[3] = "-mode"
			case "fallback-status":
				args = []string{"status"}
				want = 0
				valid = true
			case "fallback-verify-results":
				args = []string{"verify-results"}
				want = 0
				valid = true
			}
			var out, errout bytes.Buffer
			got := runWithResultPolicy(args, &out, &errout, ops, bootstrap, old)
			if got != want || strings.Contains(errout.String(), "private-result-policy-error") {
				t.Fatal(got, want, errout.String())
			}
			if (calls == 1) != valid {
				t.Fatal("unexpected operation", calls)
			}
			if name == "fallback-verify-results" && out.Len() != 0 {
				t.Fatal("old verify no longer silent")
			}
		})
	}
}
