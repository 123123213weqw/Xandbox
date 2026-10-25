package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/releasestore"
)

func TestFixedCLIAndPrivateFailures(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"status", "extra"}, {"publish", "-manifest", "/private", "-expected-revision", "01", "-request-id", strings.Repeat("a", 32)}, {"publish", "-manifest", "/private", "-expected-revision", "-1", "-request-id", "id"}, {"publish", "-manifest", "/private", "-expected-revision", "0", "-request-id", "id", "exec", "sh"}} {
		var out, errout bytes.Buffer
		called := false
		p := func(context.Context, string, uint64, string) (releasestore.Result, error) {
			called = true
			return releasestore.Result{}, nil
		}
		s := func(context.Context) (releasestore.Result, error) { called = true; return releasestore.Result{}, nil }
		if run(args, &out, &errout, p, s) != 1 || called || out.Len() != 0 {
			t.Fatalf("invalid CLI reached operation %q", args)
		}
	}
	var out, errout bytes.Buffer
	secret := "private-path-secret-token"
	p := func(ctx context.Context, m string, r uint64, id string) (releasestore.Result, error) {
		if _, ok := ctx.Deadline(); !ok || m != "/private" || r != 0 || id != strings.Repeat("a", 32) {
			t.Fatal("fixed request changed")
		}
		return releasestore.Result{}, errors.New(secret)
	}
	if run([]string{"publish", "-manifest", "/private", "-expected-revision", "0", "-request-id", strings.Repeat("a", 32)}, &out, &errout, p, nil) != 1 || out.Len() != 0 || strings.Contains(errout.String(), secret) {
		t.Fatal("raw error exported")
	}
	out.Reset()
	errout.Reset()
	s := func(context.Context) (releasestore.Result, error) { return releasestore.Result{Version: 1}, nil }
	if run([]string{"status"}, &out, &errout, nil, s) != 0 || errout.Len() != 0 || !strings.Contains(out.String(), `"services_changed":false`) {
		t.Fatal("status result mismatch")
	}
}
