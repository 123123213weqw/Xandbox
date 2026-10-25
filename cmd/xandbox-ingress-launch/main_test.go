package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestFixedCLIRejectsArgumentsWithoutExecutingAnything(t *testing.T) {
	for _, args := range [][]string{nil, {"-unknown-private-value"}, {"-manifest"}, {"-manifest", ""}, {"-manifest", "/private/config", "tenant-command"}, {"-manifest", "/private/config", "-exec", "/bin/sh"}, {"-h"}, {"-manifest", "/private/a", "-manifest", "/private/b"}} {
		var out bytes.Buffer
		calls := 0
		code := run(args, &out, func(string) error { calls++; return nil })
		if code != 1 || calls != 0 || out.String() != "xandbox-ingress-launch: fixed manifest required; no fallback\n" {
			t.Fatal("invalid CLI executed or leaked an argument")
		}
	}
}
func TestFixedCLIFailureNeverPrintsRootPathOrUnderlyingError(t *testing.T) {
	var out bytes.Buffer
	calls := 0
	if run([]string{"-manifest", "/private/config"}, &out, func(path string) error {
		calls++
		if path != "/private/config" {
			t.Fatal("manifest changed")
		}
		return errors.New("private-credential-or-path")
	}) != 1 || calls != 1 {
		t.Fatal("launch result drift")
	}
	if strings.Contains(out.String(), "private") || out.String() != "xandbox-ingress-launch: preflight failed (platform); gateway not executed\n" {
		t.Fatal("raw failure leaked")
	}
}
