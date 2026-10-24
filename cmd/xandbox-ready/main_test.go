package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestOnlyFixedManifestAndClosedFailure(t *testing.T) {
	for _, args := range [][]string{nil, {"-manifest"}, {"-manifest", "/etc/ready.json", "sh"}, {"-manifest=/etc/ready.json"}, {"-token", "private"}, {"-manifest", ""}} {
		var b bytes.Buffer
		called := false
		if run(args, &b, func(string) error { called = true; return nil }) != 1 || called || strings.Contains(b.String(), "private") {
			t.Fatal("unsafe CLI")
		}
	}
	var b bytes.Buffer
	if run([]string{"-manifest", "/etc/ready.json"}, &b, func(string) error { return errors.New("secret-private-path") }) != 1 || strings.Contains(b.String(), "secret-private-path") {
		t.Fatal("raw error exported")
	}
	b.Reset()
	if run([]string{"-manifest", "/etc/ready.json"}, &b, func(string) error { return nil }) != 0 || b.Len() != 0 {
		t.Fatal("successful helper must stay quiet")
	}
}
