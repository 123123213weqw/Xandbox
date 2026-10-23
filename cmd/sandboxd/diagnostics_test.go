package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/diagnostics"
)

type doNotFormat struct{}

func (doNotFormat) Error() string { panic("must not render cause") }
func TestBootstrapClassesNeverRenderCauseOrFlagValues(t *testing.T) {
	for _, reason := range []diagnostics.Reason{diagnostics.Other, diagnostics.StateLock, diagnostics.AuthMode, diagnostics.DiagnosticsUnavailable, 255} {
		e := &bootstrapFailure{reason: reason, cause: doNotFormat{}}
		if !strings.HasPrefix(e.Error(), "sandboxd:") || e.Unwrap() == nil {
			t.Fatal("closed bootstrap class")
		}
	}
	for _, args := range [][]string{
		{"-max-instances", "private-value\ninjected-line"},
		{"-unknown-secret-argument"},
		{"-backend", "mock", "-state-dir", "/private-path-not-created"},
	} {
		e := runArgs(args)
		var b *bootstrapFailure
		if e == nil || !errors.As(e, &b) || strings.Contains(e.Error(), "private-") || strings.Contains(e.Error(), "injected") {
			t.Fatal("unclosed bootstrap output")
		}
	}
}
