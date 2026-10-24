package main

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/diagnostics"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
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

func TestBootstrapExtendedClassesAreClosedAndPreserveConcreteErrno(t *testing.T) {
	for reason, want := range map[diagnostics.Reason]string{
		diagnostics.IOFailure:         "input/output error",
		diagnostics.QuotaExceeded:     "disk quota exceeded",
		diagnostics.NoSpace:           "no space left on device",
		diagnostics.ReadOnly:          "read-only file system",
		diagnostics.NodeAdmission:     "frontend admission differs from immutable node policy",
		diagnostics.NodePlacement:     "controller/publisher must be inside node control subtree",
		diagnostics.IOBackingQueue:    "IO policy must name the exact runtime backing queue",
		diagnostics.IODelegation:      "configured IO policy requires delegated io controller",
		diagnostics.BackendBinding:    "backend binding changed; explicit offline migration is required",
		diagnostics.QuotaCapabilities: "quota requires CAP_SYS_RESOURCE absent from all capability sets",
		diagnostics.QuotaFilesystem:   "quota runtime filesystem UUID changed",
		diagnostics.QuotaOwnership:    "unowned nonempty quota record requires operator reconciliation",
		diagnostics.QuotaMount:        "quota requires the exact writable ext4 mount with enforced prjquota",
	} {
		e := &bootstrapFailure{reason: reason, cause: doNotFormat{}}
		if e.Error() != "sandboxd: "+want || strings.ContainsAny(e.Error(), "\r\n") {
			t.Fatal("bootstrap class not exact")
		}
	}
	for _, tc := range []struct {
		e error
		r diagnostics.Reason
	}{
		{&diagnostics.Fault{Reason: diagnostics.DiagnosticsUnavailable, Cause: &os.PathError{Op: "secret", Path: "private-secret", Err: syscall.ENOSPC}}, diagnostics.NoSpace},
		{&diagnostics.Fault{Reason: diagnostics.DiagnosticsUnavailable, Cause: syscall.EROFS}, diagnostics.ReadOnly},
		{firecracker.ErrIOBackingQueue, diagnostics.IOBackingQueue},
		{firecracker.ErrQuotaMount, diagnostics.QuotaMount},
	} {
		if firecracker.DiagnosticReason(tc.e) != tc.r {
			t.Fatal("known errno or policy class was masked")
		}
	}
}
