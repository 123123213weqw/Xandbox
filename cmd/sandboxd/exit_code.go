package main

import (
	"errors"

	"github.com/123123213weqw/Xandbox/internal/diagnostics"
)

const (
	exitFailure           = 1
	exitDiagnosticWrite   = 74
	exitDiagnosticPending = 75
)

// Only the final diagnostic Close boundary creates this origin marker. A
// similarly wrapped error from another subsystem must not become a diagnostic
// shutdown result. Preserve the existing Fault and errors.Is/As chain.
type diagnosticShutdownFailure struct{ fault *diagnostics.Fault }

func (*diagnosticShutdownFailure) Error() string { return "diagnostic shutdown failed" }
func (e *diagnosticShutdownFailure) Unwrap() error {
	if e == nil || e.fault == nil {
		return nil
	}
	return e.fault
}

func diagnosticShutdownFault(cause error) error {
	if cause == nil {
		return nil
	}
	return &diagnosticShutdownFailure{fault: &diagnostics.Fault{
		Reason: diagnostics.DiagnosticsUnavailable,
		Cause:  cause,
	}}
}

// The exit status is a closed observation, NOT a successful shutdown or a retry
// authorization. No I/O, delay, error rendering or new producer is added here.
// Bootstrap keeps its existing status/message contract. All failures remain
// nonzero; only exact Logger.Close sentinels at the marked boundary get 74/75.
func processExitCode(err error) int {
	if err == nil {
		return 0
	}
	var bootstrap *bootstrapFailure
	if errors.As(err, &bootstrap) {
		return exitFailure
	}
	var shutdown *diagnosticShutdownFailure
	if !errors.As(err, &shutdown) || shutdown == nil || shutdown.fault == nil || shutdown.fault.Reason != diagnostics.DiagnosticsUnavailable {
		return exitFailure
	}
	switch shutdown.fault.Cause {
	case diagnostics.ErrWrite:
		return exitDiagnosticWrite
	case diagnostics.ErrPending:
		return exitDiagnosticPending
	default:
		return exitFailure
	}
}
