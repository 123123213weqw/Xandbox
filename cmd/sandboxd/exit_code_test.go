package main

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/diagnostics"
)

func TestDiagnosticShutdownExitCodes(t *testing.T) {
	var absent *diagnosticShutdownFailure
	for _, tc := range []struct {
		err  error
		code int
	}{
		{nil, 0}, {doNotFormat{}, 1}, {diagnostics.ErrPending, 1}, {diagnostics.ErrWrite, 1},
		{&diagnostics.Fault{Reason: diagnostics.DiagnosticsUnavailable, Cause: diagnostics.ErrPending}, 1},
		{diagnosticShutdownFault(diagnostics.ErrPending), 75},
		{diagnosticShutdownFault(diagnostics.ErrWrite), 74},
		{errors.Join(doNotFormat{}, diagnosticShutdownFault(diagnostics.ErrPending)), 75},
		{diagnosticShutdownFault(doNotFormat{}), 1},
		{diagnosticShutdownFault(errors.Join(diagnostics.ErrPending, diagnostics.ErrWrite)), 1},
		{&diagnosticShutdownFailure{}, 1}, {absent, 1},
		{&diagnosticShutdownFailure{fault: &diagnostics.Fault{Reason: diagnostics.Other, Cause: diagnostics.ErrPending}}, 1},
		{errors.Join(&bootstrapFailure{reason: diagnostics.AuthMode, cause: doNotFormat{}}, diagnosticShutdownFault(diagnostics.ErrPending)), 1},
	} {
		if got := processExitCode(tc.err); got != tc.code {
			t.Fatal("closed exit code mismatch", got, tc.code)
		}
	}
}

func TestDiagnosticShutdownFaultPreservesCauseAndClosedReason(t *testing.T) {
	if diagnosticShutdownFault(nil) != nil {
		t.Fatal("nil became a failure")
	}
	for _, cause := range []error{diagnostics.ErrPending, diagnostics.ErrWrite} {
		err := diagnosticShutdownFault(cause)
		var fault *diagnostics.Fault
		if !errors.Is(err, cause) || !errors.As(err, &fault) || fault == nil || fault.Reason != diagnostics.DiagnosticsUnavailable || diagnostics.FailureReason(err) != diagnostics.DiagnosticsUnavailable {
			t.Fatal("diagnostic cause or existing reason was lost")
		}
	}
}

func TestDiagnosticShutdownMessageNeverFormatsCause(t *testing.T) {
	if got := diagnosticShutdownFault(doNotFormat{}).Error(); got != "diagnostic shutdown failed" {
		t.Fatal("shutdown message is not closed")
	}
	var absent *diagnosticShutdownFailure
	if absent.Error() != "diagnostic shutdown failed" || absent.Unwrap() != nil {
		t.Fatal("invalid marker is not closed")
	}
}

func TestDiagnosticShutdownOrdinaryMainAndCloseBoundaryAreWired(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal("ordinary main source unavailable")
	}
	var entry, run *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			switch fn.Name.Name {
			case "main":
				entry = fn
			case "runArgs":
				run = fn
			}
		}
	}
	if entry == nil || run == nil {
		t.Fatal("ordinary source functions absent")
	}
	exits := 0
	ast.Inspect(entry, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !namedSelector(call.Fun, "os", "Exit") {
			return true
		}
		exits++
		if len(call.Args) != 1 {
			t.Fatal("ordinary failure status is not classified")
		}
		decision, ok := call.Args[0].(*ast.CallExpr)
		if !ok || !namedIdentifier(decision.Fun, "processExitCode") || len(decision.Args) != 1 || !namedIdentifier(decision.Args[0], "err") {
			t.Fatal("ordinary main bypasses the closed failure classification")
		}
		return true
	})
	if exits != 1 {
		t.Fatal("ordinary exit boundary changed")
	}
	closes, marks, preserves, budgets := 0, 0, 0, 0
	ast.Inspect(run, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if namedSelector(call.Fun, "diagnostic", "Close") {
			closes++
		}
		if namedIdentifier(call.Fun, "diagnosticShutdownFault") && len(call.Args) == 1 && namedIdentifier(call.Args[0], "e") {
			marks++
		}
		if namedSelector(call.Fun, "errors", "Join") && len(call.Args) == 2 && namedIdentifier(call.Args[0], "retErr") {
			if marker, ok := call.Args[1].(*ast.CallExpr); ok && namedIdentifier(marker.Fun, "diagnosticShutdownFault") {
				preserves++
			}
		}
		if namedSelector(call.Fun, "context", "WithTimeout") && len(call.Args) == 2 {
			if bound, ok := call.Args[1].(*ast.BinaryExpr); ok && bound.Op == token.MUL && namedSelector(bound.Y, "time", "Millisecond") {
				if value, ok := bound.X.(*ast.BasicLit); ok && value.Value == "250" {
					budgets++
				}
			}
		}
		return true
	})
	if closes != 1 || marks != 1 || preserves != 1 || budgets != 1 {
		t.Fatal("ordinary Close/error preservation/250ms boundary changed")
	}
}

func namedIdentifier(expr ast.Expr, name string) bool {
	value, ok := expr.(*ast.Ident)
	return ok && value.Name == name
}
func namedSelector(expr ast.Expr, owner, name string) bool {
	value, ok := expr.(*ast.SelectorExpr)
	return ok && namedIdentifier(value.X, owner) && value.Sel.Name == name
}
