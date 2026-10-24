package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"
)

// This structural guard covers the registration-before-public-serving contract,
// not a reconstruction of an earlier CI exit whose status was not recorded.
func startupSignalOrder(source []byte) bool {
	file, e := parser.ParseFile(token.NewFileSet(), "startup.go", source, 0)
	if e != nil {
		return false
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "runArgs" || fn.Body == nil {
			continue
		}
		registration, serving := -1, -1
		for index, statement := range fn.Body.List {
			if assign, ok := statement.(*ast.AssignStmt); ok && len(assign.Lhs) > 0 && len(assign.Rhs) == 1 {
				name, ok := assign.Lhs[0].(*ast.Ident)
				call, yes := assign.Rhs[0].(*ast.CallExpr)
				if ok && yes && name.Name == "signalCtx" {
					selector, ok := call.Fun.(*ast.SelectorExpr)
					if ok {
						base, ok := selector.X.(*ast.Ident)
						if ok && base.Name == "signal" && selector.Sel.Name == "NotifyContext" {
							for _, arg := range call.Args {
								if sig, ok := arg.(*ast.SelectorExpr); ok {
									pkg, ok := sig.X.(*ast.Ident)
									if ok && pkg.Name == "syscall" && sig.Sel.Name == "SIGTERM" {
										registration = index
									}
								}
							}
						}
					}
				}
			}
			if goroutine, ok := statement.(*ast.GoStmt); ok {
				ast.Inspect(goroutine, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					selector, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					base, ok := selector.X.(*ast.Ident)
					if ok && base.Name == "server" && selector.Sel.Name == "Serve" {
						serving = index
					}
					return true
				})
			}
		}
		return registration >= 0 && serving >= 0 && registration < serving
	}
	return false
}
func TestTerminationRegisteredBeforePublicServe(t *testing.T) {
	source, e := os.ReadFile("main.go")
	if e != nil {
		t.Fatal(e)
	}
	if !startupSignalOrder(source) {
		t.Fatal("public serving can precede SIGTERM registration")
	}
	old := []byte(`package main;func runArgs(){go func(){server.Serve(listener)}();signalCtx,stopSignals:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)}`)
	if startupSignalOrder(old) {
		t.Fatal("earlier ordering falsely accepted")
	}
	conditional := []byte(`package main;func runArgs(){if x {signalCtx,stopSignals:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)};go func(){server.Serve(listener)}()}`)
	if startupSignalOrder(conditional) {
		t.Fatal("conditional registration is not the serving contract")
	}
}
