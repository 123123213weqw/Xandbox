package telemetry

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

func activityFunction(t *testing.T, path, name string) *ast.FuncDecl {
	t.Helper()
	f, e := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	var found *ast.FuncDecl
	for _, item := range f.Decls {
		if fn, ok := item.(*ast.FuncDecl); ok && fn.Name.Name == name {
			if found != nil {
				t.Fatal("ambiguous actual function", name)
			}
			found = fn
		}
	}
	if found == nil {
		t.Fatal("actual function missing", name)
	}
	return found
}

func activityName(node ast.Node) string {
	switch n := node.(type) {
	case *ast.Ident:
		return n.Name
	case *ast.SelectorExpr:
		return activityName(n.X) + "." + n.Sel.Name
	}
	return ""
}

func TestCreationActivityHTTPRegistryKindAndReturnBoundaryAreWired(t *testing.T) {
	for _, test := range []struct{ file, function, kind, operation string }{
		{"server.go", "create", "CreationRaw", "a.manager.CreateScoped"},
		{"session.go", "openSession", "CreationSessionOpen", "a.sessions.Open"},
		{"session.go", "switchSession", "CreationSessionSwitch", "a.sessions.Switch"},
	} {
		fn := activityFunction(t, filepath.Join("..", "httpapi", test.file), test.function)
		start, end, original := 0, 0, 0
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if activityName(call.Fun) == "a.manager.WithCreationTrace" {
				if len(call.Args) != 2 || activityName(call.Args[1]) != "telemetry."+test.kind {
					t.Fatal("kind is not sealed handler constant")
				}
				parent, ok := call.Args[0].(*ast.CallExpr)
				if !ok || activityName(parent.Fun) != "r.Context" || len(parent.Args) != 0 {
					t.Fatal("original caller context replaced")
				}
				start++
			}
			if activityName(call.Fun) == test.operation {
				if len(call.Args) == 0 || activityName(call.Args[0]) != "ctx" {
					t.Fatal("original operation lost observer context")
				}
				original++
			}
			return true
		})
		for _, statement := range fn.Body.List {
			if deferCall, ok := statement.(*ast.DeferStmt); ok && activityName(deferCall.Call.Fun) == "telemetry.EndCreationTrace" {
				if len(deferCall.Call.Args) != 1 || activityName(deferCall.Call.Args[0]) != "ctx" {
					t.Fatal("scope end changed context")
				}
				end++
			}
		}
		if start != 1 || end != 1 || original != 1 {
			t.Fatal("missing actual manager-registry handler binding/defer", test.function, start, end, original)
		}
	}
	fn := activityFunction(t, filepath.Join("..", "sandbox", "creation_observation.go"), "WithCreationTrace")
	found := 0
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && activityName(call.Fun) == "telemetry.WithCreationTraceKind" {
			if len(call.Args) != 3 || activityName(call.Args[0]) != "ctx" || activityName(call.Args[1]) != "m.opts.Metrics" || activityName(call.Args[2]) != "kind" {
				t.Fatal("observation uses foreign registry/context/input")
			}
			found++
		}
		return true
	})
	if found != 1 {
		t.Fatal("actual manager registry not connected")
	}
}

func TestCreationActivityPermitAndNodeCheckAreSeparateActualCalls(t *testing.T) {
	// Activity bookkeeping must not be inserted into the response span's clock
	// sample itself. Overall request wall time still includes instrumentation.
	start := activityFunction(t, "creation.go", "StartCreation")
	begin, sample := token.NoPos, token.NoPos
	ast.Inspect(start.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if activityName(c.Fun) == "startCreationActivityCounter" {
				begin = c.Pos()
			}
			if activityName(c.Fun) == "time.Now" {
				sample = c.Pos()
			}
		}
		return true
	})
	if begin == token.NoPos || sample == token.NoPos || begin >= sample {
		t.Fatal("activity setup moved inside original response clock interval")
	}
	end := activityFunction(t, "creation.go", "End")
	sample, bookkeeping := token.NoPos, token.NoPos
	ast.Inspect(end.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if activityName(c.Fun) == "time.Since" {
				sample = c.Pos()
			}
			if activityName(c.Fun) == "span.trace.activityRegistry.endCreationCounter" {
				bookkeeping = c.Pos()
			}
		}
		return true
	})
	if sample == token.NoPos || bookkeeping == token.NoPos || sample >= bookkeeping {
		t.Fatal("activity teardown moved inside original response clock interval")
	}
	fn := activityFunction(t, filepath.Join("..", "firecracker", "node_linux.go"), "acquirePrepare")
	found := map[string]int{}
	for i, statement := range fn.Body.List {
		a, ok := statement.(*ast.AssignStmt)
		if !ok || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
			continue
		}
		call, ok := a.Rhs[0].(*ast.CallExpr)
		if !ok || activityName(call.Fun) != "telemetry.StartCreationActivity" {
			continue
		}
		if len(call.Args) != 2 || activityName(call.Args[0]) != "ctx" {
			t.Fatal("activity lost original context")
		}
		phase := activityName(call.Args[1])
		want := "n.preparing.acquire"
		if phase == "telemetry.CreationNodeCheck" {
			want = "n.check"
		} else if phase != "telemetry.CreationPermitWait" {
			t.Fatal("unknown activity in actual acquirePrepare")
		}
		variable := activityName(a.Lhs[0])
		if i+3 >= len(fn.Body.List) {
			t.Fatal("missing actual guarded operation")
		}
		deferred, ok := fn.Body.List[i+1].(*ast.DeferStmt)
		if !ok || activityName(deferred.Call.Fun) != variable+".End" {
			t.Fatal("missing real return fallback")
		}
		actual, ok := fn.Body.List[i+2].(*ast.AssignStmt)
		if !ok || len(actual.Rhs) != 1 {
			t.Fatal("missing actual operation")
		}
		op, ok := actual.Rhs[0].(*ast.CallExpr)
		if !ok || activityName(op.Fun) != want || len(op.Args) != 1 {
			t.Fatal("activity does not surround the real operation", phase)
		}
		if want == "n.preparing.acquire" && activityName(op.Args[0]) != "ctx" {
			t.Fatal("permit wait context changed")
		}
		if want == "n.check" && activityName(op.Args[0]) != "true" {
			t.Fatal("node safety recheck removed/weakened")
		}
		end, ok := fn.Body.List[i+3].(*ast.ExprStmt)
		if !ok {
			t.Fatal("missing immediate actual boundary end")
		}
		endCall, ok := end.X.(*ast.CallExpr)
		if !ok || activityName(endCall.Fun) != variable+".End" {
			t.Fatal("activity crosses later operations")
		}
		found[phase]++
	}
	if found["telemetry.CreationPermitWait"] != 1 || found["telemetry.CreationNodeCheck"] != 1 || len(found) != 2 {
		t.Fatal("missing separate actual permit/node observations", found)
	}
}
