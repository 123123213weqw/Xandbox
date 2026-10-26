package telemetry

// Physical source inputs are deliberate: the current test executable can
// reject historical files without recompiling the historical implementation.
import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreationTimingBoundariesAreWiredToOrdinaryCalls(t *testing.T) {
	for _, test := range []struct {
		file, function string
		pairs          map[string]string
	}{
		{filepath.Join("..", "sandbox", "manager.go"), "createScoped", map[string]string{"CoreOwnershipCommit": "Save", "CoreDriver": "Prepare", "CoreReadyCommit": "saveLocked"}},
		{filepath.Join("..", "session", "broker.go"), "mutate", map[string]string{"SessionIntentCommit": "persist", "SessionPreparedCommit": "persist", "SessionActiveCommit": "persist"}},
		{filepath.Join("..", "firecracker", "driver_linux.go"), "Prepare", map[string]string{"DriverPrepareSlot": "acquirePrepare", "DriverOwnership": "reserveContext", "DriverQuotaReserve": "reserve", "DriverQuotaVerify": "verifyPrepared"}},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), test.file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		var body *ast.BlockStmt
		for _, declaration := range file.Decls {
			if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Name.Name == test.function {
				if body != nil {
					t.Fatal("ambiguous ordinary function")
				}
				body = fn.Body
			}
		}
		if body == nil {
			t.Fatal("ordinary function missing", test.file)
		}
		found := map[string]int{}
		ast.Inspect(body, func(node ast.Node) bool {
			block, ok := node.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i, statement := range block.List {
				start, ok := statement.(*ast.AssignStmt)
				if !ok || len(start.Lhs) != 1 || len(start.Rhs) != 1 {
					continue
				}
				variable, ok := start.Lhs[0].(*ast.Ident)
				if !ok {
					continue
				}
				call, ok := start.Rhs[0].(*ast.CallExpr)
				if !ok || len(call.Args) != 2 {
					continue
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "StartCreation" {
					continue
				}
				phase, ok := call.Args[1].(*ast.SelectorExpr)
				if !ok {
					continue
				}
				actual, wanted := test.pairs[phase.Sel.Name]
				if !wanted {
					continue
				}
				if i+2 >= len(block.List) {
					t.Fatal("missing actual boundary", phase.Sel.Name)
				}
				invocations := 0
				ast.Inspect(block.List[i+1], func(n ast.Node) bool {
					if c, ok := n.(*ast.CallExpr); ok {
						if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == actual {
							invocations++
						}
					}
					return true
				})
				end, ok := block.List[i+2].(*ast.ExprStmt)
				if !ok {
					t.Fatal("phase does not end immediately after actual call", phase.Sel.Name)
				}
				finish, ok := end.X.(*ast.CallExpr)
				if !ok {
					t.Fatal("missing phase End")
				}
				method, ok := finish.Fun.(*ast.SelectorExpr)
				if !ok || method.Sel.Name != "End" {
					t.Fatal("wrong phase end")
				}
				receiver, ok := method.X.(*ast.Ident)
				if !ok || receiver.Name != variable.Name || invocations != 1 {
					t.Fatal("phase not paired with exactly one original call", phase.Sel.Name)
				}
				found[phase.Sel.Name]++
			}
			return true
		})
		for phase := range test.pairs {
			if found[phase] != 1 {
				t.Fatal("missing, duplicated or unwired creation phase", phase, found)
			}
		}
	}
}

func TestCreationTimingHTTPObserverIsNotAnIncomingSelector(t *testing.T) {
	// Also require publication to occur after the original operation returned;
	// an empty pre-call header is not evidence of a fast operation.
	for _, name := range []string{"server.go", "session.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "httpapi", name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || (fn.Name.Name != "create" && fn.Name.Name != "openSession" && fn.Name.Name != "switchSession") {
				continue
			}
			var order []string
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch f := call.Fun.(type) {
				case *ast.SelectorExpr:
					if f.Sel.Name == "WithCreationTrace" || f.Sel.Name == "CreateScoped" || f.Sel.Name == "Open" || f.Sel.Name == "Switch" {
						order = append(order, f.Sel.Name)
					}
				case *ast.Ident:
					if f.Name == "creationTiming" {
						order = append(order, f.Name)
					}
				}
				return true
			})
			if len(order) != 3 || order[0] != "WithCreationTrace" || order[2] != "creationTiming" || !strings.Contains("CreateScoped Open Switch", order[1]) {
				t.Fatal("ordinary HTTP observer missing/reordered", fn.Name.Name, order)
			}
		}
	}
}
