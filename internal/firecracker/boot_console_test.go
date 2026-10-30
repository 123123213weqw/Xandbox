package firecracker

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// Source-mechanism guard only, not a guest boot, timing or performance test.
// Read the actual cold branch and the table consumed by its apiPut loop; a
// comment, unused constant or test-only duplicate is not the boot contract.
func coldBootConsoleExpression(t *testing.T) ast.Expr {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "driver_linux.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var prepare *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "Prepare" && fn.Recv != nil && len(fn.Recv.List) == 1 {
			if pointer, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
				if receiver, ok := pointer.X.(*ast.Ident); ok && receiver.Name == "driver" {
					prepare = fn
				}
			}
		}
	}
	if prepare == nil {
		t.Fatal("ordinary Prepare missing")
	}
	var cold *ast.BlockStmt
	ast.Inspect(prepare.Body, func(n ast.Node) bool {
		stmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		condition, ok := stmt.Cond.(*ast.BinaryExpr)
		if !ok || condition.Op != token.NEQ {
			return true
		}
		selector, ok := condition.X.(*ast.SelectorExpr)
		nilValue, nilOK := condition.Y.(*ast.Ident)
		if ok && selector.Sel.Name == "Snapshot" && nilOK && nilValue.Name == "nil" {
			if config, ok := selector.X.(*ast.SelectorExpr); ok && config.Sel.Name == "cfg" {
				if owner, ok := config.X.(*ast.Ident); ok && owner.Name == "d" {
					cold, _ = stmt.Else.(*ast.BlockStmt)
				}
			}
		}
		return true
	})
	if cold == nil {
		t.Fatal("ordinary snapshot/cold boundary missing")
	}
	var expression ast.Expr
	definitions, boundTables := 0, 0
	ast.Inspect(cold, func(n ast.Node) bool {
		if assignment, ok := n.(*ast.AssignStmt); ok && assignment.Tok == token.DEFINE && len(assignment.Lhs) == 1 && len(assignment.Rhs) == 1 {
			if name, ok := assignment.Lhs[0].(*ast.Ident); ok && name.Name == "bootArgs" {
				definitions++
				expression = assignment.Rhs[0]
			}
		}
		loop, ok := n.(*ast.RangeStmt)
		if !ok {
			return true
		}
		value, ok := loop.Value.(*ast.Ident)
		table, tableOK := loop.X.(*ast.CompositeLit)
		if !ok || !tableOK || value.Name != "put" {
			return true
		}
		bound, called := false, false
		for _, row := range table.Elts {
			entry, ok := row.(*ast.CompositeLit)
			if !ok || len(entry.Elts) != 2 {
				continue
			}
			path, pathOK := entry.Elts[0].(*ast.BasicLit)
			body, bodyOK := entry.Elts[1].(*ast.CompositeLit)
			if !pathOK || path.Value != `"/boot-source"` || !bodyOK {
				continue
			}
			for _, field := range body.Elts {
				pair, ok := field.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, keyOK := pair.Key.(*ast.BasicLit)
				argument, argumentOK := pair.Value.(*ast.Ident)
				if keyOK && key.Value == `"boot_args"` && argumentOK && argument.Name == "bootArgs" {
					bound = true
				}
			}
		}
		ast.Inspect(loop.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 4 {
				return true
			}
			fn, ok := call.Fun.(*ast.Ident)
			path, pathOK := call.Args[2].(*ast.SelectorExpr)
			body, bodyOK := call.Args[3].(*ast.SelectorExpr)
			if ok && fn.Name == "apiPut" && pathOK && bodyOK && path.Sel.Name == "path" && body.Sel.Name == "body" {
				pathOwner, p := path.X.(*ast.Ident)
				bodyOwner, b := body.X.(*ast.Ident)
				called = called || (p && b && pathOwner.Name == "put" && bodyOwner.Name == "put")
			}
			return true
		})
		if bound && called {
			boundTables++
		}
		return true
	})
	if definitions != 1 || boundTables != 1 {
		t.Fatalf("ordinary cold boot argument binding changed: definitions=%d tables=%d", definitions, boundTables)
	}
	return expression
}

func evaluateColdBootConsoleExpression(expression ast.Expr, id, generation string) (string, error) {
	switch node := expression.(type) {
	case *ast.BasicLit:
		if node.Kind == token.STRING {
			return strconv.Unquote(node.Value)
		}
	case *ast.BinaryExpr:
		if node.Op == token.ADD {
			left, err := evaluateColdBootConsoleExpression(node.X, id, generation)
			if err != nil {
				return "", err
			}
			right, err := evaluateColdBootConsoleExpression(node.Y, id, generation)
			if err != nil {
				return "", err
			}
			return left + right, nil
		}
	case *ast.SelectorExpr:
		if owner, ok := node.X.(*ast.Ident); ok && owner.Name == "ref" {
			switch node.Sel.Name {
			case "ID":
				return id, nil
			case "Generation":
				return generation, nil
			}
		}
	}
	return "", fmt.Errorf("cold boot policy contains an opaque expression")
}

func TestColdBootConsolePolicyUsesActualColdAPIArguments(t *testing.T) {
	args, err := evaluateColdBootConsoleExpression(coldBootConsoleExpression(t), strings.Repeat("a", 32), strings.Repeat("b", 32))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(" "+args+" ", " quiet ") != 1 {
		t.Fatal("ordinary cold API arguments do not request quiet console exactly once")
	}
}

func TestColdBootConsolePolicyPreservesOriginalGuestContract(t *testing.T) {
	for _, pair := range [][2]string{{strings.Repeat("a", 32), strings.Repeat("b", 32)}, {strings.Repeat("c", 32), strings.Repeat("d", 32)}} {
		args, err := evaluateColdBootConsoleExpression(coldBootConsoleExpression(t), pair[0], pair[1])
		if err != nil {
			t.Fatal(err)
		}
		want := "console=ttyS0 quiet reboot=k panic=1 pci=off rdinit=/sbin/init xandbox.guest=1 xandbox.id=" + pair[0] + " xandbox.generation=" + pair[1]
		if args != want {
			t.Fatal("ordinary guest arguments changed beyond the reviewed quiet flag")
		}
	}
}

func TestColdBootConsolePolicyGuardRejectsOpaqueExpressions(t *testing.T) {
	for _, text := range []string{`incomingHeader()`, `ctx.Value("args")`, `request.ID`, `ref.Other`, `"a" * "b"`, `123`, `ambient`} {
		expression, err := parser.ParseExpr(text)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evaluateColdBootConsoleExpression(expression, "id", "generation"); err == nil {
			t.Fatal("opaque expression accepted by source-only guard")
		}
	}
}
