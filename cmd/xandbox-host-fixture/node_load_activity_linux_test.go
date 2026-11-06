//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/telemetry"
)

func nodeLoadActivityMetricsFixture() []byte {
	r := &telemetry.Registry{}
	c := telemetry.WithCreationTraceKind(context.Background(), r, telemetry.CreationSessionSwitch)
	defer telemetry.EndCreationTrace(c)
	s := telemetry.StartCreation(c, telemetry.DriverPrepareSlot)
	defer s.End()
	a := telemetry.StartCreationActivity(c, telemetry.CreationPermitWait)
	defer a.End()
	return r.Render(telemetry.Gauges{})
}

func TestNodeLoadCreationActivityParsesSealedCurrentExposition(t *testing.T) {
	status, v := nodeLoadReadCreationActivity(nodeLoadActivityMetricsFixture())
	if status != "observed" || v == nil || v.Version != 1 || v.Requests != [3]uint64{0, 0, 1} || v.Phases[2][4] != 1 || v.Phases[2][13] != 1 || v.Phases[2][14] != 0 {
		t.Fatal("exact current producer exposition not preserved")
	}
	copy := nodeLoadCloneCreationActivity(v)
	v.Requests[2] = 88
	v.Phases[2][13] = 99
	if copy.Requests[2] != 1 || copy.Phases[2][13] != 1 || nodeLoadCloneCreationActivity(nil) != nil {
		t.Fatal("frozen snapshot aliases mutable source")
	}
	// Distinguish every producer kind/phase index, not only the two examples.
	r := &telemetry.Registry{}
	var spans []*telemetry.CreationActivitySpan
	for kind := 0; kind < 3; kind++ {
		ctx := telemetry.WithCreationTraceKind(context.Background(), r, telemetry.CreationKind(kind))
		defer telemetry.EndCreationTrace(ctx)
		for phase := 0; phase < 15; phase++ {
			for n := 0; n < 1+phase+16*kind; n++ {
				spans = append(spans, telemetry.StartCreationActivity(ctx, telemetry.CreationActivityPhase(phase)))
			}
		}
	}
	defer func() {
		for _, s := range spans {
			s.End()
		}
	}()
	status, all := nodeLoadReadCreationActivity(r.Render(telemetry.Gauges{}))
	if status != "observed" || all == nil {
		t.Fatal("complete current producer vocabulary missing")
	}
	for kind := 0; kind < 3; kind++ {
		if all.Requests[kind] != 1 {
			t.Fatal("kind index drift")
		}
		for phase := 0; phase < 15; phase++ {
			if all.Phases[kind][phase] != uint64(1+phase+16*kind) {
				t.Fatal("producer/consumer phase ordinal drift", kind, phase)
			}
		}
	}
}

func TestNodeLoadCreationActivityMissingDisabledInvalidAreNotZero(t *testing.T) {
	b := string(nodeLoadActivityMetricsFixture())
	for _, test := range []struct{ text, status string }{
		{"xandbox_records 3\n", "missing"},
		{strings.Replace(b, "xandbox_creation_activity_enabled 1", "xandbox_creation_activity_enabled 0", 1), "disabled"},
		{strings.Replace(b, "xandbox_creation_activity_invalid 0", "xandbox_creation_activity_invalid 1", 1), "invalid"},
	} {
		status, v := nodeLoadReadCreationActivity([]byte(test.text))
		if status != test.status || v != nil {
			t.Fatal("unknown observation became zero-valued data", status)
		}
		row, e := json.Marshal(nodeLoadObservation{CreationActivityStatus: status})
		if e != nil || !strings.Contains(string(row), `"creation_activity":null`) {
			t.Fatal("unavailable values were published as counters")
		}
	}
}

func TestNodeLoadCreationActivityRejectsMalformedPartialAndUnbounded(t *testing.T) {
	b := string(nodeLoadActivityMetricsFixture())
	line := `xandbox_creation_requests_active{operation="raw_create"} 0`
	for _, text := range []string{
		b + line + "\n", strings.Replace(b, line+"\n", "", 1),
		b + "xandbox_creation_unreviewed 0\n", strings.Replace(b, line, strings.Replace(line, "raw_create", "tenant-secret", 1), 1),
		strings.Replace(b, `phase="xa_driver_slot"`, `phase="unreviewed"`, 1),
		strings.Replace(b, line, strings.TrimSuffix(line, "0")+"-1", 1),
		strings.Replace(b, line, strings.TrimSuffix(line, "0")+"NaN", 1),
		strings.Replace(b, line, strings.TrimSuffix(line, "0")+"00", 1),
		strings.Replace(b, line, strings.TrimSuffix(line, "0")+"1048577", 1),
		strings.Replace(b, line, line+" extra", 1),
		strings.Repeat("x", (256<<10)+1),
	} {
		status, v := nodeLoadReadCreationActivity([]byte(text))
		if status != "malformed" || v != nil {
			t.Fatal("malformed/unknown observation accepted")
		}
	}
}

func TestNodeLoadCreationActivityDoesNotInventTransactionalConsistency(t *testing.T) {
	b := string(nodeLoadActivityMetricsFixture())
	b = strings.Replace(b, `xandbox_creation_requests_active{operation="session_switch"} 1`, `xandbox_creation_requests_active{operation="session_switch"} 0`, 1)
	status, v := nodeLoadReadCreationActivity([]byte(b))
	if status != "observed" || v == nil || v.Requests[2] != 0 || v.Phases[2][13] != 1 {
		t.Fatal("independent samples rejected as an impossible atomic snapshot")
	}
}

func TestNodeLoadCreationActivityIsOnExistingReadAndOriginalObservationBounds(t *testing.T) {
	f, e := parser.ParseFile(token.NewFileSet(), "node_load_observe_linux.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	do, read, found := 0, 0, 0
	for _, declaration := range f.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "nodeLoadObserve" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				if method, ok := call.Fun.(*ast.SelectorExpr); ok && method.Sel.Name == "Do" {
					do++
				}
				if name, ok := call.Fun.(*ast.Ident); ok {
					if name.Name == "readSwitchMetrics" {
						read++
					}
					if name.Name == "nodeLoadReadCreationActivity" {
						if len(call.Args) != 1 {
							t.Fatal("unexpected activity source")
						}
						arg, ok := call.Args[0].(*ast.Ident)
						if !ok || arg.Name != "b" {
							t.Fatal("not the original response bytes")
						}
						found++
					}
				}
			}
			return true
		})
	}
	if do != 1 || read != 1 || found != 1 || nodeLoadProbeSlots != 8 || nodeLoadReplyMax != 1<<20 {
		t.Fatal("observer added a management call or changed fixed limits", do, read, found)
	}
	// A per-row version alone cannot distinguish an old capsule with no rows.
	state, e := parser.ParseFile(token.NewFileSet(), "node_load_state_linux.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	stamp, bound := token.NoPos, token.NoPos
	for _, item := range state.Decls {
		fn, ok := item.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "summary" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if a, ok := node.(*ast.AssignStmt); ok && len(a.Lhs) == 1 && len(a.Rhs) == 1 {
				if field, ok := a.Lhs[0].(*ast.SelectorExpr); ok && field.Sel.Name == "CreationActivityVersion" {
					parent, ok := field.X.(*ast.SelectorExpr)
					if !ok || parent.Sel.Name != "privateDiagnostics" {
						t.Fatal("private version stamped on unrelated value")
					}
					owner, ok := parent.X.(*ast.Ident)
					if !ok || owner.Name != "s" {
						t.Fatal("private version lost actual state receiver")
					}
					v, ok := a.Rhs[0].(*ast.BasicLit)
					if !ok || v.Value != "1" || stamp != token.NoPos {
						t.Fatal("unsealed/duplicate private observation version")
					}
					stamp = a.Pos()
				}
			}
			if call, ok := node.(*ast.CallExpr); ok {
				if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "nodeLoadPrivateBound" {
					bound = call.Pos()
				}
			}
			return true
		})
	}
	if stamp == token.NoPos || bound == token.NoPos || stamp >= bound {
		t.Fatal("mandatory discriminator not set before actual private capsule")
	}
	status, v := nodeLoadReadCreationActivity(nodeLoadActivityMetricsFixture())
	row := nodeLoadObservation{CreationActivityStatus: status, CreationActivity: v}
	full := nodeLoadPrivateDiagnostics{Slow: make([]nodeLoadObservation, 8), Failure: &row}
	for i := range full.Slow {
		full.Slow[i] = row
	}
	if e := nodeLoadPrivateBound(full); e != nil {
		t.Fatal("fixed numeric extension exceeded original private bound")
	}
}
