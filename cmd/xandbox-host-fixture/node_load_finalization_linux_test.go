//go:build linux && xandbox_host_fixture

package main

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"
)

func TestNodeLoadFinalizationHasClosedPrivateErrorProjection(t *testing.T) {
	names := []string{"load_offered_clock", "load_post_offer_empty", "load_quota_tail", "load_post_tail_empty", "load_acceptance", "load_fd_drain", "load_final_sample", "load_sample_validation", "load_inventory_commit", "load_checkpoint_commit"}
	for n, name := range names {
		s := &nodeLoadState{}
		cause := errors.New("private diagnostic path/key/not-for-public-report")
		if got := s.finalFailure(nodeLoadFinalStage(n), cause); got != cause || s.first != cause || s.firstRow.Stage != name {
			t.Fatal("finalization diagnostic lost exact cause or closed stage", n)
		}
		out, err := s.summary()
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(out)
		if err != nil || strings.Contains(string(data), cause.Error()) || !strings.Contains(string(data), `"Stage":"`+name+`"`) || out["observed_result_rows"] != 0 {
			t.Fatal("private error leaked or finalization invented a measured result", n, err)
		}
	}
	s := &nodeLoadState{}
	if err := s.finalFailure(nodeLoadFinalAcceptance, nil); err != nil || s.firstRow != nil || s.first != nil {
		t.Fatal("successful check invented a failure")
	}
	if err := s.finalFailure(nodeLoadFinalStage(255), nil); err == nil || s.firstRow.Stage != "load_invalid_final_stage" {
		t.Fatal("non-closed stage admitted")
	}
}

func TestNodeLoadFinalizationDoesNotReplaceWorkerOrTailFailure(t *testing.T) {
	for _, stage := range []string{"raw_fresh", "canary_switch", "raw_full_quota"} {
		s := &nodeLoadState{}
		first := errors.New("private actual first failure")
		row := nodeLoadRow{Kind: 2, Index: 3, Phase: 4, Tenant: 1, Stage: stage, Outcome: "failed"}
		s.fail(row, first)
		later := errors.New("private later finalization error")
		if s.finalFailure(nodeLoadFinalTail, later) != later || s.first != first || !reflect.DeepEqual(*s.firstRow, row) {
			t.Fatal("finalization erased a real worker/tail failure")
		}
		s.fail(nodeLoadRow{Stage: "load_setup_or_finalization"}, later)
		if s.first != first || !reflect.DeepEqual(*s.firstRow, row) {
			t.Fatal("generic deferred handler replaced the first failure")
		}
	}
}

func TestNodeLoadFinalizationStagesAreWiredIntoActualRun(t *testing.T) {
	// Static wiring check PLUS the dynamic state/projection controls above.
	// No synthetic result is presented as a real long-run/KVM observation.
	f, err := parser.ParseFile(token.NewFileSet(), "node_load_linux.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var run *ast.FuncDecl
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "nodeLoadRun" {
			run = fn
		}
	}
	if run == nil {
		t.Fatal("missing real run")
	}
	var got []string
	ast.Inspect(run.Body, func(n ast.Node) bool {
		r, ok := n.(*ast.ReturnStmt)
		if !ok || len(r.Results) != 2 {
			return true
		}
		call, ok := r.Results[1].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "finalFailure" {
			return true
		}
		if len(call.Args) != 2 {
			t.Fatal("finalization return has an open argument shape")
		}
		receiver, ok := sel.X.(*ast.Ident)
		stage, typed := call.Args[0].(*ast.Ident)
		if !ok || receiver.Name != "state" || !typed {
			t.Fatal("failure return is not tied to the actual run state/closed stage")
		}
		got = append(got, stage.Name)
		return true
	})
	want := []string{"nodeLoadFinalOfferClock", "nodeLoadFinalPostOfferEmpty", "nodeLoadFinalTail", "nodeLoadFinalPostTailEmpty", "nodeLoadFinalAcceptance", "nodeLoadFinalFDDrain", "nodeLoadFinalSample", "nodeLoadFinalSamplesValid", "nodeLoadFinalInventory", "nodeLoadFinalCheckpoint"}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("missing, reordered or untyped finalization return", got)
	}
}
