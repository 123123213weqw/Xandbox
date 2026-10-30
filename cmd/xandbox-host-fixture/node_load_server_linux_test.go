//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/telemetry"
)

func TestNodeLoadServerTimingClosedDecoderAndProducerVocabulary(t *testing.T) {
	ctx := telemetry.WithCreationTrace(context.Background())
	for _, phase := range []telemetry.CreationPhase{telemetry.CoreAdmission, telemetry.CoreOwnershipCommit, telemetry.CoreDriver, telemetry.CoreReadyCommit, telemetry.DriverPrepareSlot, telemetry.DriverOwnership, telemetry.DriverQuotaReserve, telemetry.DriverAssetCopy, telemetry.DriverQuotaVerify, telemetry.DriverActivation, telemetry.SessionIntentCommit, telemetry.SessionPreparedCommit, telemetry.SessionActiveCommit} {
		telemetry.StartCreation(ctx, phase).End()
	}
	entries, ok := nodeLoadServerEntries([]string{telemetry.CreationServerTiming(ctx)})
	if !ok || len(entries) != 13 {
		t.Fatal("producer/consumer vocabularies disagree", entries, ok)
	}
	for n, entry := range entries {
		if entry.Phase != nodeLoadServerNames[n] || entry.Calls != 1 {
			t.Fatal("wrong closed metric", entry)
		}
	}
	good := `xa_core_admission;dur=20.125;desc="n1"`
	for _, values := range [][]string{nil, {""}, {good, good}, {strings.Repeat("x", 2049)}, {good + ", " + good}, {`private;dur=1.000;desc="n1"`}, {`xa_core_admission;dur=NaN;desc="n1"`}, {`xa_core_admission;dur=-1.000;desc="n1"`}, {`xa_core_admission;dur=35001.001;desc="n1"`}, {`xa_core_admission;dur=1.000;desc="n2"`}, {good + `;key="private"`}, {"xa_core_driver;dur=1.000;desc=\"n1\", " + good}} {
		if _, ok := nodeLoadServerEntries(values); ok {
			t.Fatal("open/duplicate/oversized timing accepted")
		}
	}
}

func TestNodeLoadServerTimingActualCallPreservesResponseErrorAndContext(t *testing.T) {
	for _, mode := range []string{"refusal", "deadline", "absent", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			original, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			defer cancel()
			actors := &nodeLoadActors{}
			ctx, actor := actors.begin(original, 1, 64, 0, 0, nil)
			calls := 0
			api := &switchAPI{http: &http.Client{Transport: nodeLoadActorTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Context() != ctx || req.Header.Get("Server-Timing") != "" {
					t.Fatal("observer changed context or request headers")
				}
				if mode == "deadline" {
					return nil, context.DeadlineExceeded
				}
				response := nodeLoadActorReply(503, map[string]any{"error": map[string]string{"code": "UNAVAILABLE"}})
				response.Header = make(http.Header)
				if mode != "absent" {
					response.Header.Set("Server-Timing", `xa_core_admission;dur=0.000;desc="n1"`)
				}
				if mode == "invalid" {
					response.Header.Set("Server-Timing", "private-header-secret")
				}
				return response, nil
			})}}
			outcome, err := nodeLoadTraced(ctx, loadActorOpenHTTP, func() (string, error) {
				return nodeLoadCall(ctx, api, "POST", "/v1/sessions", "fixed-test", nodeSpec(), nil, 201)
			})
			if calls != 1 || (mode == "deadline" && !errors.Is(err, context.DeadlineExceeded)) || (mode != "deadline" && (err != nil || outcome != "service_unavailable503")) {
				t.Fatal("observation changed/retried original API result", calls, outcome, err)
			}
			v := actor.snapshot()
			if len(v.Server) != 1 || v.Server[0].Phase != "canary_open_http" || v.Server[0].ResponseObserved != (mode != "deadline") || v.Server[0].TimingsPresent != (mode != "deadline" && mode != "absent") || v.Invalid != (mode == "invalid") {
				t.Fatal("absent/invalid response hidden", v)
			}
			if mode == "refusal" && (len(v.Server[0].Entries) != 1 || v.Phases[0].Outcome != "ok") {
				t.Fatal("ordinary refusal was relabeled", v)
			}
		})
	}
}

func TestNodeLoadServerTimingFirstFailureDeepCopiesNestedMetrics(t *testing.T) {
	actors := &nodeLoadActors{}
	ctx, actor := actors.begin(context.Background(), 1, 64, 0, 0, nil)
	_ = nodeLoadTraceError(ctx, loadActorSwitch, func() error {
		nodeLoadCaptureServer(ctx, &http.Response{Header: http.Header{"Server-Timing": {`xa_core_admission;dur=0.000;desc="n1"`}}})
		return context.DeadlineExceeded
	})
	row := nodeLoadRow{Kind: 1, Index: 64, Tenant: 0, Stage: "canary_switch"}
	actor.finish(row, context.DeadlineExceeded)
	actors.freezeFailure(row, context.DeadlineExceeded)
	actor.mu.Lock()
	actor.value.Server[0].Entries[0].MS = 99
	actor.mu.Unlock()
	v := actors.snapshot()
	if v.Failure == nil || v.Failure.Server[0].Entries[0].MS != 0 {
		t.Fatal("failure aliases live actor")
	}
	v.Failure.Server[0].Entries[0].MS = 88
	if actors.snapshot().Failure.Server[0].Entries[0].MS != 0 {
		t.Fatal("snapshot aliases first failure")
	}
}

func TestNodeLoadServerTimingHookIsOnOriginalHTTPResponse(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "node_load_api_linux.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got int
	for _, declaration := range f.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "nodeLoadCall" {
			continue
		}
		for i, statement := range fn.Body.List {
			assign, ok := statement.(*ast.AssignStmt)
			if !ok || len(assign.Rhs) != 1 {
				continue
			}
			call, ok := assign.Rhs[0].(*ast.CallExpr)
			if !ok {
				continue
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Do" {
				continue
			}
			if len(assign.Lhs) != 2 || i+1 >= len(fn.Body.List) {
				t.Fatal("original HTTP response shape changed")
			}
			response, ok := assign.Lhs[0].(*ast.Ident)
			if !ok {
				t.Fatal("original response missing")
			}
			expr, ok := fn.Body.List[i+1].(*ast.ExprStmt)
			if !ok {
				t.Fatal("missing server observation after original Do")
			}
			observe, ok := expr.X.(*ast.CallExpr)
			if !ok || len(observe.Args) != 2 {
				t.Fatal("missing server observation after original Do")
			}
			name, ok := observe.Fun.(*ast.Ident)
			if !ok || name.Name != "nodeLoadCaptureServer" {
				t.Fatal("missing server observation after original Do")
			}
			ctx, ok := observe.Args[0].(*ast.Ident)
			if !ok || ctx.Name != "ctx" {
				t.Fatal("not original actor context")
			}
			r, ok := observe.Args[1].(*ast.Ident)
			if !ok || r.Name != response.Name {
				t.Fatal("not original HTTP response")
			}
			got++
		}
	}
	if got != 1 {
		t.Fatal("missing/duplicated original HTTP observation", got)
	}
}
