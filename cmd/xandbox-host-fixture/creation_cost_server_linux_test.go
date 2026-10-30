//go:build linux && xandbox_host_fixture

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

func generatedCostServerHeader() string {
	parts := make([]string, 10)
	for i := range parts {
		parts[i] = nodeLoadServerNames[i] + `;dur=0.000;desc="n1"`
	}
	return strings.Join(parts, ", ")
}

func generatedCostServerResponse(values ...string) *http.Response {
	return &http.Response{Header: http.Header{"Server-Timing": values}}
}

func TestCreationCostServerCapturesOnlyClosedOrderedCompleteTenSpans(t *testing.T) {
	p := &creationCostTrace{scope: "cold"}
	if e := p.beginCreate(); e != nil {
		t.Fatal(e)
	}
	p.captureCreateServer(generatedCostServerResponse(generatedCostServerHeader()))
	if e := p.finishCreate(time.Millisecond, true); e != nil {
		t.Fatal(e)
	}
	if p.validateCreateServers() != nil || p.validateCreates("cold") != nil || p.creates[0].ServerTiming.Status != "observed" {
		t.Fatal("complete closed sample rejected", p.creates)
	}
	for i, entry := range p.creates[0].ServerTiming.Entries {
		if entry.Phase != nodeLoadServerNames[i] || entry.Calls != 1 || entry.MS != 0 {
			t.Fatal("wrong fixed span", entry)
		}
	}
}

func TestCreationCostServerUnknownIsNotZeroAndRawHeadersNeverRetained(t *testing.T) {
	good := generatedCostServerHeader()
	cases := []struct {
		response *http.Response
		status   string
	}{
		{nil, "no_response"}, {generatedCostServerResponse(), "missing"},
		{generatedCostServerResponse(""), "invalid"},
		{generatedCostServerResponse("synthetic-private-header-marker"), "invalid"},
		{generatedCostServerResponse(good, good), "invalid"},
		{generatedCostServerResponse(strings.Repeat("x", 2049)), "invalid"},
		{generatedCostServerResponse(strings.Join(strings.Split(good, ", ")[:9], ", ")), "invalid"},
		{generatedCostServerResponse(good + `, xa_session_intent_commit;dur=0.000;desc="n1"`), "invalid"},
	}
	for _, tc := range cases {
		p := &creationCostTrace{scope: "cold"}
		if e := p.beginCreate(); e != nil {
			t.Fatal(e)
		}
		p.captureCreateServer(tc.response)
		if e := p.finishCreate(time.Millisecond, true); e != nil {
			t.Fatal(e)
		}
		v := p.creates[0].ServerTiming
		if v.Status != tc.status || v.Entries == nil || len(v.Entries) != 0 || p.validateCreateServers() == nil || !p.creates[0].Success {
			t.Fatal("unknown relabeled as zero/failed original API", v)
		}
		b, e := json.Marshal(p.creates)
		if e != nil || bytes.Contains(b, []byte("synthetic-private-header-marker")) || bytes.Contains(b, []byte("Server-Timing")) {
			t.Fatal("raw header entered observation")
		}
	}
	p := &creationCostTrace{scope: "cold"}
	_ = p.beginCreate()
	_ = p.finishCreate(time.Millisecond, true)
	if p.creates[0].ServerTiming.Status != "not_observed" || p.validateCreateServers() == nil {
		t.Fatal("uncalled observer silently accepted")
	}
}

func TestCreationCostServerDuplicateOrOutOfFlightCannotBeHidden(t *testing.T) {
	for _, duplicate := range []bool{true, false} {
		p := &creationCostTrace{scope: "cold"}
		if duplicate {
			_ = p.beginCreate()
			p.captureCreateServer(generatedCostServerResponse(generatedCostServerHeader()))
		}
		p.captureCreateServer(generatedCostServerResponse(generatedCostServerHeader()))
		if !p.serverObservationInvalid || p.validateCreateServers() == nil {
			t.Fatal("invalid capture accepted")
		}
	}
	var disabled *creationCostTrace
	disabled.captureCreateServer(generatedCostServerResponse("unused"))
}

func TestCreationCostServerCallKeepsOriginalContextResultErrorAndOneRequest(t *testing.T) {
	for _, mode := range []string{"off", "good", "bad-header", "transport", "status", "body"} {
		t.Run(mode, func(t *testing.T) {
			p := &creationCostTrace{scope: "cold"}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			calls := 0
			sentinel := errors.New("generated transport sentinel")
			c := &switchAPI{costProbe: p, http: &http.Client{Transport: switchTestTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Context() != ctx || req.Method != "POST" || req.URL.Path != "/v1/sandboxes" || req.Header.Get("Server-Timing") != "" {
					t.Fatal("original request/context changed")
				}
				if mode == "transport" {
					return nil, sentinel
				}
				r := generatedCostServerResponse(generatedCostServerHeader())
				r.StatusCode = 201
				r.Body = io.NopCloser(strings.NewReader(`{"state":"READY","backend":"firecracker"}`))
				if mode == "off" || mode == "bad-header" {
					r.Header.Set("Server-Timing", "synthetic-private-header-marker")
				}
				if mode == "status" {
					r.StatusCode = 503
				}
				if mode == "body" {
					r.Body = io.NopCloser(strings.NewReader("not-json"))
				}
				return r, nil
			})}}
			if mode == "off" {
				c.costProbe = nil
			}
			r, e := c.create(ctx, "generated-unit-key")
			wantSuccess := mode == "off" || mode == "good" || mode == "bad-header"
			if calls != 1 || (e == nil) != wantSuccess || (wantSuccess && r.State != "READY") || (mode == "transport" && !errors.Is(e, sentinel)) {
				t.Fatal("API result/error changed", calls, r.State, e)
			}
			if mode == "status" {
				var status *switchHTTPStatusError
				if !errors.As(e, &status) || status.Got != 503 || status.Want != 201 {
					t.Fatal("original status error masked", e)
				}
			}
			if mode == "off" {
				if len(p.creates) != 0 || p.createInFlight || p.serverObservationInvalid {
					t.Fatal("OFF captured a response")
				}
			} else if len(p.creates) != 1 || p.creates[0].Success != wantSuccess || p.creates[0].ElapsedNS <= 0 {
				t.Fatal("original success/failure observation lost")
			}
		})
	}
}

func TestCreationCostServerArithmeticChecksRoundingNotCriticalPath(t *testing.T) {
	p := &creationCostTrace{scope: "cold"}
	_ = p.beginCreate()
	p.captureCreateServer(generatedCostServerResponse(generatedCostServerHeader()))
	entries := p.createServer.Entries
	entries[2].MS = 3
	entries[4].MS = 3.006 // Six rounded child spans can sum slightly above parent.
	if !costCreateServerFits(entries, int64(3*time.Millisecond)) {
		t.Fatal("header rounding falsely rejected")
	}
	for _, bad := range []float64{-1, math.NaN(), math.Inf(1), 35001.001} {
		entries[4].MS = bad
		if costCreateServerFits(entries, int64(time.Second)) {
			t.Fatal("invalid entry accepted", bad)
		}
	}
	entries[4].MS = 3.011
	if costCreateServerFits(entries, int64(time.Second)) {
		t.Fatal("impossible nesting accepted")
	}
	entries[4].MS = 0
	if costCreateServerFits(entries, int64(time.Millisecond)) {
		t.Fatal("server parent larger than client envelope accepted")
	}
}

func TestCreationCostServerFailedAllFiveObservationsWithinOriginalBound(t *testing.T) {
	p := &creationCostTrace{scope: "checkpoint", ordinaryELF: prepareTraceELFSHA}
	for i := 0; i < 5; i++ {
		_ = p.beginCreate()
		p.captureCreateServer(generatedCostServerResponse(generatedCostServerHeader()))
		for j := range p.createServer.Entries {
			p.createServer.Entries[j].MS = 1234.567
		}
		_ = p.finishCreate(time.Second, i != 4)
	}
	payload, e := p.failedCreatePayload()
	if e != nil {
		t.Fatal("failure observation absent", e)
	}
	var report struct {
		Schema  int                 `json:"schema"`
		Valid   bool                `json:"valid_comparison"`
		Creates []costCreateElapsed `json:"http_create_elapsed"`
	}
	if len(payload) <= 2048 || len(payload) > 4096 || json.Unmarshal(payload, &report) != nil || report.Schema != 2 || report.Valid || len(report.Creates) != 5 || report.Creates[4].Success {
		t.Fatal("complete five-sample failure payload absent, overflowed, or reclassified")
	}
	t.Logf("GENERATED_FIVE_FAILURE_VECTOR_BYTES %d; original4096_bound_retained", len(payload))
}

func TestCreationCostServerWiredAtOriginalDoWithNilGateFirst(t *testing.T) {
	fset := token.NewFileSet()
	file, e := parser.ParseFile(fset, "quota_switch_linux.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	found := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "call" {
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
			if i+1 >= len(fn.Body.List) {
				t.Fatal("response observation missing")
			}
			var code bytes.Buffer
			if format.Node(&code, fset, fn.Body.List[i+1]) != nil || code.String() != "if p := c.costProbe; p != nil && p.createInFlight && method == \"POST\" && path == \"/v1/sandboxes\" {\n\tp.captureCreateServer(r)\n}" {
				t.Fatal("OFF/fixed original response gate changed", code.String())
			}
			found++
		}
	}
	if found != 1 {
		t.Fatal("missing or duplicated original response observation", found)
	}
}

func TestCreationCostServerUnmeasuredRefusalsKeepOriginalChecksAndNoObservation(t *testing.T) {
	// The original full protocol also POSTs N+1/pressure/replay refusals through
	// call(), not create(). An endpoint-only observer incorrectly poisoned the
	// diagnostic. Model that old callback separately, never as old runtime data.
	oldModel := &creationCostTrace{scope: "cold"}
	oldModel.captureCreateServer(generatedCostServerResponse("not-selected"))
	if !oldModel.serverObservationInvalid {
		t.Fatal("generated old out-of-flight counterexample disappeared")
	}
	p := &creationCostTrace{scope: "cold"}
	calls, status := 0, 503
	ctx := context.Background()
	c := &switchAPI{costProbe: p, http: &http.Client{Transport: switchTestTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Context() != ctx {
			t.Fatal("original context replaced")
		}
		r := generatedCostServerResponse("synthetic-unselected-header")
		r.StatusCode = status
		r.Body = io.NopCloser(strings.NewReader(`{"state":"READY","backend":"firecracker"}`))
		if status == 201 {
			r.Header.Set("Server-Timing", generatedCostServerHeader())
		}
		return r, nil
	})}}
	refusals := func() {
		for _, expected := range []int{503, 500, 410} {
			status = expected
			if e := c.call(ctx, "POST", "/v1/sandboxes", "generated-fixed-key", nodeSpec(), nil, expected); e != nil {
				t.Fatal("original refusal check changed", expected, e)
			}
			if p.serverObservationInvalid || p.createInFlight {
				t.Fatal("unmeasured refusal entered create observer")
			}
		}
	}
	refusals()
	if len(p.creates) != 0 {
		t.Fatal("unmeasured refusal invented a create sample")
	}
	status = 201
	if _, e := c.create(ctx, "generated-measured-key"); e != nil {
		t.Fatal(e)
	}
	refusals()
	if calls != 7 || len(p.creates) != 1 || p.validateCreateServers() != nil {
		t.Fatal("measured create or original call inventory changed", calls, p.creates)
	}
}
