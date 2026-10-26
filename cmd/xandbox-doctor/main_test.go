package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/hostdoctor"
)

func TestNoCallerPathsCommandsOrMutationFlags(t *testing.T) {
	calls := 0
	collect := func(context.Context) hostdoctor.Report { calls++; return hostdoctor.Report{} }
	for _, args := range [][]string{{"--install"}, {"-root", "/private/SECRET"}, {"--systemd", "9999"}, {"sh", "-c", "secret"}, {"--force"}, {"-h", "extra"}} {
		var out, errout bytes.Buffer
		if run(args, &out, &errout, collect) != 2 || calls != 0 || out.Len() != 0 || strings.Contains(errout.String(), "SECRET") || strings.Contains(errout.String(), "secret") {
			t.Fatal("caller selection reached observer or leaked")
		}
	}
	for _, arg := range []string{"-h", "--help"} {
		var out, errout bytes.Buffer
		if run([]string{arg}, &out, &errout, collect) != 0 || calls != 0 || errout.Len() != 0 || !strings.Contains(out.String(), "not deployment") {
			t.Fatal("help ran a probe or lost the readiness boundary")
		}
	}
}

func TestJSONAndExitStatusDoNotHideMissingPrerequisites(t *testing.T) {
	for _, met := range []bool{false, true} {
		var out, errout bytes.Buffer
		code := run(nil, &out, &errout, func(ctx context.Context) hostdoctor.Report {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("query context is unbounded")
			}
			return hostdoctor.Report{Version: 1, BasicPrerequisitesMet: met, ReadOnly: true}
		})
		if (code == 0) != met || errout.Len() != 0 || !strings.Contains(out.String(), `"production_ready":false`) || !strings.Contains(out.String(), `"isolation_validated":false`) {
			t.Fatal("report exit code or maturity changed")
		}
	}
}

type brokenOutput struct{}

func (brokenOutput) Write([]byte) (int, error) { return 0, errors.New("PRIVATE_OUTPUT_PATH") }

func TestOutputFailureIsClosedAndNonzero(t *testing.T) {
	var errout bytes.Buffer
	if run(nil, brokenOutput{}, &errout, func(context.Context) hostdoctor.Report { return hostdoctor.Report{} }) != 2 || strings.Contains(errout.String(), "PRIVATE") {
		t.Fatal("output failure swallowed or raw error leaked")
	}
}
