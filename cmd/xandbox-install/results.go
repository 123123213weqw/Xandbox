package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/123123213weqw/Xandbox/internal/installtxn"
	"io"
	"strings"
	"time"
)

type resultOperations struct {
	apply     func(context.Context, string, uint64, string) (installtxn.Result, error)
	reconcile func(context.Context, string) (installtxn.Result, error)
	status    func(context.Context) (installtxn.Result, error)
	verify    func(context.Context) error
}

func runWithResults(args []string, out, errout io.Writer, results resultOperations, old operations) int {
	if len(args) == 0 || args[0] != "apply-results" && args[0] != "reconcile-results" && args[0] != "status-results" && args[0] != "verify-results" {
		return run(args, out, errout, old)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	validRequest := func(s string) bool {
		_, e := hex.DecodeString(s)
		return len(s) == 32 && strings.ToLower(s) == s && e == nil
	}
	var value installtxn.Result
	var e error
	silent := false
	switch {
	case len(args) == 7 && args[0] == "apply-results" && args[1] == "-plan" && args[2] != "" && args[3] == "-expected-revision" && args[4] == "0" && args[5] == "-request-id" && validRequest(args[6]) && results.apply != nil:
		value, e = results.apply(ctx, args[2], 0, args[6])
	case len(args) == 3 && args[0] == "reconcile-results" && args[1] == "-request-id" && validRequest(args[2]) && results.reconcile != nil:
		value, e = results.reconcile(ctx, args[2])
	case len(args) == 1 && args[0] == "status-results" && results.status != nil:
		value, e = results.status(ctx)
	case len(args) == 1 && args[0] == "verify-results" && results.verify != nil:
		silent = true
		e = results.verify(ctx)
	default:
		io.WriteString(errout, "xandbox-install: fixed result-bootstrap arguments required\n")
		return 1
	}
	if e != nil {
		io.WriteString(errout, "xandbox-install: result bootstrap unconfirmed; preserve exact request and installed state\n")
		return 1
	}
	if !silent && json.NewEncoder(out).Encode(value) != nil {
		return 1
	}
	return 0
}
