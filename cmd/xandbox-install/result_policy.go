package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/installtxn"
)

type resultPolicyOperations struct {
	reconfigure func(context.Context, string, uint64, string) (installtxn.Result, error)
	reconcile   func(context.Context, string) (installtxn.Result, error)
}

// Explicit verbs; the old grammar and four bootstrap verbs stay unchanged.
func runWithResultPolicy(args []string, out, errout io.Writer, policy resultPolicyOperations, results resultOperations, old operations) int {
	if len(args) == 0 || args[0] != "reconfigure-results" && args[0] != "reconcile-results-policy" {
		return runWithResults(args, out, errout, results, old)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	validRequest := func(s string) bool {
		_, e := hex.DecodeString(s)
		return len(s) == 32 && strings.ToLower(s) == s && e == nil
	}
	var value installtxn.Result
	var e error
	switch {
	case len(args) == 7 && args[0] == "reconfigure-results" && args[1] == "-plan" && args[2] != "" && args[3] == "-expected-revision" && args[5] == "-request-id" && validRequest(args[6]) && policy.reconfigure != nil:
		revision, err := strconv.ParseUint(args[4], 10, 64)
		if err != nil || revision == 0 || revision == ^uint64(0) || strconv.FormatUint(revision, 10) != args[4] {
			io.WriteString(errout, "xandbox-install: fixed result-policy revision required\n")
			return 1
		}
		value, e = policy.reconfigure(ctx, args[2], revision, args[6])
	case len(args) == 3 && args[0] == "reconcile-results-policy" && args[1] == "-request-id" && validRequest(args[2]) && policy.reconcile != nil:
		value, e = policy.reconcile(ctx, args[2])
	default:
		io.WriteString(errout, "xandbox-install: fixed result-policy arguments required\n")
		return 1
	}
	if e != nil {
		io.WriteString(errout, "xandbox-install: result policy unconfirmed; preserve current state and exact request\n")
		return 1
	}
	if json.NewEncoder(out).Encode(value) != nil {
		return 1
	}
	return 0
}
