// xandbox-install reconciles only a fixed root initial-install composition.
// There is no task argv, shell, service selection or host execution fallback.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/installtxn"
)

type operations struct {
	replacePending func(context.Context, string, uint64, string, string) (installtxn.Result, error)
	recoverPolicy  func(context.Context, string, uint64, string, string) (installtxn.Result, error)
	apply          func(context.Context, string, uint64, string) (installtxn.Result, error)
	reconcile      func(context.Context, string) (installtxn.Result, error)
	status         func(context.Context) (installtxn.Result, error)
	verify         func(context.Context) error
	reconfigure    func(context.Context, string, uint64, string) (installtxn.Result, error)
}

func run(args []string, out, errout io.Writer, op operations) int {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var v installtxn.Result
	var e error
	silent := false
	switch {
	case len(args) == 7 && args[0] == "apply" && args[1] == "-plan" && args[2] != "" && args[3] == "-expected-revision" && args[4] == "0" && args[5] == "-request-id":
		v, e = op.apply(ctx, args[2], 0, args[6])
	case len(args) == 7 && args[0] == "reconfigure" && args[1] == "-plan" && args[2] != "" && args[3] == "-expected-revision" && args[5] == "-request-id":
		expected, err := strconv.ParseUint(args[4], 10, 64)
		if err != nil || expected == 0 || expected == ^uint64(0) || strconv.FormatUint(expected, 10) != args[4] || op.reconfigure == nil {
			io.WriteString(errout, "xandbox-install: fixed reconfiguration arguments required\n")
			return 1
		}
		v, e = op.reconfigure(ctx, args[2], expected, args[6])
	case len(args) == 9 && args[0] == "recover-policy" && args[1] == "-plan" && args[2] != "" && args[3] == "-expected-revision" && args[5] == "-request-id" && args[7] == "-supersedes-request-id":
		expected, err := strconv.ParseUint(args[4], 10, 64)
		requestOK := func(v string) bool {
			_, e := hex.DecodeString(v)
			return len(v) == 32 && strings.ToLower(v) == v && e == nil
		}
		if err != nil || expected < 2 || expected == ^uint64(0) || strconv.FormatUint(expected, 10) != args[4] || !requestOK(args[6]) || !requestOK(args[8]) || args[6] == args[8] || op.recoverPolicy == nil {
			io.WriteString(errout, "xandbox-install: fixed policy recovery arguments required\n")
			return 1
		}
		v, e = op.recoverPolicy(ctx, args[2], expected, args[6], args[8])
	case len(args) == 9 && args[0] == "replace-pending-policy" && args[1] == "-plan" && args[2] != "" && args[3] == "-expected-revision" && args[5] == "-request-id" && args[7] == "-replaces-request-id":
		expected, err := strconv.ParseUint(args[4], 10, 64)
		requestOK := func(v string) bool {
			_, e := hex.DecodeString(v)
			return len(v) == 32 && strings.ToLower(v) == v && e == nil
		}
		if err != nil || expected == 0 || expected == ^uint64(0) || strconv.FormatUint(expected, 10) != args[4] || !requestOK(args[6]) || !requestOK(args[8]) || args[6] == args[8] || op.replacePending == nil {
			io.WriteString(errout, "xandbox-install: fixed pending replacement arguments required\n")
			return 1
		}
		v, e = op.replacePending(ctx, args[2], expected, args[6], args[8])
	case len(args) == 3 && args[0] == "reconcile" && args[1] == "-request-id":
		v, e = op.reconcile(ctx, args[2])
	case len(args) == 1 && args[0] == "status":
		v, e = op.status(ctx)
	case len(args) == 1 && args[0] == "verify":
		e = op.verify(ctx)
		silent = true
	default:
		io.WriteString(errout, "xandbox-install: fixed initial-install arguments required\n")
		return 1
	}
	if e != nil {
		io.WriteString(errout, "xandbox-install: installation unconfirmed; preserve the exact request and inspect before reconcile\n")
		return 1
	}
	if !silent && json.NewEncoder(out).Encode(v) != nil {
		return 1
	}
	return 0
}
func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, operations{replacePending: installtxn.ReplacePendingPolicy, apply: installtxn.Apply, reconcile: installtxn.Reconcile, status: installtxn.Status, verify: installtxn.Verify, reconfigure: installtxn.Reconfigure, recoverPolicy: installtxn.RecoverPolicy}))
}
