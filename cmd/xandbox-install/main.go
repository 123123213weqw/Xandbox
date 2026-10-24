// xandbox-install reconciles only a fixed root initial-install composition.
// There is no task argv, shell, service selection or host execution fallback.
package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/123123213weqw/Xandbox/internal/installtxn"
)

type operations struct {
	apply     func(context.Context, string, uint64, string) (installtxn.Result, error)
	reconcile func(context.Context, string) (installtxn.Result, error)
	status    func(context.Context) (installtxn.Result, error)
	verify    func(context.Context) error
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
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, operations{installtxn.Apply, installtxn.Reconcile, installtxn.Status, installtxn.Verify}))
}
