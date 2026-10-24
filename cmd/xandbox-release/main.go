// xandbox-release publishes immutable artifacts; it does not install, execute,
// enable, restart, resume or garbage-collect a running node or service.
package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/123123213weqw/Xandbox/internal/releasestore"
)

type publisher func(context.Context, string, uint64, string) (releasestore.Result, error)

func run(args []string, out, errout io.Writer, publish publisher, status func(context.Context) (releasestore.Result, error)) int {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var v releasestore.Result
	var err error
	if len(args) == 1 && args[0] == "status" {
		v, err = status(ctx)
	} else if len(args) == 7 && args[0] == "publish" && args[1] == "-manifest" && args[2] != "" && args[3] == "-expected-revision" && args[5] == "-request-id" {
		n, e := strconv.ParseUint(args[4], 10, 64)
		if e != nil || strconv.FormatUint(n, 10) != args[4] {
			io.WriteString(errout, "xandbox-release: fixed arguments required\n")
			return 1
		}
		v, err = publish(ctx, args[2], n, args[6])
	} else {
		io.WriteString(errout, "xandbox-release: fixed arguments required\n")
		return 1
	}
	if err != nil {
		io.WriteString(errout, "xandbox-release: publication unconfirmed; preserve inputs and retry the identical request\n")
		return 1
	}
	if json.NewEncoder(out).Encode(v) != nil {
		return 1
	}
	return 0
}
func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, releasestore.Publish, releasestore.Status))
}
