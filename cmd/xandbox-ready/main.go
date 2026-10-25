package main

import (
	"flag"
	"fmt"
	"github.com/123123213weqw/Xandbox/internal/serviceready"
	"io"
	"os"
)

func run(args []string, stderr io.Writer, start func(string) error) int {
	f := flag.NewFlagSet("xandbox-ready", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	p := f.String("manifest", "", "fixed root-owned readiness manifest")
	if e := f.Parse(args); e != nil || len(args) != 2 || args[0] != "-manifest" || *p == "" || f.NArg() != 0 {
		fmt.Fprintln(stderr, "xandbox-ready: fixed manifest required; no fallback")
		return 1
	}
	if e := start(*p); e != nil {
		fmt.Fprintln(stderr, "xandbox-ready: failed ("+serviceready.FailureStage(e)+"); ingress remains ordered behind startup")
		return 1
	}
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stderr, serviceready.Run)) }
