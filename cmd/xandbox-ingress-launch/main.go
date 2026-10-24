package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/123123213weqw/Xandbox/internal/ingresslaunch"
)

func run(args []string, stderr io.Writer, start func(string) error) int {
	f := flag.NewFlagSet("xandbox-ingress-launch", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	path := f.String("manifest", "", "root-owned ingress launch manifest")
	if e := f.Parse(args); e != nil || len(args) != 2 || args[0] != "-manifest" || *path == "" || f.NArg() != 0 {
		fmt.Fprintln(stderr, "xandbox-ingress-launch: fixed manifest required; no fallback")
		return 1
	}
	if e := start(*path); e != nil {
		fmt.Fprintln(stderr, "xandbox-ingress-launch: preflight failed ("+ingresslaunch.FailureStage(e)+"); gateway not executed")
		return 1
	}
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stderr, ingresslaunch.Run)) }
