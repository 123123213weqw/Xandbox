package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/123123213weqw/Xandbox/internal/launch"
)

func main() {
	f := flag.NewFlagSet("xandbox-launch", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	path := f.String("manifest", "", "root-owned immutable launch manifest")
	if e := f.Parse(os.Args[1:]); e != nil || *path == "" || f.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "xandbox-launch: fixed manifest required; no fallback")
		os.Exit(1)
	}
	if e := launch.Run(*path); e != nil {
		fmt.Fprintln(os.Stderr, "xandbox-launch: preflight failed ("+launch.FailureStage(e)+"); daemon not executed")
		os.Exit(1)
	}
}
