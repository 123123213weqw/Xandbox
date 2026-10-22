//go:build linux

package main

import (
	"flag"
	"os"

	"github.com/123123213weqw/Xandbox/internal/warden"
)

func main() {
	cgroup := flag.String("cgroup", "", "internal generation cgroup")
	flag.Parse()
	if err := warden.Run(*cgroup, flag.Args()); err != nil {
		// Run returns only fixed guard errors, never argv or tenant output.
		os.Stderr.WriteString("warden initialization failed: " + err.Error() + "\n")
		os.Exit(1)
	}
}
