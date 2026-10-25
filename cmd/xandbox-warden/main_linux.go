//go:build linux

package main

import (
	"flag"
	"os"

	"github.com/123123213weqw/Xandbox/internal/warden"
)

func main() {
	cgroup := flag.String("cgroup", "", "internal generation cgroup")
	hardDeadline := flag.Int64("hard-deadline-ns", 0, "internal CLOCK_BOOTTIME hard deadline")
	denyQuota := flag.Bool("deny-quota-mutation", false, "internal: inherit project/quota mutation filter")
	flag.Parse()
	if err := warden.RunWithQuota(*cgroup, *hardDeadline, flag.Args(), *denyQuota); err != nil {
		// Run returns only fixed guard errors, never argv or tenant output.
		os.Stderr.WriteString("warden initialization failed: " + err.Error() + "\n")
		os.Exit(1)
	}
}
