// xandbox-doctor observes host prerequisites; it never installs or runs a VM.
package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/123123213weqw/Xandbox/internal/hostdoctor"
)

func run(args []string, out, errout io.Writer, collect func(context.Context) hostdoctor.Report) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		_, e := io.WriteString(out, "Usage: xandbox-doctor\nRead-only systemd-install-v1 prerequisite observations; exit 0 is not deployment or production readiness.\n")
		if e != nil {
			return 2
		}
		return 0
	}
	if len(args) != 0 {
		io.WriteString(errout, "xandbox-doctor: no paths, commands or installation arguments accepted\n")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r := collect(ctx)
	if json.NewEncoder(out).Encode(r) != nil {
		io.WriteString(errout, "xandbox-doctor: report output failed\n")
		return 2
	}
	if !r.BasicPrerequisitesMet {
		return 1
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, hostdoctor.Collect)) }
