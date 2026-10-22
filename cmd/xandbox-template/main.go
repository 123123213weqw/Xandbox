// xandbox-template is a node-root offline-template catalog administration tool.
// It never accepts task argv or executes guest code on the host.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"os"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	state := flag.String("state-dir", "", "bound node state directory")
	cfg := flag.String("config", "", "bound snapshot-mode Firecracker config")
	manifest := flag.String("manifest", "", "private trusted builder manifest")
	memory := flag.String("memory", "", "sealed builder memory snapshot")
	snapshot := flag.String("snapshot-state", "", "sealed builder VMM state")
	timeout := flag.Duration("timeout", 2*time.Minute, "bounded administrative operation timeout")
	flag.Parse()
	a := flag.Args()
	if len(a) == 1 && a[0] == "host-abi" {
		v, e := firecracker.SnapshotHostABI()
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"host_abi": v})
	}
	if *state == "" || *cfg == "" || len(a) < 1 || *timeout <= 0 || *timeout > 10*time.Minute {
		return errors.New("usage: xandbox-template -state-dir PATH -config PATH {status|publish|activate ID|retire ID|gc}; host-abi needs no config")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c, e := firecracker.OpenSnapshotCatalogContext(ctx, *state, *cfg)
	if e != nil {
		return e
	}
	var out any
	switch a[0] {
	case "status":
		if len(a) != 1 {
			return errors.New("status takes no identifier")
		}
		out, e = c.Status(ctx)
	case "publish":
		if len(a) != 1 || *manifest == "" || *memory == "" || *snapshot == "" {
			return errors.New("publish requires manifest, memory and snapshot-state, no identifier")
		}
		var id string
		id, e = c.Publish(ctx, *manifest, *memory, *snapshot)
		out = map[string]string{"template_id": id}
	case "activate", "retire":
		if len(a) != 2 {
			return errors.New("activate/retire requires exact template ID")
		}
		if a[0] == "activate" {
			e = c.Activate(ctx, a[1])
		} else {
			e = c.Retire(ctx, a[1])
		}
		out = map[string]bool{"accepted": e == nil}
	case "gc":
		if len(a) != 1 {
			return errors.New("gc takes no identifier")
		}
		var removed []string
		removed, e = c.Collect(ctx)
		out = map[string]any{"removed": removed}
	default:
		return errors.New("invalid catalog operation")
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}
