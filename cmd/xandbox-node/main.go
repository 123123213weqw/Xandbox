// xandbox-node is a same-host-UID operator client. It never accepts a tenant
// bearer token, TCP endpoint, guest argv, or an arbitrary API path.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
)

func main() {
	if e := run(os.Args[1:], os.Stdout, os.Stderr); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(args []string, out, diagnostic io.Writer) error {
	f := flag.NewFlagSet("xandbox-node", flag.ContinueOnError)
	f.SetOutput(diagnostic)
	dir := f.String("state-dir", "", "existing private daemon state directory")
	epoch := f.String("epoch", "", "epoch from status; required for mutations")
	revision := f.Uint64("revision", 0, "expected committed revision from status")
	id := f.String("request-id", "", "32hex command ID; retain for exact retry; generated if omitted")
	timeout := f.Duration("timeout", 5*time.Second, "local RPC wait; timeout does NOT undo an accepted mutation")
	if e := f.Parse(args); e != nil {
		return e
	}
	if *dir == "" || f.NArg() != 1 || *timeout <= 0 || *timeout > time.Minute {
		return errors.New("usage: xandbox-node -state-dir DIR [-epoch E -revision R -request-id ID] status|drain|resume")
	}
	op := f.Arg(0)
	if op != "status" && op != "drain" && op != "resume" {
		return errors.New("unknown fixed operator command")
	}
	if op == "status" && (*epoch != "" || *revision != 0 || *id != "") {
		return errors.New("status accepts no mutation fields")
	}
	var command nodecontrol.Command
	if op != "status" {
		if *id == "" {
			v, e := nodecontrol.NewRequestID()
			if e != nil {
				return e
			}
			*id = v
		}
		command = nodecontrol.Command{Version: 1, Epoch: *epoch, ExpectedRevision: *revision, RequestID: *id}
		if !command.Valid() {
			return errors.New("mutation requires a valid status epoch, positive revision and32hex request ID")
		}
	}
	c, e := nodecontrol.NewClient(*dir)
	if e != nil {
		return e
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	var reply nodecontrol.Reply
	if op == "status" {
		reply, e = c.Status(ctx)
	} else {
		// Command identifiers are not credentials. Save this private diagnostic
		// before sending: an EOF/timeout leaves the outcome ambiguous.
		fmt.Fprintf(diagnostic, "operator request_id=%s epoch=%s expected_revision=%d\n", command.RequestID, command.Epoch, command.ExpectedRevision)
		mode := nodecontrol.ModeDrained
		if op == "resume" {
			mode = nodecontrol.ModeOpen
		}
		reply, e = c.Change(ctx, mode, command)
	}
	if e != nil {
		return e
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(reply)
}
