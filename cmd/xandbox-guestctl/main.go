// xandbox-guestctl is an experimental host-side vsock protocol diagnostic.
// It never executes guest commands on the host.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/123123213weqw/Xandbox/internal/guestbridge"
	"github.com/123123213weqw/Xandbox/internal/guestwire"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	socket := flag.String("vsock-socket", "", "private Firecracker vsock bridge path")
	id := flag.String("id", "", "expected instance ID")
	generation := flag.String("generation", "", "expected execution generation")
	timeout := flag.Duration("timeout", 5*time.Second, "guest command timeout")
	limit := flag.Int("output-bytes", 16_384, "total stdout/stderr bound")
	flag.Parse()
	args := flag.Args()
	if *socket == "" || len(args) < 1 {
		return fmt.Errorf("usage: xandbox-guestctl -vsock-socket PATH -id ID -generation GENERATION {health|exec COMMAND [ARGS...]}")
	}
	req := guestwire.Request{Version: guestwire.Version, Operation: args[0], Ref: sandbox.Ref{ID: *id, Generation: *generation}}
	if req.Operation == "exec" {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return err
		}
		req.ExecutionID = hex.EncodeToString(id[:])
		req.Argv = args[1:]
		req.TimeoutMS = int(timeout.Milliseconds())
		req.MaxOutputBytes = *limit
	} else if req.Operation != "health" || len(args) != 1 {
		return fmt.Errorf("invalid diagnostic operation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout+5*time.Second)
	defer cancel()
	response, err := guestbridge.Call(ctx, *socket, req)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
		return err
	}
	if response.Error != "" {
		return fmt.Errorf("guest returned %s", response.Status)
	}
	return nil
}
