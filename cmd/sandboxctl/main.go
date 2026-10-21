package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/123123213weqw/Xandbox/internal/client"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	global := flag.NewFlagSet("sandboxctl", flag.ContinueOnError)
	socket := global.String("socket", "", "sandboxd Unix socket (required)")
	deadline := global.Duration("deadline", 10*time.Second, "overall client deadline")
	if err := global.Parse(os.Args[1:]); err != nil {
		return err
	}
	args := global.Args()
	if *socket == "" || len(args) == 0 {
		return fmt.Errorf("usage: sandboxctl -socket PATH {health|create|exec|job|get|stop|destroy} [options]")
	}
	c := client.New(*socket)
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *deadline)
	defer cancel()
	var result any
	var err error
	switch args[0] {
	case "health":
		err = c.Do(ctx, http.MethodGet, "/healthz", nil, &result)
	case "create":
		flags := flag.NewFlagSet("create", flag.ContinueOnError)
		ttl := flags.Duration("ttl", 5*time.Minute, "instance lifetime")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("usage: create [-ttl 5m]")
		}
		err = c.Do(ctx, http.MethodPost, "/v1/sandboxes", sandbox.CreateRequest{TTLMS: int(ttl.Milliseconds())}, &result)
	case "get":
		if len(args) != 2 {
			return fmt.Errorf("usage: get ID")
		}
		err = c.Do(ctx, http.MethodGet, "/v1/sandboxes/"+args[1], nil, &result)
	case "exec":
		flags := flag.NewFlagSet("exec", flag.ContinueOnError)
		timeout := flags.Duration("timeout", 5*time.Second, "command timeout, <= instance policy")
		wait := flags.Bool("wait", false, "poll until execution finishes")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		pos := flags.Args()
		if len(pos) < 3 {
			return fmt.Errorf("usage: exec [-wait] [-timeout 5s] ID GENERATION COMMAND [ARGS...]")
		}
		var job sandbox.Job
		err = c.Do(ctx, http.MethodPost, "/v1/sandboxes/"+pos[0]+"/exec", sandbox.ExecRequest{
			Generation: pos[1], Argv: pos[2:], TimeoutMS: int(timeout.Milliseconds()),
		}, &job)
		for err == nil && *wait && job.Status == "RUNNING" {
			if err = pause(ctx); err == nil {
				err = c.Do(ctx, http.MethodGet, "/v1/sandboxes/"+pos[0]+"/executions/"+job.ID, nil, &job)
			}
		}
		result = job
	case "job":
		if len(args) != 3 {
			return fmt.Errorf("usage: job ID EXECUTION_ID")
		}
		err = c.Do(ctx, http.MethodGet, "/v1/sandboxes/"+args[1]+"/executions/"+args[2], nil, &result)
	case "stop", "destroy":
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		wait := flags.Bool("wait", false, "for destroy: wait until resources are reclaimed")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		pos := flags.Args()
		if len(pos) != 2 {
			return fmt.Errorf("usage: %s [-wait] ID GENERATION", args[0])
		}
		method, path := http.MethodDelete, "/v1/sandboxes/"+pos[0]
		if args[0] == "stop" {
			method, path = http.MethodPost, path+"/stop"
		}
		var record sandbox.Record
		err = c.Do(ctx, method, path, map[string]string{"generation": pos[1]}, &record)
		for err == nil && args[0] == "destroy" && *wait && record.State != sandbox.Destroyed {
			if err = pause(ctx); err == nil {
				err = c.Do(ctx, http.MethodGet, "/v1/sandboxes/"+pos[0], nil, &record)
			}
		}
		result = record
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func pause(ctx context.Context) error {
	timer := time.NewTimer(20 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
