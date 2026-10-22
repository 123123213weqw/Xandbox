// Package guest implements the guest-only execution service. The real executor
// requires guest boot attestation checks and is never a host-side backend.
package guest

import (
	"context"
	"net"
	"time"

	"github.com/123123213weqw/Xandbox/internal/guestwire"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

type Runner interface {
	Run(context.Context, guestwire.Request) (sandbox.Output, error)
}

type Server struct {
	Ref    sandbox.Ref
	BootID string
	Runner Runner
}

// ServeConn serves exactly one bounded call. peerIsHost must come from the
// accepted AF_VSOCK sockaddr, never from any field controlled by a request.
func (s *Server) ServeConn(conn net.Conn, peerIsHost bool) {
	defer conn.Close()
	if !peerIsHost || s.Runner == nil {
		return
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	var req guestwire.Request
	if err := guestwire.Read(conn, guestwire.MaxRequest, &req); err != nil || !req.Valid() || req.Ref != s.Ref {
		return
	}
	response := guestwire.Response{Version: guestwire.Version, Ref: s.Ref, ExecutionID: req.ExecutionID, BootID: s.BootID, Status: "READY"}
	if readiness, ok := s.Runner.(interface{ Ready() bool }); ok && !readiness.Ready() {
		response.Status = "FAILED"
		response.Error = "guest executor fenced"
		guestwire.Write(conn, guestwire.MaxResponse, response)
		return
	}
	if req.Operation == "health" {
		if observer, ok := s.Runner.(interface{ ActiveGroups() (int, error) }); ok {
			groups, err := observer.ActiveGroups()
			if err != nil {
				response.Status = "FAILED"
				response.Error = "guest execution state unavailable"
			} else {
				response.ActiveGroups = &groups
			}
		}
	}
	if req.Operation == "exec" {
		if err := conn.SetDeadline(time.Now().Add(time.Duration(req.TimeoutMS)*time.Millisecond + 5*time.Second)); err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.TimeoutMS)*time.Millisecond)
		defer cancel()
		// EOF (including a dead host controller) cancels the entire execution
		// cgroup. Extra bytes are also a protocol violation and cancel the call.
		done := make(chan struct{})
		go func() { defer close(done); var b [1]byte; conn.Read(b[:]); cancel() }()
		out, err := s.Runner.Run(ctx, req)
		response.Output = out
		response.Status = "EXITED"
		if err != nil {
			response.Output.ExitCode = -1
			response.Error = "guest execution failed"
			response.Status = "FAILED"
			if ctx.Err() == context.DeadlineExceeded {
				response.Status = "TIMED_OUT"
				response.Error = "execution deadline exceeded"
			} else if ctx.Err() != nil {
				response.Status = "CANCELLED"
				response.Error = "execution cancelled"
			}
		}
		guestwire.Write(conn, guestwire.MaxResponse, response)
		conn.Close()
		<-done
		return
	}
	guestwire.Write(conn, guestwire.MaxResponse, response)
}
