// Package guestbridge connects only to a Firecracker vsock Unix bridge.
package guestbridge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/guestwire"
)

var initializationPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

var bootPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func Call(ctx context.Context, socket string, request guestwire.Request) (guestwire.Response, error) {
	var response guestwire.Response
	if !request.Valid() {
		return response, errors.New("invalid guest request")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return response, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline := time.Now().Add(65 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return response, err
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %d\n", guestwire.Port); err != nil {
		return response, err
	}
	reader := bufio.NewReaderSize(conn, 64)
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > 32 {
		return response, errors.New("invalid vsock bridge acknowledgement")
	}
	parts := strings.Split(strings.TrimSuffix(string(line), "\n"), " ")
	if len(parts) != 2 || parts[0] != "OK" {
		return response, errors.New("vsock bridge connection rejected")
	}
	if port, err := strconv.ParseUint(parts[1], 10, 32); err != nil || port == 0 {
		return response, errors.New("invalid vsock bridge port")
	}
	if err := guestwire.Write(conn, guestwire.MaxRequest, request); err != nil {
		return response, err
	}
	if err := guestwire.Read(reader, guestwire.MaxResponse, &response); err != nil {
		return response, err
	}
	if response.InitializationHash != "" && !initializationPattern.MatchString(response.InitializationHash) {
		return guestwire.Response{}, errors.New("invalid guest initialization epoch")
	}
	if response.Version != guestwire.Version || response.Ref != request.Ref || response.ExecutionID != request.ExecutionID || !bootPattern.MatchString(response.BootID) {
		return guestwire.Response{}, errors.New("guest response identity mismatch")
	}
	if response.Status != "READY" && response.Status != "EXITED" && response.Status != "TIMED_OUT" && response.Status != "CANCELLED" && response.Status != "FAILED" {
		return guestwire.Response{}, errors.New("invalid guest response status")
	}
	if request.Operation == "health" && response.Status != "READY" {
		return response, errors.New("guest not ready")
	}
	if ((response.Status == "READY" || response.Status == "EXITED") && response.Error != "") || ((response.Status == "FAILED" || response.Status == "TIMED_OUT" || response.Status == "CANCELLED") && response.Error == "") {
		return guestwire.Response{}, errors.New("inconsistent guest response")
	}
	if request.Operation == "exec" && (response.Status == "READY" || len(response.Output.Stdout)+len(response.Output.Stderr) > request.MaxOutputBytes) {
		return guestwire.Response{}, errors.New("invalid guest execution result")
	}
	return response, nil
}
