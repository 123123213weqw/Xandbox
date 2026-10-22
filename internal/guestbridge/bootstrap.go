package guestbridge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/guestinit"
	"github.com/123123213weqw/Xandbox/internal/guestwire"
)

// Bootstrap reaches only the separate pristine guest port. CLAIMED does not
// permit Exec; caller must await normal health with matching Ref/epoch/BootID.
func Bootstrap(ctx context.Context, socket string, req guestinit.Request) (guestinit.Response, error) {
	var out guestinit.Response
	if !req.Valid() {
		return out, errors.New("invalid pristine initialization request")
	}
	c, e := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if e != nil {
		return out, e
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if e = c.SetDeadline(deadline); e != nil {
		return out, e
	}
	if _, e = fmt.Fprintf(c, "CONNECT %d\n", guestinit.Port); e != nil {
		return out, e
	}
	reader := bufio.NewReaderSize(c, 64)
	line, e := reader.ReadSlice('\n')
	if e != nil || len(line) > 32 {
		return out, errors.New("invalid bootstrap bridge acknowledgement")
	}
	parts := strings.Split(strings.TrimSuffix(string(line), "\n"), " ")
	if len(parts) != 2 || parts[0] != "OK" {
		return out, errors.New("bootstrap bridge rejected")
	}
	if n, e := strconv.ParseUint(parts[1], 10, 32); e != nil || n == 0 {
		return out, errors.New("invalid bootstrap bridge port")
	}
	if e = guestwire.Write(c, guestinit.MaxRequest, req); e != nil {
		return out, e
	}
	if e = guestwire.Read(reader, guestinit.MaxResponse, &out); e != nil {
		return out, e
	}
	if !out.Valid() {
		return guestinit.Response{}, errors.New("invalid bootstrap response")
	}
	if req.Operation == "initialize" && out.Digest != req.Digest() {
		return guestinit.Response{}, errors.New("initialization already claimed by different request")
	}
	if out.Phase == guestinit.Failed {
		return out, errors.New("guest initialization failed")
	}
	return out, nil
}

// Initialize confirms the sealed handoff rather than treating CLAIMED as READY.
// Lost acknowledgements may be resolved only by the exact requested epoch, never
// by fresh entropy/identity or execution on the host.
func Initialize(ctx context.Context, socket string, req guestinit.Request) (guestwire.Response, error) {
	if req.Operation != "initialize" || !req.Valid() {
		return guestwire.Response{}, errors.New("invalid initialization request")
	}
	want := req.Digest()
	_, _ = Bootstrap(ctx, socket, req)
	for ctx.Err() == nil {
		probe, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		out, e := Call(probe, socket, guestwire.Request{Version: guestwire.Version, Operation: "health", Ref: req.Ref})
		cancel()
		if e == nil && out.BootID == req.BootID && out.InitializationHash == want {
			return out, nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(20 * time.Millisecond):
		}
	}
	return guestwire.Response{}, errors.New("guest initialization epoch not confirmed")
}
