// Package fixturewire is a read-only test-image diagnostic protocol. Production
// agents and images do not import it and have no listener on this fixture port.
package fixturewire

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/guestwire"
)

const Port = 902

type Request struct {
	Version        int    `json:"version"`
	Operation      string `json:"operation"`
	ExpectedBootID string `json:"expected_boot_id,omitempty"`
}
type Response struct {
	Version            int  `json:"version"`
	BeforeMarkerExit   bool `json:"before_marker_exit"`
	Claimed            bool `json:"claimed"`
	Receipt            bool `json:"receipt"`
	MachineIDDirectory bool `json:"machine_id_directory"`
	BootMatches        bool `json:"boot_matches"`
	BootReadOnlyBind   bool `json:"boot_read_only_bind"`
	AgentGenerations   int  `json:"agent_generations"`
}

func Inspect(ctx context.Context, socket, expected string) (Response, error) {
	var out Response
	if len(expected) > 36 {
		return out, errors.New("invalid diagnostic identity length")
	}
	c, e := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if e != nil {
		return out, e
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	if _, e = fmt.Fprintf(c, "CONNECT %d\n", Port); e != nil {
		return out, e
	}
	r := bufio.NewReaderSize(c, 64)
	line, e := r.ReadSlice('\n')
	if e != nil || len(line) > 32 || !strings.HasPrefix(string(line), "OK ") {
		return out, errors.New("fixture bridge unavailable")
	}
	parts := strings.Split(strings.TrimSuffix(string(line), "\n"), " ")
	if len(parts) != 2 {
		return out, errors.New("invalid fixture bridge acknowledgement")
	}
	if port, e := strconv.ParseUint(parts[1], 10, 32); e != nil || port == 0 {
		return out, errors.New("invalid fixture bridge port")
	}
	if e = guestwire.Write(c, 1024, Request{Version: 1, Operation: "inspect", ExpectedBootID: expected}); e != nil {
		return out, e
	}
	if e = guestwire.Read(r, 2048, &out); e != nil {
		return out, e
	}
	if out.Version != 1 || out.AgentGenerations < 0 || out.AgentGenerations > 65536 {
		return Response{}, errors.New("invalid fixture response")
	}
	return out, nil
}
