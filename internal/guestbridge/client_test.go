package guestbridge

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/guestwire"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func testBridge(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "xbv-")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "v.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close(); os.RemoveAll(dir) })
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		serve(conn)
	}()
	return socket
}
func health() guestwire.Request {
	return guestwire.Request{Version: 1, Operation: "health", Ref: sandbox.Ref{ID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}}
}

func TestBridgeIdentityAndAck(t *testing.T) {
	for _, bad := range []string{"", "identity", "version", "status", "ack", "boot", "error"} {
		t.Run(bad, func(t *testing.T) {
			socket := testBridge(t, func(conn net.Conn) {
				r := bufio.NewReader(conn)
				line, err := r.ReadString('\n')
				if err != nil || line != "CONNECT 900\n" {
					t.Error("incorrect bridge handshake")
					return
				}
				if bad == "ack" {
					fmt.Fprint(conn, strings.Repeat("X", 80))
					return
				}
				fmt.Fprint(conn, "OK 1073741824\n")
				var req guestwire.Request
				if err := guestwire.Read(r, guestwire.MaxRequest, &req); err != nil {
					t.Error(err)
					return
				}
				response := guestwire.Response{Version: 1, Ref: req.Ref, Status: "READY", BootID: "11111111-1111-4111-8111-111111111111"}
				switch bad {
				case "identity":
					response.Ref.Generation = strings.Repeat("c", 32)
				case "version":
					response.Version = 2
				case "status":
					response.Status = "unknown"
				case "boot":
					response.BootID = ""
				case "error":
					response.Error = "failure despite READY"
				}
				_ = guestwire.Write(conn, guestwire.MaxResponse, response)
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			response, err := Call(ctx, socket, health())
			if bad == "" {
				if err != nil || response.BootID != "11111111-1111-4111-8111-111111111111" {
					t.Fatalf("health: %+v %v", response, err)
				}
			} else if err == nil {
				t.Fatalf("invalid %s response accepted", bad)
			}
		})
	}
}

func TestBridgeCancellationClosesConnection(t *testing.T) {
	closed := make(chan struct{})
	socket := testBridge(t, func(conn net.Conn) {
		defer close(closed)
		var b [128]byte
		for {
			if _, err := conn.Read(b[:]); err != nil {
				return
			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := Call(ctx, socket, health()); err == nil {
		t.Fatal("cancelled bridge returned success")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("cancelled call leaked its socket")
	}
}
