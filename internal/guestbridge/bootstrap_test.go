package guestbridge

import (
	"bufio"
	"context"
	"fmt"
	"github.com/123123213weqw/Xandbox/internal/guestinit"
	"github.com/123123213weqw/Xandbox/internal/guestwire"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInitializationWaitsForExactEpochEvenAfterLostAcknowledgement(t *testing.T) {
	for _, bad := range []string{"", "epoch", "boot", "ref", "uninitialized"} {
		t.Run(bad, func(t *testing.T) {
			r, e := guestinit.NewRequest(health().Ref)
			if e != nil {
				t.Fatal(e)
			}
			defer r.WipeEntropy()
			dir, e := os.MkdirTemp("", "xb-init-")
			if e != nil {
				t.Fatal(e)
			}
			defer os.RemoveAll(dir)
			socket := filepath.Join(dir, "v.sock")
			l, e := net.Listen("unix", socket)
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					conn, e := l.Accept()
					if e != nil {
						return
					}
					func() {
						defer conn.Close()
						reader := bufio.NewReader(conn)
						line, e := reader.ReadString('\n')
						if e != nil {
							return
						}
						fmt.Fprint(conn, "OK 1234\n")
						if line == "CONNECT 901\n" {
							var req guestinit.Request
							_ = guestwire.Read(reader, guestinit.MaxRequest, &req)
							req.WipeEntropy()
							return
						} // Simulate a lost CLAIMED acknowledgement.
						if line != "CONNECT 900\n" {
							return
						}
						var req guestwire.Request
						if guestwire.Read(reader, guestwire.MaxRequest, &req) != nil {
							return
						}
						response := guestwire.Response{Version: 1, Ref: r.Ref, BootID: r.BootID, InitializationHash: r.Digest(), Status: "READY"}
						switch bad {
						case "epoch":
							response.InitializationHash = strings.Repeat("f", 64)
						case "boot":
							response.BootID = "11111111-1111-4111-8111-111111111111"
						case "ref":
							response.Ref.Generation = strings.Repeat("e", 32)
						case "uninitialized":
							response.InitializationHash = ""
						}
						_ = guestwire.Write(conn, guestwire.MaxResponse, response)
					}()
				}
			}()
			deadline := 150 * time.Millisecond
			if bad == "" {
				deadline = 2 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), deadline)
			defer cancel()
			out, e := Initialize(ctx, socket, r)
			if bad == "" {
				if e != nil || out.InitializationHash != r.Digest() {
					t.Fatal("matching epoch not recovered after lost ACK", e)
				}
			} else if e == nil {
				t.Fatal("unconfirmed epoch accepted", bad)
			}
			l.Close()
			<-done
		})
	}
}
func TestBootstrapRejectsDifferentClaimWithoutEchoingSecrets(t *testing.T) {
	req, e := guestinit.NewRequest(health().Ref)
	if e != nil {
		t.Fatal(e)
	}
	defer req.WipeEntropy()
	socket := testBridge(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		line, _ := reader.ReadString('\n')
		if line != "CONNECT 901\n" {
			t.Error("wrong bootstrap port")
			return
		}
		fmt.Fprint(conn, "OK 1234\n")
		var r guestinit.Request
		_ = guestwire.Read(reader, guestinit.MaxRequest, &r)
		defer r.WipeEntropy()
		_ = guestwire.Write(conn, guestinit.MaxResponse, guestinit.Response{Version: 1, Phase: guestinit.Claimed, Digest: strings.Repeat("d", 64)})
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e = Bootstrap(ctx, socket, req); e == nil || strings.Contains(e.Error(), req.Nonce) {
		t.Fatal("different initialization accepted or nonce leaked")
	}
}
