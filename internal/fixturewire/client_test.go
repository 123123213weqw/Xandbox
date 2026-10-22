package fixturewire

import (
	"bufio"
	"context"
	"github.com/123123213weqw/Xandbox/internal/guestwire"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadOnlyFixtureProtocol(t *testing.T) {
	root, e := os.MkdirTemp("/tmp", "xf")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(root)
	socket := filepath.Join(root, "v.sock")
	l, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		line, _ := r.ReadString('\n')
		if line != "CONNECT 902\n" {
			return
		}
		_, _ = c.Write([]byte("OK 42\n"))
		var q Request
		if guestwire.Read(r, 1024, &q) != nil || q.Operation != "inspect" {
			return
		}
		_ = guestwire.Write(c, 2048, Response{Version: 1, AgentGenerations: 2})
	}()
	ctx, c := context.WithTimeout(context.Background(), time.Second)
	defer c()
	v, e := Inspect(ctx, socket, "")
	if e != nil || v.AgentGenerations != 2 {
		t.Fatal(e)
	}
	<-done
}
