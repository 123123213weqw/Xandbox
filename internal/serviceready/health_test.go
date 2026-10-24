package serviceready

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func validHealth() map[string]any {
	return map[string]any{"backend": "firecracker", "isolation": true, "authentication": true, "admission_open": true, "production_ready": false, "isolation_mechanism": "firecracker-kvm-jailer", "message": "lifecycle prototype; production acceptance incomplete"}
}
func TestHealthRequiresExactRealAuthenticatedShape(t *testing.T) {
	good := validHealth()
	b, _ := json.Marshal(good)
	if e := healthBody(b); e != nil {
		t.Fatal(e)
	}
	good["admission_open"] = false
	b, _ = json.Marshal(good)
	if e := healthBody(b); e != nil {
		t.Fatal("must preserve durable drain", e)
	}
	for _, key := range []string{"backend", "isolation", "authentication", "admission_open", "production_ready", "isolation_mechanism", "message"} {
		bad := validHealth()
		delete(bad, key)
		b, _ = json.Marshal(bad)
		if key != "message" && healthBody(b) == nil {
			t.Fatal("missing health field", key)
		}
	}
	for _, pair := range []struct {
		k string
		v any
	}{{"backend", "mock"}, {"isolation", false}, {"isolation", 1}, {"authentication", false}, {"authentication", nil}, {"admission_open", nil}, {"production_ready", true}, {"isolation_mechanism", "host-shell"}, {"stats", map[string]any{}}, {"private", true}} {
		bad := validHealth()
		bad[pair.k] = pair.v
		b, _ = json.Marshal(bad)
		if healthBody(b) == nil {
			t.Fatal("invalid health", pair.k)
		}
	}
	b, _ = json.Marshal(validHealth())
	if healthBody(append(b[:len(b)-1], []byte(`,"isolation":true}`)...)) == nil {
		t.Fatal("duplicate health accepted")
	}
}
func serveHealth(t *testing.T, reply string) (net.Conn, <-chan *http.Request) {
	t.Helper()
	client, server := net.Pipe()
	requests := make(chan *http.Request, 1)
	go func() {
		defer server.Close()
		r, e := http.ReadRequest(bufio.NewReader(server))
		if e == nil {
			requests <- r
			server.Write([]byte(reply))
		}
		close(requests)
	}()
	return client, requests
}
func TestHTTPGateIsFixedBodylessAndRejectsRedirectOrOversize(t *testing.T) {
	b, _ := json.Marshal(validHealth())
	for _, status := range []string{"200 OK", "302 Found"} {
		conn, seen := serveHealth(t, "HTTP/1.1 "+status+"\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"+string(b))
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		e := requestHealth(ctx, conn)
		cancel()
		conn.Close()
		r := <-seen
		if r == nil || r.Method != "GET" || r.URL.Path != "/healthz" || r.ContentLength != 0 || r.Header.Get("Authorization") != "" {
			t.Fatal("not fixed public health")
		}
		if (e == nil) != (status == "200 OK") {
			t.Fatal("wrong HTTP acceptance", status, e)
		}
	}
}

func TestHTTPRejectsOversizedHealthAndNoResponseDeadline(t *testing.T) {
	conn, _ := serveHealth(t, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"+strings.Repeat(" ", 2049))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if requestHealth(ctx, conn) == nil {
		t.Fatal("oversize health")
	}
	cancel()
	conn.Close()
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if requestHealth(ctx, client) == nil {
		t.Fatal("unresponsive service accepted")
	}
	client.Close()
}
