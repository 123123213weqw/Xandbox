package observability

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/telemetry"
)

func shortDir(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(base, "xb-m-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
func clientFor(t *testing.T, path string) *http.Client {
	t.Helper()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 3 * time.Second}
}
func TestPrivateSurfaceAndStrictRoutes(t *testing.T) {
	dir := shortDir(t)
	r := &telemetry.Registry{}
	s, err := Start(dir, r, func() telemetry.Gauges { return telemetry.Gauges{Records: 7} })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	info, err := os.Lstat(s.path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal(info, err)
	}
	c := clientFor(t, s.path)
	for _, tc := range []struct {
		method, path string
		status       int
	}{{"GET", "/metrics", 200}, {"GET", "/metrics?tenant=secret", 404}, {"POST", "/metrics", 405}, {"GET", "/debug/pprof", 404}, {"GET", "/v1/sandboxes", 404}} {
		req, _ := http.NewRequest(tc.method, "http://localhost"+tc.path, nil)
		req.Header.Set("Authorization", "Bearer never-export-this")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 65537))
		resp.Body.Close()
		if resp.StatusCode != tc.status || len(b) > 65536 || strings.Contains(string(b), "never-export") {
			t.Fatal(resp.Status, len(b))
		}
		if tc.status == 200 && (!strings.Contains(string(b), "xandbox_records 7\n") || resp.Header.Get("Cache-Control") != "no-store") {
			t.Fatal("bad exposition")
		}
	}
	s.Close()
	if _, err := os.Lstat(s.path); !os.IsNotExist(err) {
		t.Fatal("socket not removed", err)
	}
}
func TestRefusesFilesSymlinksAndPublicDirectory(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "public"} {
		t.Run(kind, func(t *testing.T) {
			dir := shortDir(t)
			path := filepath.Join(dir, "metrics.sock")
			switch kind {
			case "file":
				os.WriteFile(path, []byte("preserve"), 0600)
			case "symlink":
				os.Symlink("missing", path)
			case "public":
				os.Chmod(dir, 0755)
			}
			if s, err := Start(dir, &telemetry.Registry{}, func() telemetry.Gauges { return telemetry.Gauges{} }); err == nil {
				s.Close()
				t.Fatal("unsafe path accepted")
			}
			if kind == "file" {
				b, _ := os.ReadFile(path)
				if string(b) != "preserve" {
					t.Fatal("file replaced")
				}
			}
		})
	}
}
func TestBoundedConnectionsAndConcurrentScrapes(t *testing.T) {
	dir := shortDir(t)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var calls atomic.Int32
	s, err := Start(dir, &telemetry.Registry{}, func() telemetry.Gauges { calls.Add(1); entered <- struct{}{}; <-release; return telemetry.Gauges{} })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer close(release)
	c := clientFor(t, s.path)
	done := make(chan error, 2)
	for range 2 {
		go func() {
			resp, err := c.Get("http://localhost/metrics")
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			done <- err
		}()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("scrape not entered")
		}
	}
	resp, err := c.Get("http://localhost/metrics")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 503 || calls.Load() != 2 {
		t.Fatal("unbounded scrape concurrency", resp.Status, calls.Load())
	}
	// The listener, independently of the handler, bounds accepted HTTP goroutines.
	l := s.listener.(*limitedListener)
	conns := []net.Conn{}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for range MaxConnections + 4 {
		if conn, err := net.DialTimeout("unix", s.path, time.Second); err == nil {
			conns = append(conns, conn)
		}
	}
	if len(l.slots) > MaxConnections {
		t.Fatal("unbounded listener")
	}
}

type pipeListener struct {
	connections chan net.Conn
	closed      chan struct{}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connections:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *pipeListener) Close() error   { close(l.closed); return nil }
func (l *pipeListener) Addr() net.Addr { return &net.UnixAddr{Name: "test", Net: "unix"} }

func TestListenerClosesOverflowAndReusesOnlyReleasedSlots(t *testing.T) {
	base := &pipeListener{connections: make(chan net.Conn, MaxConnections+1), closed: make(chan struct{})}
	defer base.Close()
	l := &limitedListener{Listener: base, slots: make(chan struct{}, MaxConnections)}
	owned := []net.Conn{}
	defer func() {
		for _, c := range owned {
			c.Close()
		}
	}()
	for range MaxConnections {
		a, b := net.Pipe()
		defer b.Close()
		base.connections <- a
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		owned = append(owned, c)
	}
	a, b := net.Pipe()
	defer b.Close()
	base.connections <- a
	next := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); next <- c }()
	b.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := b.Read(buf); err != io.EOF {
		t.Fatal("overflow was not closed", err)
	}
	if len(l.slots) != MaxConnections {
		t.Fatal("overflow leaked a slot")
	}
	owned[0].Close()
	a, b = net.Pipe()
	defer b.Close()
	base.connections <- a
	select {
	case c := <-next:
		if c == nil {
			t.Fatal("listener closed")
		}
		owned = append(owned, c)
	case <-time.After(time.Second):
		t.Fatal("released slot not reusable")
	}
}
