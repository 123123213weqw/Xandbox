// Package observability serves operator-only metrics on a separate private UDS.
// Tenant bearer tokens never authorize this host-UID administrative surface.
package observability

import (
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/telemetry"
)

const MaxConnections = 16

type Server struct {
	server   *http.Server
	listener net.Listener
	path     string
	errors   chan error
}

// Start requires exclusive ownership of the controller state directory. It
// never binds TCP, follows socket symlinks, or replaces ordinary files.
func Start(stateDir string, registry *telemetry.Registry, gauges func() telemetry.Gauges) (*Server, error) {
	if registry == nil || gauges == nil {
		return nil, errors.New("metrics registry and atomic gauge source required")
	}
	dir, err := privatefile.EnsureDirectory(stateDir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "metrics.sock")
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("refusing to replace non-socket metrics path")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		l.Close()
		os.Remove(path)
		return nil, err
	}
	busy := make(chan struct{}, 2)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != "/metrics" || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		select {
		case busy <- struct{}{}:
			defer func() { <-busy }()
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write(registry.Render(gauges()))
	})
	s := &Server{listener: &limitedListener{Listener: l, slots: make(chan struct{}, MaxConnections)}, path: path, errors: make(chan error, 1)}
	s.server = &http.Server{Handler: h, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 4096}
	go func() {
		err := s.server.Serve(s.listener)
		if !errors.Is(err, http.ErrServerClosed) {
			s.errors <- err
		}
	}()
	return s, nil
}

func (s *Server) Errors() <-chan error { return s.errors }
func (s *Server) Close() error         { err := s.server.Close(); os.Remove(s.path); return err }

type limitedListener struct {
	net.Listener
	slots chan struct{}
}
type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}
