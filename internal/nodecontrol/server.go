package nodecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

const SocketName = "operator.sock"
const MaxConnections = 16
const MaxCommandBytes = 1024
const MaxReplyBytes = 8192

type Reply struct {
	Control             Status        `json:"control"`
	ResourceObservation sandbox.Stats `json:"resource_observation"`
}
type Server struct {
	server   *http.Server
	listener *net.UnixListener
	control  *Controller
	path     string
	info     os.FileInfo
	errors   chan error
}
type controlError struct {
	Code string `json:"code"`
}

func authorizedUID(uid uint32) bool { return uid == uint32(os.Geteuid()) }
func checkPeer(c *net.UnixConn) error {
	u, e := peerUID(c)
	if e != nil {
		return e
	}
	if !authorizedUID(u) {
		return errors.New("operator peer UID rejected")
	}
	return nil
}

// Start requires the daemon's exclusive state lock. Resources MUST be a bounded
// in-memory observation, not I/O or a quiescence/backup certificate. No tenant
// token is accepted; authorization is private ancestry/mode plus kernel peer UID.
func Start(stateDir string, c *Controller, resources func() sandbox.Stats) (*Server, error) {
	if c == nil || resources == nil {
		return nil, ErrInvalid
	}
	dir, e := privatefile.ExistingDirectory(stateDir)
	if e != nil {
		return nil, e
	}
	path := filepath.Join(dir, SocketName)
	if info, e := os.Lstat(path); e == nil {
		if !privateSocket(info) {
			return nil, errors.New("refusing non-private or non-socket operator path")
		}
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return nil, e
	}
	l.SetUnlinkOnClose(false)
	if e = os.Chmod(path, 0600); e != nil {
		l.Close()
		os.Remove(path)
		return nil, e
	}
	info, e := os.Lstat(path)
	if e != nil {
		l.Close()
		return nil, e
	}
	s := &Server{listener: l, control: c, path: path, info: info, errors: make(chan error, 1)}
	h := controlHandler(c, resources)
	s.server = &http.Server{Handler: h, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 4096}
	go func() {
		e := s.server.Serve(&peerListener{UnixListener: l, slots: make(chan struct{}, MaxConnections)})
		if !errors.Is(e, http.ErrServerClosed) {
			s.errors <- e
		}
	}()
	return s, nil
}
func controlHandler(c *Controller, resources func() sandbox.Stats) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		fail := func(status int, code string) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(controlError{code})
		}
		if r.URL.RawQuery != "" || r.URL.RawPath != "" || len(r.Header.Values("Authorization")) != 0 || r.Header.Get("Origin") != "" {
			fail(400, "INVALID_REQUEST")
			return
		}
		if r.URL.Path == "/v1/node" && r.Method == http.MethodGet {
			b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 1))
			if e != nil || len(b) != 0 {
				fail(400, "INVALID_REQUEST")
				return
			}
			_ = json.NewEncoder(w).Encode(Reply{Control: c.Status(), ResourceObservation: resources()})
			return
		}
		target := ""
		switch r.URL.Path {
		case "/v1/node/drain":
			target = ModeDrained
		case "/v1/node/resume":
			target = ModeOpen
		default:
			fail(404, "NOT_FOUND")
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			fail(405, "METHOD_NOT_ALLOWED")
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			fail(415, "JSON_REQUIRED")
			return
		}
		data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxCommandBytes))
		if e != nil {
			fail(413, "COMMAND_TOO_LARGE")
			return
		}
		var request Command
		if e = strictjson.Decode(data, &request); e != nil || !request.Valid() {
			fail(400, "INVALID_COMMAND")
			return
		}
		view, e := c.Change(r.Context(), target, request)
		if e != nil {
			switch {
			case errors.Is(e, ErrBusy):
				fail(409, "BUSY")
			case errors.Is(e, ErrConflict):
				fail(409, "CONFLICT")
			case errors.Is(e, ErrFenced):
				fail(503, "PERSISTENCE_FENCED")
			case errors.Is(e, ErrExhausted):
				fail(409, "REVISION_EXHAUSTED")
			case errors.Is(e, ErrClosed):
				fail(503, "CLOSED")
			case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded):
				fail(408, "CANCELLED_BEFORE_ACCEPTANCE")
			default:
				fail(500, "INTERNAL")
			}
			return
		}
		_ = json.NewEncoder(w).Encode(Reply{Control: view, ResourceObservation: resources()})
	})
}
func (s *Server) Errors() <-chan error { return s.errors }

// Stop closes the listener and fences new control operations WITHOUT waiting
// behind storage. The daemon must subsequently Close the controller and retain
// its exclusive state lock if that bounded wait fails.
func (s *Server) Stop() error {
	s.control.FenceClose()
	e := s.server.Close()
	if current, err := os.Lstat(s.path); err == nil && os.SameFile(current, s.info) {
		e = errors.Join(e, os.Remove(s.path))
	}
	return e
}
func (s *Server) Close(ctx context.Context) error { return errors.Join(s.Stop(), s.control.Close(ctx)) }

type peerListener struct {
	*net.UnixListener
	slots chan struct{}
}
type peerConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *peerConn) Close() error { e := c.Conn.Close(); c.once.Do(c.release); return e }
func (l *peerListener) Accept() (net.Conn, error) {
	for {
		c, e := l.AcceptUnix()
		if e != nil {
			return nil, e
		}
		if e = checkPeer(c); e != nil {
			c.Close()
			continue
		}
		select {
		case l.slots <- struct{}{}:
			return &peerConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}
