package nodecontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

type Client struct{ http *http.Client }

func NewClient(stateDir string) (*Client, error) {
	dir, e := privatefile.ExistingDirectory(stateDir)
	if e != nil {
		return nil, e
	}
	directoryInfo, e := os.Lstat(dir)
	if e != nil {
		return nil, e
	}
	path := filepath.Join(dir, SocketName)
	transport := &http.Transport{DisableKeepAlives: true, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		if _, e := privatefile.ExistingDirectory(dir); e != nil {
			return nil, e
		}
		currentDir, e := os.Lstat(dir)
		if e != nil || !os.SameFile(directoryInfo, currentDir) {
			return nil, errors.New("operator root identity changed")
		}
		before, e := os.Lstat(path)
		if e != nil {
			return nil, e
		}
		if !privateSocket(before) {
			return nil, errors.New("invalid private operator socket")
		}
		conn, e := (&net.Dialer{}).DialContext(ctx, "unix", path)
		if e != nil {
			return nil, e
		}
		u, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			return nil, errors.New("operator transport is not Unix")
		}
		if e = checkPeer(u); e != nil {
			conn.Close()
			return nil, e
		}
		after, e := os.Lstat(path)
		if e != nil || !privateSocket(after) || !os.SameFile(before, after) {
			conn.Close()
			return nil, errors.New("operator socket identity changed")
		}
		return conn, nil
	}}
	return &Client{http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) Close()                                    { c.http.CloseIdleConnections() }
func (c *Client) Status(ctx context.Context) (Reply, error) { return c.call(ctx, "status", nil) }
func (c *Client) Change(ctx context.Context, mode string, request Command) (Reply, error) {
	if !request.Valid() {
		return Reply{}, ErrInvalid
	}
	if mode == ModeDrained {
		return c.call(ctx, "drain", &request)
	}
	if mode == ModeOpen {
		return c.call(ctx, "resume", &request)
	}
	return Reply{}, ErrInvalid
}
func (c *Client) call(ctx context.Context, operation string, command *Command) (Reply, error) {
	var reply Reply
	path, method := "/v1/node", http.MethodGet
	if operation != "status" {
		path += "/" + operation
		method = http.MethodPost
	}
	var data []byte
	if command != nil {
		data, _ = json.Marshal(command)
	}
	r, e := http.NewRequestWithContext(ctx, method, "http://node.local"+path, bytes.NewReader(data))
	if e != nil {
		return reply, e
	}
	if command != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	response, e := c.http.Do(r)
	if e != nil {
		return reply, e
	}
	defer response.Body.Close()
	b, e := io.ReadAll(io.LimitReader(response.Body, MaxReplyBytes+1))
	if e != nil {
		return reply, e
	}
	if len(b) > MaxReplyBytes {
		return reply, errors.New("operator reply too large")
	}
	if response.StatusCode != 200 {
		var failure controlError
		if e = strictjson.Decode(b, &failure); e != nil {
			return reply, fmt.Errorf("operator HTTP%d", response.StatusCode)
		}
		switch failure.Code {
		case "BUSY", "CONFLICT", "PERSISTENCE_FENCED", "REVISION_EXHAUSTED", "CLOSED", "CANCELLED_BEFORE_ACCEPTANCE", "INVALID_COMMAND", "INVALID_REQUEST":
			return reply, fmt.Errorf("operator HTTP%d: %s", response.StatusCode, failure.Code)
		default:
			return reply, fmt.Errorf("operator HTTP%d", response.StatusCode)
		}
	}
	if e = strictjson.Decode(b, &reply); e != nil {
		return reply, e
	}
	if !reply.Control.valid() {
		return reply, errors.New("invalid operator reply")
	}
	return reply, nil
}
