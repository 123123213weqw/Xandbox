package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"github.com/123123213weqw/Xandbox/internal/telemetry"
)

// A synthetic blocked call, not disk latency, KVM or a production timeout.
// The caller can disconnect while Prepare deliberately has not returned.
type creationActivityHTTPDriver struct {
	sandbox.Driver
	block                       atomic.Bool
	entered, cancelled, release chan struct{}
}

func (d *creationActivityHTTPDriver) Prepare(ctx context.Context, ref sandbox.Ref, p sandbox.Preparation) error {
	if !d.block.Load() {
		return d.Driver.Prepare(ctx, ref, p)
	}
	close(d.entered)
	<-ctx.Done()
	close(d.cancelled)
	<-d.release
	return ctx.Err()
}

func TestCreationActivityHTTPAfterCallerDisconnectUsesSameRegistry(t *testing.T) {
	for _, kind := range []string{"raw_create", "session_open", "session_switch"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			store, e := sandbox.NewFileStore(filepath.Join(root, "ledger"))
			if e != nil {
				t.Fatal(e)
			}
			mock, e := sandbox.NewMockDriver(filepath.Join(root, "runtime"))
			if e != nil {
				t.Fatal(e)
			}
			d := &creationActivityHTTPDriver{Driver: mock, entered: make(chan struct{}), cancelled: make(chan struct{}), release: make(chan struct{})}
			metrics := &telemetry.Registry{}
			core, e := sandbox.NewManager(store, d, sandbox.Options{Metrics: metrics, MaxInstances: 4, PrepareTimeout: 3 * time.Second})
			if e != nil {
				t.Fatal(e)
			}
			fs, e := session.NewFileStore(filepath.Join(root, "sessions"))
			if e != nil {
				t.Fatal(e)
			}
			broker, e := session.New(core, fs, session.Options{Metrics: metrics})
			if e != nil {
				t.Fatal(e)
			}
			handler, e := NewConfigured(core, Options{AllowUnauthenticatedMock: true, Sessions: broker})
			if e != nil {
				t.Fatal(e)
			}
			server := httptest.NewServer(handler)
			ctx, cancel := context.WithCancel(context.Background())
			var release sync.Once
			t.Cleanup(func() {
				cancel()
				release.Do(func() { close(d.release) })
				server.Close()
				closing, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if e := broker.Close(closing); e != nil {
					t.Error(e)
				}
				if e := core.Close(closing); e != nil {
					t.Error(e)
				}
			})
			path, body := "/v1/sandboxes", `{}`
			if kind == "session_open" {
				path = "/v1/sessions"
			}
			if kind == "session_switch" {
				req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/sessions", strings.NewReader(`{}`))
				req.Header.Set("Idempotency-Key", "initial-activity-session")
				resp, err := server.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				var opened session.Result
				err = json.NewDecoder(resp.Body).Decode(&opened)
				resp.Body.Close()
				if err != nil || resp.StatusCode != 201 || opened.ID == "" {
					t.Fatal("initial session setup failed")
				}
				path, body = "/v1/sessions/"+opened.ID+"/switch", `{"expected_revision":1,"create":{}}`
			}
			d.block.Store(true)
			req, e := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+path, strings.NewReader(body))
			if e != nil {
				t.Fatal(e)
			}
			req.Header.Set("Idempotency-Key", "blocked-activity-operation")
			// Neither this invented selector nor tracing input selects the kind.
			req.Header.Set("X-Xandbox-Creation-Kind", "private-caller-label")
			req.Header.Set("Traceparent", "private-caller-label")
			done := make(chan error, 1)
			go func() {
				resp, err := server.Client().Do(req)
				if resp != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				done <- err
			}()
			select {
			case <-d.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("actual handler did not reach blocked Prepare")
			}
			cancel()
			select {
			case <-d.cancelled:
			case <-time.After(2 * time.Second):
				t.Fatal("original caller cancellation did not propagate")
			}
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("client did not lose the response", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("client cancellation stalled")
			}
			text := string(metrics.Render(telemetry.Gauges{}))
			requestLine := `xandbox_creation_requests_active{operation="` + kind + `"} `
			phaseLine := `xandbox_creation_phases_active{operation="` + kind + `",phase="xa_core_driver"} `
			if !strings.Contains(text, requestLine+"1\n") || !strings.Contains(text, phaseLine+"1\n") || strings.Contains(text, "private-caller-label") {
				t.Fatal("disconnect hid in-flight work or changed the sealed kind")
			}
			release.Do(func() { close(d.release) })
			until := time.Now().Add(2 * time.Second)
			for {
				text = string(metrics.Render(telemetry.Gauges{}))
				if strings.Contains(text, requestLine+"0\n") && strings.Contains(text, phaseLine+"0\n") {
					break
				}
				if time.Now().After(until) {
					t.Fatal("real operation return did not end the activity")
				}
				time.Sleep(time.Millisecond)
			}
			if !strings.Contains(text, "xandbox_creation_activity_invalid 0\n") {
				t.Fatal("balanced handler produced invalid counters")
			}
		})
	}
}
