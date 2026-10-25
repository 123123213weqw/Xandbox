package nodecontrol

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func TestPrivateUnixOperatorRoundTripCredentialsAndProtocol(t *testing.T) {
	root := shortRoot(t)
	fs, e := OpenStore(root)
	if e != nil {
		t.Fatal(e)
	}
	c, e := New(fs, sandbox.NewAdmissionGate(false))
	if e != nil {
		t.Fatal(e)
	}
	s, e := Start(root, c, func() sandbox.Stats { return sandbox.Stats{Backend: "mock", Capacity: 4} })
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.Close(ctx)
	})
	client, e := NewClient(root)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, e := client.Status(ctx)
	if e != nil || !r.Control.AdmissionOpen {
		t.Fatal(r, e)
	}
	drained, e := client.Change(ctx, ModeDrained, command(r.Control.Committed, "b"))
	if e != nil || drained.Control.AdmissionOpen {
		t.Fatal(drained, e)
	}
	replay, e := client.Change(ctx, ModeDrained, command(r.Control.Committed, "b"))
	if e != nil || replay.Control != drained.Control {
		t.Fatal("last command retry", e)
	}
	if _, e = client.Change(ctx, ModeOpen, command(r.Control.Committed, "c")); e == nil {
		t.Fatal("stale command opened gate")
	}
	opened, e := client.Change(ctx, ModeOpen, command(drained.Control.Committed, "d"))
	if e != nil || !opened.Control.AdmissionOpen {
		t.Fatal(opened, e)
	}
	if authorizedUID(uint32(os.Geteuid()) + 1) {
		t.Fatal("different host UID accepted")
	}
	// Kernel credentials are also checked by the client; a non-Unix transport
	// or a malicious TCP address cannot be selected through this API.
	if _, e = NewClient(filepath.Join(root, "missing")); e == nil {
		t.Fatal("client created a missing state root")
	}
	if _, e = os.Stat(filepath.Join(root, "missing")); !os.IsNotExist(e) {
		t.Fatal("read-only client modified state")
	}
}
func TestOperatorStrictRequestsCannotUseTenantTokensOrArbitraryRoutes(t *testing.T) {
	f := &memoryStore{state: initialState()}
	c, e := New(f, sandbox.NewAdmissionGate(false))
	if e != nil {
		t.Fatal(e)
	}
	h := controlHandler(c, func() sandbox.Stats { return sandbox.Stats{} })
	valid := `{"version":1,"epoch":"` + strings.Repeat("a", 32) + `","expected_revision":1,"request_id":"` + strings.Repeat("b", 32) + `"}`
	for _, tc := range []struct {
		method, path, body, auth string
		want                     int
	}{
		{"GET", "/v1/node", "", "", 200},
		{"GET", "/v1/node?x=1", "", "", 400},
		{"GET", "/v1/node", "x", "", 400},
		{"GET", "/v1/node", "", "Bearer tenant-token", 400},
		{"POST", "/v1/node/drain", valid, "Bearer tenant-token", 400},
		{"GET", "/v1/node/drain", "", "", 405},
		{"POST", "/v1/node/exec", valid, "", 404},
		{"POST", "/v1/node/drain", strings.Replace(valid, `"version":1`, `"version":2`, 1), "", 400},
		{"POST", "/v1/node/drain", strings.Replace(valid, `"version":1`, `"version":1,"argv":["forbidden"]`, 1), "", 400},
		{"POST", "/v1/node/drain", valid + valid, "", 400},
		{"POST", "/v1/node/drain", strings.Repeat("x", MaxCommandBytes+1), "", 413},
	} {
		t.Run(tc.method+tc.path+tc.body[:min(5, len(tc.body))], func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			if tc.method == "POST" {
				r.Header.Set("Content-Type", "application/json")
			}
			if tc.auth != "" {
				r.Header.Set("Authorization", tc.auth)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatal(w.Code, tc.want, w.Body.String())
			}
		})
	}
	if c.Status().Committed.Revision != 1 || !c.Status().AdmissionOpen {
		t.Fatal("invalid request mutated control")
	}
}
func TestOperatorClientStatusAndLifecycleDoNotWaitForBlockedControlSave(t *testing.T) {
	root := shortRoot(t)
	gate := sandbox.NewAdmissionGate(true)
	ledger, e := sandbox.NewFileStore(filepath.Join(root, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	driver, e := sandbox.NewMockDriver(filepath.Join(root, "instances"))
	if e != nil {
		t.Fatal(e)
	}
	core, e := sandbox.NewManager(ledger, driver, sandbox.Options{AdmissionGate: gate, MaxInstances: 4, ReapInterval: time.Millisecond, RetryDelay: time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		core.Close(ctx)
	})
	old, e := core.Create(context.Background(), sandbox.CreateRequest{})
	if e != nil {
		t.Fatal(e)
	}
	f := &memoryStore{state: initialState(), entered: make(chan struct{}, 1), release: make(chan struct{})}
	c, e := New(f, gate)
	if e != nil {
		t.Fatal(e)
	}
	s, e := Start(root, c, core.Stats)
	if e != nil {
		t.Fatal(e)
	}
	client, e := NewClient(root)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := client.Change(ctx, ModeDrained, command(initialState(), "b")); done <- e }()
	<-f.entered
	statusCtx, statusCancel := context.WithTimeout(context.Background(), time.Second)
	defer statusCancel()
	if r, e := client.Status(statusCtx); e != nil || r.Control.Phase != "pending" || r.Control.AdmissionOpen {
		t.Fatal("same client status blocked", r, e)
	}
	if _, e = core.Create(context.Background(), sandbox.CreateRequest{}); !errors.Is(e, sandbox.ErrDraining) {
		t.Fatal(e)
	}
	if _, e = core.Exec(old.ID, sandbox.ExecRequest{Generation: old.Generation, Argv: []string{"echo", "still-alive"}}); e != nil {
		t.Fatal("accepted task blocked", e)
	}
	if _, e = core.Destroy(old.Ref); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(time.Second)
	for core.Metrics().Allocated != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if core.Metrics().Allocated != 0 {
		t.Fatal("Stop/Cleanup waited for operator persistence")
	}
	if _, e = client.Change(statusCtx, ModeOpen, command(initialState(), "c")); e == nil || !strings.Contains(e.Error(), "BUSY") {
		t.Fatal("concurrent mutation queued behind IO", e)
	}
	cancel()
	if e = <-done; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer closeCancel()
	if e = s.Close(closeCtx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("unresolved control writer not retained", e)
	}
	close(f.release)
	deadline = time.Now().Add(time.Second)
	for c.Status().PendingRequestID != "" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if e = c.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	if gate.Open() {
		t.Fatal("late storage completion reopened closing node")
	}
}
func TestOperatorSocketModeAndCleanupIdentity(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "public-mode"} {
		t.Run(kind, func(t *testing.T) {
			root := shortRoot(t)
			path := filepath.Join(root, SocketName)
			switch kind {
			case "file":
				os.WriteFile(path, nil, 0600)
			case "symlink":
				os.Symlink("missing", path)
			case "public-mode":
				l, e := net.Listen("unix", path)
				if e != nil {
					t.Fatal(e)
				}
				defer l.Close()
				os.Chmod(path, 0666)
			}
			c, _ := New(&memoryStore{state: initialState()}, sandbox.NewAdmissionGate(false))
			if s, e := Start(root, c, func() sandbox.Stats { return sandbox.Stats{} }); e == nil {
				s.Close(context.Background())
				t.Fatal("unknown/nonprivate socket path replaced")
			}
		})
	}
	root := shortRoot(t)
	c, _ := New(&memoryStore{state: initialState()}, sandbox.NewAdmissionGate(false))
	s, e := Start(root, c, func() sandbox.Stats { return sandbox.Stats{} })
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, SocketName)
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(path, []byte("keep"), 0600)
	if e = s.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	if b, e := os.ReadFile(path); e != nil || string(b) != "keep" {
		t.Fatal("cleanup unlinked a substituted path")
	}
}
