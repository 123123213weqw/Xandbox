package nodecontrol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func TestClientDoesNotReuseAuthorityAfterRootReplacementOrSocketHardlink(t *testing.T) {
	for _, kind := range []string{"root-replaced", "socket-hardlink", "socket-public"} {
		t.Run(kind, func(t *testing.T) {
			root := shortRoot(t)
			c, e := New(&memoryStore{state: initialState()}, sandbox.NewAdmissionGate(false))
			if e != nil {
				t.Fatal(e)
			}
			s, e := Start(root, c, func() sandbox.Stats { return sandbox.Stats{} })
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close(context.Background())
			client, e := NewClient(root)
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			if _, e = client.Status(context.Background()); e != nil {
				t.Fatal(e)
			}
			socket := filepath.Join(root, SocketName)
			switch kind {
			case "root-replaced":
				moved := root + "-moved"
				if e = os.Rename(root, moved); e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { os.RemoveAll(moved) })
				if e = os.Mkdir(root, 0700); e != nil {
					t.Fatal(e)
				}
				// Keep the exact same socket inode reachable through a new root.
				// A client that checks only the socket would accept it.
				if e = os.Rename(filepath.Join(moved, SocketName), socket); e != nil {
					t.Fatal(e)
				}
			case "socket-hardlink":
				if e = os.Link(socket, filepath.Join(root, "alias")); e != nil {
					t.Fatal(e)
				}
			case "socket-public":
				if e = os.Chmod(socket, 0666); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = client.Status(context.Background()); e == nil {
				t.Fatal("reused stale/private socket authority")
			}
		})
	}
}

func TestClientRejectsMalformedOrUnboundedSuccessReplies(t *testing.T) {
	good := Status{Version: 1, Committed: initialState(), Phase: "ready", DesiredMode: ModeOpen, AdmissionOpen: true}
	for _, kind := range []string{"phase", "pending-open", "missing-pending-id", "negative-reservations", "ready-desired", "unknown-field", "duplicate-field", "trailing", "too-large", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			view := good
			switch kind {
			case "phase":
				view.Phase = "invented"
			case "pending-open":
				view.Phase, view.PendingRequestID = "pending", strings.Repeat("b", 32)
			case "missing-pending-id":
				view.Phase, view.AdmissionOpen = "fenced", false
			case "negative-reservations":
				view.PendingSessionReservations = -1
			case "ready-desired":
				view.DesiredMode = ModeDrained
			}
			data, e := json.Marshal(Reply{Control: view})
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "unknown-field":
				data = append(data[:len(data)-1], []byte(`,"extra":true}`)...)
			case "duplicate-field":
				data = append(data[:len(data)-1], []byte(`,"control":{}}`)...)
			case "trailing":
				data = append(data, []byte(` {}`)...)
			case "too-large":
				data = []byte(strings.Repeat(" ", MaxReplyBytes+1))
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind == "redirect" {
					http.Redirect(w, r, "/other", http.StatusTemporaryRedirect)
					return
				}
				w.Write(data)
			}))
			defer server.Close()
			// Protocol validation only; production clients can never select TCP.
			client := &Client{http: &http.Client{Transport: roundTripTo{target: server.URL}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
			defer client.Close()
			if _, e = client.Status(context.Background()); e == nil {
				t.Fatal("invalid success reply accepted")
			}
		})
	}
}

type roundTripTo struct{ target string }

func (t roundTripTo) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	copy.URL.Host = strings.TrimPrefix(t.target, "http://")
	return http.DefaultTransport.RoundTrip(copy)
}
