package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/session"
)

func sessionAPI(t *testing.T) (*httptest.Server, string, string) {
	t.Helper()
	_, core := setupAPI(t)
	store, e := session.NewFileStore(filepath.Join(t.TempDir(), "sessions"))
	if e != nil {
		t.Fatal(e)
	}
	b, e := session.New(core, store, session.Options{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if e := b.Close(ctx); e != nil {
			t.Error(e)
		}
	})
	aToken, bToken := strings.Repeat("a", 40), strings.Repeat("b", 40)
	keys := []access.Key{}
	for n, token := range []string{aToken, bToken} {
		sum := sha256.Sum256([]byte(token))
		keys = append(keys, access.Key{TokenSHA256: hex.EncodeToString(sum[:]), TenantID: []string{"alpha", "beta"}[n], MaxInstances: 4})
	}
	auth, e := access.New(access.Config{Version: 1, Keys: keys})
	if e != nil {
		t.Fatal(e)
	}
	h, e := NewConfigured(core, Options{Authenticator: auth, Sessions: b})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	return server, aToken, bToken
}

func TestSessionHTTPConditionalSwitchAndScopedProjections(t *testing.T) {
	s, a, b := sessionAPI(t)
	if status, _ := authorizedCall(t, s, "", "POST", "/v1/sessions", "{}", "create", nil); status != 401 {
		t.Fatal(status)
	}
	if status, _ := authorizedCall(t, s, a, "POST", "/v1/sessions", "{}", "", nil); status != 400 {
		t.Fatal(status)
	}
	status, body := authorizedCall(t, s, a, "POST", "/v1/sessions", "{}", "create", nil)
	if status != 201 {
		t.Fatal(status, string(body))
	}
	var first session.Result
	if e := json.Unmarshal(body, &first); e != nil {
		t.Fatal(e)
	}
	path := "/v1/sessions/" + first.ID
	for _, route := range []struct{ method, path, body string }{{"GET", path, ""}, {"POST", path + "/switch", `{"expected_revision":1}`}, {"POST", path + "/exec", `{"revision":1,"argv":["echo"]}`}, {"POST", path + "/revoke", `{"expected_revision":1}`}} {
		status, _ := authorizedCall(t, s, b, route.method, route.path, route.body, "key", nil)
		if status != 404 {
			t.Fatalf("cross tenant %s: %d", route.path, status)
		}
	}
	vmPath := "/v1/sandboxes/" + first.Current.ID
	status, _ = authorizedCall(t, s, a, "POST", vmPath+"/exec", fmt.Sprintf(`{"generation":%q,"argv":["echo","bypass"]}`, first.Current.Generation), "", nil)
	if status != 409 {
		t.Fatal("managed plain-exec bypass", status)
	}
	status, body = authorizedCall(t, s, a, "POST", path+"/exec", `{"revision":1,"argv":["echo","ok"]}`, "", nil)
	if status != 202 || !bytes.Contains(body, []byte(`"sandbox"`)) || !bytes.Contains(body, []byte(`"job"`)) {
		t.Fatal(status, string(body))
	}
	status, _ = authorizedCall(t, s, a, "POST", path+"/exec", `{"revision":1,"generation":"forged","argv":["echo"]}`, "", nil)
	if status != 400 {
		t.Fatal("accepted untrusted generation selector", status)
	}
	status, body = authorizedCall(t, s, a, "POST", path+"/switch", `{"expected_revision":1}`, "switch", nil)
	if status != 200 {
		t.Fatal(status, string(body))
	}
	var second session.Result
	json.Unmarshal(body, &second)
	if second.Revision != 2 || second.Previous != first.Current || second.Current == first.Current {
		t.Fatal(second)
	}
	status, _ = authorizedCall(t, s, a, "POST", path+"/exec", `{"revision":1,"argv":["echo"]}`, "", nil)
	if status != 409 {
		t.Fatal("stale request not rejected", status)
	}
	status, body = authorizedCall(t, s, a, "GET", path, "", "", nil)
	if status != 200 || bytes.Contains(body, []byte("key_hash")) || bytes.Contains(body, []byte("spec_hash")) {
		t.Fatal("private session metadata exposed", status, string(body))
	}
	status, body = authorizedCall(t, s, a, "POST", path+"/revoke", `{"expected_revision":2}`, "", nil)
	if status != 200 || !bytes.Contains(body, []byte(`"durable":false`)) || !bytes.Contains(body, []byte(`"stop_confirmed":false`)) {
		t.Fatal(status, string(body))
	}
	status, _ = authorizedCall(t, s, a, "POST", path+"/exec", `{"revision":2,"argv":["echo"]}`, "", nil)
	if status != 410 {
		t.Fatal("closed session admitted work", status)
	}
}
