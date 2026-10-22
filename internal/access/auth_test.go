package access

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(token, tenant string, quota int) Key {
	sum := sha256.Sum256([]byte(token))
	return Key{TokenSHA256: hex.EncodeToString(sum[:]), TenantID: tenant, MaxInstances: quota}
}

func TestAuthenticateAndRotation(t *testing.T) {
	aToken, bToken := strings.Repeat("a", 40), strings.Repeat("b", 40)
	a, err := New(Config{Version: 1, Keys: []Key{testKey(aToken, "alpha", 2), testKey(bToken, "alpha", 2)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{aToken, bToken} {
		owner, err := a.Authenticate("Bearer " + token)
		if err != nil || owner.TenantID != "alpha" || owner.MaxInstances != 2 {
			t.Fatalf("authentication: %+v %v", owner, err)
		}
	}
	for _, header := range []string{"", aToken, "Basic " + aToken, "Bearer short", "Bearer " + strings.Repeat("c", 40), "Bearer " + aToken + "\t", "Bearer " + strings.Repeat("x", 600)} {
		if _, err := a.Authenticate(header); !errors.Is(err, ErrUnauthorized) || strings.Contains(err.Error(), aToken) {
			t.Fatalf("failure not generic: %v", err)
		}
	}
}

func TestInvalidConfig(t *testing.T) {
	key := testKey(strings.Repeat("a", 40), "alpha", 2)
	for _, config := range []Config{
		{}, {Version: 2, Keys: []Key{key}}, {Version: 1},
		{Version: 1, Keys: []Key{key, key}},
		{Version: 1, Keys: []Key{key, testKey(strings.Repeat("b", 40), "alpha", 3)}},
		{Version: 1, Keys: []Key{testKey("x", "../escape", 1)}},
		{Version: 1, Keys: []Key{testKey("x", "alpha", 0)}},
		{Version: 1, Keys: []Key{{TokenSHA256: "bad", TenantID: "alpha", MaxInstances: 1}}},
	} {
		if _, err := New(config); err == nil {
			t.Errorf("accepted invalid config: %+v", config)
		}
	}
}

func TestLoadPrivateConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	data, _ := json.Marshal(Config{Version: 1, Keys: []Key{testKey(strings.Repeat("a", 40), "alpha", 2)}})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("nonprivate config accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"secret-do-not-echo":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || strings.Contains(err.Error(), "secret-do-not-echo") {
		t.Fatalf("unsafe parse error: %v", err)
	}
}
