// Package access authenticates high-entropy bearer tokens using stored digests.
package access

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

var ErrUnauthorized = errors.New("authentication required")

type Key struct {
	TokenSHA256  string `json:"token_sha256"`
	TenantID     string `json:"tenant_id"`
	MaxInstances int    `json:"max_instances"`
}

type Config struct {
	Version int   `json:"version"`
	Keys    []Key `json:"keys"`
}

type entry struct {
	digest [32]byte
	owner  sandbox.Owner
}

type Authenticator struct{ entries []entry }

func Load(path string) (*Authenticator, error) {
	data, err := privatefile.Read(path, 65_536)
	if err != nil {
		return nil, err
	}
	var config Config
	if err := strictjson.Decode(data, &config); err != nil {
		// Do not echo JSON keys or values from a credential configuration.
		return nil, errors.New("invalid authentication configuration JSON")
	}
	return New(config)
}

func New(config Config) (*Authenticator, error) {
	if config.Version != 1 || len(config.Keys) == 0 || len(config.Keys) > 256 {
		return nil, errors.New("authentication configuration requires version 1 and 1..256 keys")
	}
	a := &Authenticator{}
	digests := make(map[string]bool)
	quotas := make(map[string]int)
	for _, key := range config.Keys {
		owner := sandbox.Owner{TenantID: key.TenantID, MaxInstances: key.MaxInstances}
		if !owner.Valid() || len(key.TokenSHA256) != 64 {
			return nil, errors.New("invalid authentication identity, quota, or digest")
		}
		digest, err := hex.DecodeString(key.TokenSHA256)
		if err != nil || key.TokenSHA256 != strings.ToLower(key.TokenSHA256) || digests[key.TokenSHA256] {
			return nil, errors.New("invalid or duplicate authentication digest")
		}
		if previous, ok := quotas[key.TenantID]; ok && previous != key.MaxInstances {
			return nil, errors.New("all keys for one tenant must have the same quota")
		}
		quotas[key.TenantID], digests[key.TokenSHA256] = key.MaxInstances, true
		e := entry{owner: owner}
		copy(e.digest[:], digest)
		a.entries = append(a.entries, e)
	}
	return a, nil
}

func (a *Authenticator) Authenticate(header string) (sandbox.Owner, error) {
	if len(header) > 520 || !strings.HasPrefix(header, "Bearer ") {
		return sandbox.Owner{}, ErrUnauthorized
	}
	token := strings.TrimPrefix(header, "Bearer ")
	if len(token) < 32 || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return sandbox.Owner{}, ErrUnauthorized
	}
	digest := sha256.Sum256([]byte(token))
	var owner sandbox.Owner
	matched := false
	for _, e := range a.entries {
		if subtle.ConstantTimeCompare(digest[:], e.digest[:]) == 1 {
			owner, matched = e.owner, true
		}
	}
	if !matched {
		return sandbox.Owner{}, ErrUnauthorized
	}
	return owner, nil
}
