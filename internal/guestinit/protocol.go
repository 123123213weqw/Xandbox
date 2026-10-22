// Package guestinit defines a one-shot pristine-guest initialization protocol.
// It is not a tenant RPC, reset API, snapshot catalog, or normal execution wire.
package guestinit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/123123213weqw/Xandbox/internal/guestwire"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

const (
	Version     = 1
	Port        = 901
	MaxRequest  = 4096
	MaxResponse = 1024
	Waiting     = "WAITING"
	Claimed     = "CLAIMED"
	Failed      = "FAILED"
)

var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var bootPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Request struct {
	Version    int         `json:"version"`
	Operation  string      `json:"operation"`
	Ref        sandbox.Ref `json:"ref,omitempty"`
	Nonce      string      `json:"nonce,omitempty"`
	Entropy    []byte      `json:"entropy,omitempty"`
	BootID     string      `json:"boot_id,omitempty"`
	RealtimeNS int64       `json:"realtime_ns,omitempty"`
}

func (r Request) Valid() bool {
	if r.Version != Version {
		return false
	}
	if r.Operation == "state" {
		return r.Ref == (sandbox.Ref{}) && r.Nonce == "" && len(r.Entropy) == 0 && r.BootID == "" && r.RealtimeNS == 0
	}
	if r.Operation != "initialize" || !(guestwire.Request{Version: guestwire.Version, Operation: "health", Ref: r.Ref}).Valid() || !hashPattern.MatchString(r.Nonce) || len(r.Entropy) != 64 || !bootPattern.MatchString(r.BootID) || r.RealtimeNS < 1_577_836_800_000_000_000 || r.RealtimeNS > 4_102_444_800_000_000_000 {
		return false
	}
	var nonzero byte
	for _, b := range r.Entropy {
		nonzero |= b
	}
	return nonzero != 0
}

func (r Request) Digest() string {
	b, _ := json.Marshal(r)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func (r *Request) WipeEntropy() {
	for i := range r.Entropy {
		r.Entropy[i] = 0
	}
	r.Entropy = nil
}

// NewRequest is host-only policy: use fresh CSPRNG material for every new Ref.
// A retry must retain the exact request, never substitute a new nonce/seed.
func NewRequest(ref sandbox.Ref) (Request, error) {
	if !(guestwire.Request{Version: guestwire.Version, Operation: "health", Ref: ref}).Valid() {
		return Request{}, errors.New("invalid new guest identity")
	}
	r := Request{Version: Version, Operation: "initialize", Ref: ref, RealtimeNS: time.Now().UnixNano(), Entropy: make([]byte, 64)}
	var nonce [32]byte
	var boot [16]byte
	for _, b := range [][]byte{r.Entropy, nonce[:], boot[:]} {
		if _, e := rand.Read(b); e != nil {
			r.WipeEntropy()
			return Request{}, e
		}
	}
	boot[6] = (boot[6] & 15) | 64
	boot[8] = (boot[8] & 63) | 128
	r.Nonce = hex.EncodeToString(nonce[:])
	s := hex.EncodeToString(boot[:])
	r.BootID = s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
	return r, nil
}

// Receipt excludes entropy/nonce. Only a sealed guest-local root file may carry
// this record; it is not host ownership or an authorization credential.
type Receipt struct {
	Version int         `json:"version"`
	Ref     sandbox.Ref `json:"ref"`
	BootID  string      `json:"boot_id"`
	Digest  string      `json:"request_hash"`
}

func (r Receipt) Valid() bool {
	return r.Version == Version && (guestwire.Request{Version: guestwire.Version, Operation: "health", Ref: r.Ref}).Valid() && bootPattern.MatchString(r.BootID) && hashPattern.MatchString(r.Digest)
}

type Response struct {
	Version int    `json:"version"`
	Phase   string `json:"phase"`
	Digest  string `json:"request_hash,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (r Response) Valid() bool {
	if r.Version != Version {
		return false
	}
	switch r.Phase {
	case Waiting:
		return r.Digest == "" && r.Error == ""
	case Claimed:
		return hashPattern.MatchString(r.Digest) && r.Error == ""
	case Failed:
		return hashPattern.MatchString(r.Digest) && r.Error == "initialization failed"
	}
	return false
}
