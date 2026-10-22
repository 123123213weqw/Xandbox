package guestinit

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/guestwire"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func testRequest() Request {
	return Request{Version: Version, Operation: "initialize", Ref: sandbox.Ref{ID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}, Nonce: strings.Repeat("c", 64), Entropy: bytes.Repeat([]byte{0x42}, 64), BootID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", RealtimeNS: 1_792_600_000_000_000_000}
}
func exchange(g *Gate, r Request) (Response, error) {
	client, server := net.Pipe()
	defer client.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	go g.ServeConn(server, true)
	if e := guestwire.Write(client, MaxRequest, r); e != nil {
		return Response{}, e
	}
	var out Response
	e := guestwire.Read(client, MaxResponse, &out)
	return out, e
}
func TestSingleClaimConcurrentReplayAndUnrelatedRequest(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	g := New(func(r Request) error {
		calls.Add(1)
		close(entered)
		<-release
		return errors.New("private failure never echo")
	})
	r := testRequest()
	out, e := exchange(g, r)
	if e != nil || out.Phase != Claimed || out.Digest != r.Digest() {
		t.Fatal("initial claim", e)
	}
	<-entered
	var wg sync.WaitGroup
	for n := range 32 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			copy := r
			if n%2 == 1 {
				copy.Nonce = strings.Repeat("d", 64)
			}
			out, e := exchange(g, copy)
			if e != nil || out.Phase != Claimed || out.Digest != r.Digest() {
				t.Error("claim changed or blocked", e)
			}
		}(n)
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("initializer ran more than once")
	}
	state, e := exchange(g, Request{Version: Version, Operation: "state"})
	if e != nil || state.Phase != Claimed || !state.Valid() {
		t.Fatal("state blocked while initializer in progress")
	}
}
func TestLostAcknowledgementAndFailedHandoffNeverReopen(t *testing.T) {
	var calls atomic.Int32
	var captured []byte
	g := New(func(r Request) error { calls.Add(1); captured = r.Entropy; return errors.New("private-inner-path") })
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { g.ServeConn(server, true); close(done) }()
	r := testRequest()
	if e := guestwire.Write(client, MaxRequest, r); e != nil {
		t.Fatal(e)
	}
	client.Close()
	<-done
	if calls.Load() != 1 || !bytes.Equal(captured, make([]byte, 64)) {
		t.Fatal("lost ACK rolled back claim or entropy not cleared")
	}
	r.Nonce = strings.Repeat("e", 64)
	out, e := exchange(g, r)
	if e != nil || out.Phase != Failed || out.Error != "initialization failed" || calls.Load() != 1 || strings.Contains(out.Error, "private") {
		t.Fatal("failed handoff reopened or leaked private error")
	}
}
func TestUntrustedPeerAndExecutionPayloadNeverInitialize(t *testing.T) {
	var calls atomic.Int32
	g := New(func(Request) error { calls.Add(1); return nil })
	for _, peer := range []bool{false, true} {
		client, server := net.Pipe()
		client.SetDeadline(time.Now().Add(time.Second))
		go g.ServeConn(server, peer)
		r := testRequest()
		if peer {
			r.Operation = "exec"
		}
		_ = guestwire.Write(client, MaxRequest, r)
		var out Response
		if guestwire.Read(client, MaxResponse, &out) == nil {
			t.Fatal("unsafe request accepted")
		}
		client.Close()
	}
	if calls.Load() != 0 {
		t.Fatal("untrusted initialization applied")
	}
}
func TestRequestValidationGenerationAndWiping(t *testing.T) {
	r := testRequest()
	if !r.Valid() {
		t.Fatal("fixture invalid")
	}
	for _, mutate := range []func(*Request){func(r *Request) { r.Version = 2 }, func(r *Request) { r.Ref.ID = "../escape" }, func(r *Request) { r.Nonce = "short" }, func(r *Request) { r.Entropy = make([]byte, 64) }, func(r *Request) { r.Entropy = r.Entropy[:63] }, func(r *Request) { r.BootID = "duplicate" }, func(r *Request) { r.RealtimeNS = 0 }, func(r *Request) { r.Operation = "exec" }} {
		copy := r
		mutate(&copy)
		if copy.Valid() {
			t.Fatal("invalid request accepted")
		}
	}
	state := Request{Version: Version, Operation: "state"}
	if !state.Valid() {
		t.Fatal("state invalid")
	}
	state.Ref = r.Ref
	if state.Valid() {
		t.Fatal("state carries identity")
	}
	a, e := NewRequest(r.Ref)
	if e != nil || !a.Valid() {
		t.Fatal("new request invalid", e)
	}
	b, e := NewRequest(r.Ref)
	if e != nil || a.Nonce == b.Nonce || a.BootID == b.BootID || bytes.Equal(a.Entropy, b.Entropy) {
		t.Fatal("fresh epoch duplicated", e)
	}
	if a.Digest() != a.Digest() || a.Digest() == b.Digest() {
		t.Fatal("digest not request-bound")
	}
	seed := a.Entropy
	a.WipeEntropy()
	b.WipeEntropy()
	if !bytes.Equal(seed, make([]byte, 64)) {
		t.Fatal("entropy not zeroed")
	}
	if _, e = NewRequest(sandbox.Ref{}); e == nil {
		t.Fatal("invalid host Ref accepted")
	}
}
func FuzzBootstrapDecoder(f *testing.F) {
	f.Add([]byte(`{"version":1,"operation":"state"}`))
	f.Add([]byte(`{"version":1,"VERSION":2}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var framed bytes.Buffer
		header := []byte{byte(len(b) >> 24), byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}
		framed.Write(header)
		framed.Write(b)
		var req Request
		if guestwire.Read(&framed, MaxRequest, &req) == nil && req.Valid() {
			if len(req.Digest()) != 64 {
				t.Fatal("bad digest")
			}
		}
		req.WipeEntropy()
	})
}
