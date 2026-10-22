package guestwire

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func testRequest() Request {
	return Request{Version: Version, Operation: "exec", Ref: sandbox.Ref{ID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}, ExecutionID: strings.Repeat("c", 32), Argv: []string{"echo", "hello"}, TimeoutMS: 100, MaxOutputBytes: 1024}
}
func TestValidation(t *testing.T) {
	r := testRequest()
	if !r.Valid() {
		t.Fatal("valid request rejected")
	}
	for _, mutate := range []func(*Request){func(r *Request) { r.Version = 2 }, func(r *Request) { r.Ref.Generation = "stale" }, func(r *Request) { r.Operation = "shell" }, func(r *Request) { r.TimeoutMS = 60001 }, func(r *Request) { r.MaxOutputBytes = 0 }, func(r *Request) { r.Argv = []string{"echo", "null\x00"} }, func(r *Request) { r.Argv = []string{strings.Repeat("x", 32769)} }, func(r *Request) { r.ExecutionID = "../escape" }} {
		bad := r
		mutate(&bad)
		if bad.Valid() {
			t.Errorf("invalid request accepted: %+v", bad)
		}
	}
	health := Request{Version: Version, Operation: "health", Ref: r.Ref}
	if !health.Valid() {
		t.Fatal("valid health rejected")
	}
	health.Argv = []string{"echo"}
	if health.Valid() {
		t.Fatal("health carries execution fields")
	}
}
func TestFrames(t *testing.T) {
	r := testRequest()
	var frame bytes.Buffer
	if err := Write(&frame, MaxRequest, r); err != nil {
		t.Fatal(err)
	}
	var out Request
	if err := Read(&frame, MaxRequest, &out); err != nil || !out.Valid() || out.ExecutionID != r.ExecutionID {
		t.Fatalf("roundtrip: %+v %v", out, err)
	}
	for _, n := range []uint32{0, MaxRequest + 1, 0xffffffff} {
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], n)
		if err := Read(bytes.NewReader(h[:]), MaxRequest, &out); err == nil {
			t.Fatalf("unsafe frame length accepted: %d", n)
		}
	}
	if err := Read(bytes.NewReader([]byte{0, 0}), MaxRequest, &out); err == nil {
		t.Fatal("short header accepted")
	}
	if err := Write(io.Discard, 8, r); err == nil {
		t.Fatal("oversized write accepted")
	}
	var duplicate bytes.Buffer
	data := []byte(`{"version":1,"VERSION":2}`)
	binary.Write(&duplicate, binary.BigEndian, uint32(len(data)))
	duplicate.Write(data)
	if err := Read(&duplicate, MaxRequest, &out); err == nil {
		t.Fatal("duplicate fields accepted")
	}
}

type shortWriter struct{}

func (shortWriter) Write([]byte) (int, error) { return 0, nil }
func TestShortWrite(t *testing.T) {
	if err := Write(shortWriter{}, MaxRequest, testRequest()); err != io.ErrShortWrite {
		t.Fatalf("short write: %v", err)
	}
}

func TestValidArgvFitsEscapedFrame(t *testing.T) {
	r := testRequest()
	r.Argv = []string{"echo", strings.Repeat("\x01", 32768-len("echo"))}
	if !r.Valid() {
		t.Fatal("boundary argv rejected")
	}
	var frame bytes.Buffer
	if err := Write(&frame, MaxRequest, r); err != nil {
		t.Fatalf("valid request cannot fit its frame: %v", err)
	}
}

func FuzzRead(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Add([]byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxRequest+4 {
			t.Skip()
		}
		var out Request
		_ = Read(bytes.NewReader(data), MaxRequest, &out)
	})
}
