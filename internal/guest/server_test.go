package guest

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/guestwire"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

type fakeRunner struct {
	calls   atomic.Int32
	wait    bool
	entered chan struct{}
}

type observedRunner struct {
	fakeRunner
	groups  int
	failure bool
}

func (f *observedRunner) ActiveGroups() (int, error) {
	if f.failure {
		return 0, errors.New("private-error-do-not-echo")
	}
	return f.groups, nil
}
func TestHealthObservesKernelGroups(t *testing.T) {
	for _, failure := range []bool{false, true} {
		r := request()
		r.Operation = "health"
		r.ExecutionID = ""
		r.Argv = nil
		r.TimeoutMS = 0
		r.MaxOutputBytes = 0
		runner := &observedRunner{groups: 2, failure: failure}
		s := Server{Ref: r.Ref, Runner: runner}
		client, conn := net.Pipe()
		go s.ServeConn(conn, true)
		if err := guestwire.Write(client, guestwire.MaxRequest, r); err != nil {
			t.Fatal(err)
		}
		var response guestwire.Response
		if err := guestwire.Read(client, guestwire.MaxResponse, &response); err != nil {
			t.Fatal(err)
		}
		client.Close()
		if failure {
			if response.Status != "FAILED" || strings.Contains(response.Error, "private-error") {
				t.Fatalf("unsafe health error: %+v", response)
			}
		} else if response.ActiveGroups == nil || *response.ActiveGroups != 2 || response.Status != "READY" {
			t.Fatalf("missing kernel observation: %+v", response)
		}
		if runner.calls.Load() != 0 {
			t.Fatal("health ran a command")
		}
	}
}

func (f *fakeRunner) Run(ctx context.Context, _ guestwire.Request) (sandbox.Output, error) {
	f.calls.Add(1)
	if f.entered != nil {
		close(f.entered)
	}
	if f.wait {
		<-ctx.Done()
		return sandbox.Output{ExitCode: -1}, ctx.Err()
	}
	return sandbox.Output{Stdout: "fake-guest-output"}, nil
}
func request() guestwire.Request {
	return guestwire.Request{Version: 1, Operation: "exec", Ref: sandbox.Ref{ID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}, ExecutionID: strings.Repeat("c", 32), Argv: []string{"echo"}, TimeoutMS: 30, MaxOutputBytes: 1024}
}

func TestServerIdentityAndTimeout(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "exit", true: "timeout"}[timeout], func(t *testing.T) {
			r := request()
			runner := &fakeRunner{wait: timeout}
			server := Server{Ref: r.Ref, BootID: "test-boot", Runner: runner}
			client, conn := net.Pipe()
			defer client.Close()
			done := make(chan struct{})
			go func() { defer close(done); server.ServeConn(conn, true) }()
			if err := guestwire.Write(client, guestwire.MaxRequest, r); err != nil {
				t.Fatal(err)
			}
			var response guestwire.Response
			if err := guestwire.Read(client, guestwire.MaxResponse, &response); err != nil {
				t.Fatal(err)
			}
			want := "EXITED"
			if timeout {
				want = "TIMED_OUT"
			}
			if response.Status != want || response.Ref != r.Ref || runner.calls.Load() != 1 {
				t.Fatalf("response: %+v", response)
			}
			<-done
		})
	}
}

func TestServerRejectsUntrustedPeerAndGeneration(t *testing.T) {
	for _, badPeer := range []bool{false, true} {
		r := request()
		runner := &fakeRunner{}
		server := Server{Ref: r.Ref, Runner: runner}
		if !badPeer {
			r.Ref.Generation = strings.Repeat("d", 32)
		}
		client, conn := net.Pipe()
		go server.ServeConn(conn, !badPeer)
		client.SetDeadline(time.Now().Add(time.Second))
		_ = guestwire.Write(client, guestwire.MaxRequest, r)
		var response guestwire.Response
		if err := guestwire.Read(client, guestwire.MaxResponse, &response); err == nil {
			t.Fatal("untrusted request received a response")
		}
		client.Close()
		if runner.calls.Load() != 0 {
			t.Fatal("untrusted request executed")
		}
	}
}

func TestDisconnectCancelsGuestExecution(t *testing.T) {
	r := request()
	r.TimeoutMS = 60_000
	runner := &fakeRunner{wait: true, entered: make(chan struct{})}
	server := Server{Ref: r.Ref, Runner: runner}
	client, conn := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); server.ServeConn(conn, true) }()
	if err := guestwire.Write(client, guestwire.MaxRequest, r); err != nil {
		t.Fatal(err)
	}
	<-runner.entered
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("disconnected execution did not drain")
	}
}
