//go:build linux

package firecracker

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/123123213weqw/Xandbox/internal/guestwire"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRetryHonorsContextAndExitedSupervisor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := retry(ctx, nil, func() error { return errors.New("not ready") }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline not propagated: %v", err)
	}
	done := make(chan struct{})
	close(done)
	called := false
	if err := retry(context.Background(), done, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("readiness succeeded after supervisor exit")
	}
}

func TestFirecrackerAPIOnlyUsesUnixSocketAndRefusesRedirect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	mode := make(chan bool, 2)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || r.URL.Path != "/test" {
			t.Error("unexpected API operation")
		}
		if <-mode {
			w.WriteHeader(204)
		} else {
			w.Header().Set("Location", "http://127.0.0.1:1/escape")
			w.WriteHeader(307)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	mode <- true
	if err := apiPut(context.Background(), path, "/test", map[string]bool{"test": true}); err != nil {
		t.Fatal(err)
	}
	mode <- false
	if err := apiPut(context.Background(), path, "/test", map[string]bool{}); err == nil {
		t.Fatal("accepted redirected API")
	}
}

func TestOwnedCgroupProofRequiresExplicitEmpty(t *testing.T) {
	group := t.TempDir()
	events := filepath.Join(group, "cgroup.events")
	for _, text := range []string{"", "populated 1\n", "populated 01\n", "unknown 0\n"} {
		if err := os.WriteFile(events, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if emptyGroup(group) == nil {
			t.Fatal("accepted missing stop proof")
		}
	}
	if err := os.WriteFile(events, []byte("populated 0\nfrozen 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := emptyGroup(group); err != nil {
		t.Fatal(err)
	}
	if err := emptyGroup(filepath.Join(group, "absent")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(group, "missing", nil); err == nil {
		t.Fatal("driver initialized without required root policy")
	}
}

// Synthetic UDS/cgroup files only. A wire-valid completed response with the
// wrong initialization epoch must still take the host stop/fence path.
func TestDriverExecutionRequiresSealedSnapshotEpoch(t *testing.T) {
	for _, epoch := range []string{"matching", "different", "absent"} {
		t.Run(epoch, func(t *testing.T) {
			runtime, e := os.MkdirTemp("/tmp", "x")
			if e != nil {
				t.Fatal(e)
			}
			defer os.RemoveAll(runtime)
			ref := reference("1")
			k, _ := key(ref)
			cfg := policy()
			cfg.RuntimeRoot = runtime
			cfg.CgroupRoot = t.TempDir()
			root := filepath.Join(runtime, "j/firecracker", k, "root")
			if e = os.MkdirAll(root, 0700); e != nil {
				t.Fatal(e)
			}
			group := filepath.Join(cfg.CgroupRoot, k)
			if e = os.Mkdir(group, 0700); e != nil {
				t.Fatal(e)
			}
			for name, value := range map[string]string{"cgroup.events": "populated 0\n", "cgroup.kill": ""} {
				if e = os.WriteFile(filepath.Join(group, name), []byte(value), 0600); e != nil {
					t.Fatal(e)
				}
			}
			reader, writer, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			defer reader.Close()
			defer writer.Close()
			boot := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
			hash := strings.Repeat("a", 64)
			p := &process{bootID: boot, initializationHash: hash, slots: make(chan struct{}, 2), done: make(chan struct{}), life: writer}
			d := &driver{cfg: cfg, registry: &registry{owners: map[string]ownership{k: {Version: 1, Ref: ref, UID: cfg.UIDStart}}}, procs: map[string]*process{k: p}}
			l, e := net.Listen("unix", filepath.Join(root, "v.sock"))
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			served := make(chan struct{})
			go func() {
				defer close(served)
				defer close(p.done)
				c, err := l.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				r := bufio.NewReader(c)
				line, err := r.ReadString('\n')
				if err != nil || line != "CONNECT 900\n" {
					t.Error("invalid synthetic bridge request")
					return
				}
				fmt.Fprint(c, "OK 1234\n")
				var req guestwire.Request
				if err = guestwire.Read(r, guestwire.MaxRequest, &req); err != nil {
					t.Error(err)
					return
				}
				got := hash
				if epoch == "different" {
					got = strings.Repeat("b", 64)
				} else if epoch == "absent" {
					got = ""
				}
				if err = guestwire.Write(c, guestwire.MaxResponse, guestwire.Response{Version: 1, Ref: req.Ref, ExecutionID: req.ExecutionID, BootID: boot, InitializationHash: got, Status: "EXITED", Output: sandbox.Output{ExitCode: 0}}); err != nil {
					t.Error(err)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, e = d.Exec(ctx, ref, sandbox.ExecRequest{Generation: ref.Generation, Argv: []string{"true"}, TimeoutMS: 1000}, 4096)
			if epoch == "matching" && e != nil {
				t.Fatal(e)
			}
			if epoch != "matching" && !errors.Is(e, sandbox.ErrBackendFenced) {
				t.Fatal("unsealed epoch accepted", e)
			}
			<-served
			b, err := os.ReadFile(filepath.Join(group, "cgroup.kill"))
			if err != nil {
				t.Fatal(err)
			}
			if (epoch != "matching") != (string(b) == "1") {
				t.Fatal("wrong epoch did not stop host execution domain")
			}
		})
	}
}
