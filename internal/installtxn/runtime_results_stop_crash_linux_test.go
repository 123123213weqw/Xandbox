//go:build linux

package installtxn

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Owned TEST coordinator; only its parent kills/reaps the two original helpers.
// Manager/image/cgroup positives remain models; no systemctl/VM/quota actions.
func TestRuntimeResultsStopOwnedHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_RESULTS_STOP_ROOT")
	if root == "" {
		t.Skip("owned coordinator only")
	}
	if !filepath.IsAbs(root) {
		t.Fatal("absolute private TEST root required")
	}
	var st unix.Stat_t
	if unix.Lstat(root, &st) != nil || st.Mode != unix.S_IFDIR|0700 || st.Uid != uint32(os.Geteuid()) {
		t.Fatal("owned private TEST root required")
	}
	mainPID, e := strconv.Atoi(os.Getenv("XANDBOX_RESULTS_STOP_MAIN"))
	if e != nil || mainPID <= 1 {
		os.Exit(71)
	}
	ingressPID, e := strconv.Atoi(os.Getenv("XANDBOX_RESULTS_STOP_INGRESS"))
	if e != nil || ingressPID <= 1 {
		os.Exit(72)
	}
	dir, e := os.Open(root)
	if e != nil {
		os.Exit(73)
	}
	f := &filesystem{root: dir, hook: func(at string) error {
		if at == os.Getenv("XANDBOX_RESULTS_STOP_CUT") {
			_ = unix.Kill(os.Getpid(), unix.SIGKILL)
			select {}
		}
		return nil
	}}
	c, e := nodecontrol.NewPinnedClient(root+stateDir, mainPID)
	if e != nil {
		os.Exit(74)
	}
	reader := bufio.NewScanner(os.Stdin)
	reader.Buffer(make([]byte, 4096), 32768)
	m := systemManager{f, func(_ context.Context, args []string) ([]byte, error) {
		if json.NewEncoder(os.Stdout).Encode(args) != nil || !reader.Scan() {
			return nil, interrupted
		}
		var r stopManagerReply
		if json.Unmarshal(reader.Bytes(), &r) != nil || r.Failed {
			return nil, interrupted
		}
		return r.Data, nil
	}}
	proof := runtimeStopProofs{
		process: func(_ context.Context, _ transaction, unit string, id nodecontrol.ProcessIdentity) error {
			want := mainPID
			if unit == IngressUnit {
				want = ingressPID
			}
			if id.PID != want {
				return ErrConflict
			}
			return nil
		},
		empty: func(unit string) error {
			d, e := f.directory(ingressCgroupParent + "/" + unit)
			if e != nil {
				return e
			}
			defer d.Close()
			return proveIngressSubtree(d, func(int) error { return nil })
		},
	}
	s, e := f.beginRuntimeScope(context.Background())
	if e != nil {
		os.Exit(75)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, e = s.finishCloseAndStopResultsWithProofs(ctx, os.Getenv("XANDBOX_RESULTS_STOP_BASE"), runtimeReq("b"), c, m, proof); e != nil {
		os.Exit(76)
	}
	os.Exit(77) // The required owned SIGKILL cut was not reached.
}
func TestRuntimeResultsStopActualCoordinatorSIGKILLKeepsKnownClosureAndOriginalState(t *testing.T) {
	for _, cut := range []string{"runtime-results-stop-intent-durable", "runtime-results-stop-after-" + IngressUnit, "runtime-results-stop-after-" + MainUnit, "runtime-results-stop-receipt-renamed", "runtime-results-state-locked"} {
		t.Run(cut, func(t *testing.T) {
			x, s := resultsWALModel(t, "retained")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if _, e := finishResultsWAL(ctx, x, s); e != nil {
				t.Fatal(e)
			}
			s.close()
			protected := runtimeProtectedBytes(t, x.f, x.tx)
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRuntimeResultsStopOwnedHelper$")
			cmd.Env = []string{"GOMAXPROCS=2", "GOMEMLIMIT=512MiB", "XANDBOX_RESULTS_STOP_ROOT=" + x.f.root.Name(), "XANDBOX_RESULTS_STOP_MAIN=" + strconv.Itoa(x.children[MainUnit].Process.Pid), "XANDBOX_RESULTS_STOP_INGRESS=" + strconv.Itoa(x.children[IngressUnit].Process.Pid), "XANDBOX_RESULTS_STOP_BASE=" + digest(encode(x.tx)), "XANDBOX_RESULTS_STOP_CUT=" + cut}
			in, e := cmd.StdinPipe()
			if e != nil {
				t.Fatal(e)
			}
			out, e := cmd.StdoutPipe()
			if e != nil {
				t.Fatal(e)
			}
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() {
				in.Close()
				out.Close()
				if cmd.ProcessState == nil {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			})
			served := make(chan error, 1)
			go func() {
				scanner := bufio.NewScanner(out)
				scanner.Buffer(make([]byte, 4096), 32768)
				for scanner.Scan() {
					var a []string
					if json.Unmarshal(scanner.Bytes(), &a) != nil || len(a) < 1 || len(a) > 8 {
						served <- ErrPolicy
						return
					}
					data, e := x.manager.command(ctx, a)
					if e := json.NewEncoder(in).Encode(stopManagerReply{Data: data, Failed: e != nil}); e != nil {
						served <- e
						return
					}
				}
				served <- scanner.Err()
			}()
			serveErr := <-served
			if serveErr != nil {
				_ = cmd.Process.Kill()
			}
			e = cmd.Wait()
			in.Close()
			out.Close()
			var exited *exec.ExitError
			if !errors.As(e, &exited) {
				t.Fatal("coordinator not killed", e, serveErr)
			}
			status, ok := exited.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL || serveErr != nil {
				t.Fatal("not owned SIGKILL", e, serveErr)
			}
			s = x.scope(t)
			if !x.alive[MainUnit] {
				x.client = nil
			}
			p, e := stopResultsModel(ctx, x, s)
			if e != nil || p == nil || s.state == nil || !reflect.DeepEqual(x.jobs, []string{IngressUnit, MainUnit}) {
				t.Fatal(p, e, x.jobs)
			}
			if _, e = s.resultsStoppedWorkReceiptWithProof(ctx, digest(encode(x.tx)), runtimeReq("b"), p, x.manager, x.proof.empty); e != nil {
				t.Fatal(e)
			}
			unchangedRuntimeProtected(t, x.f, protected)
		})
	}
}
