//go:build linux

package installtxn

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"golang.org/x/sys/unix"
)

type stopManagerReply struct {
	Data   []byte `json:"data"`
	Failed bool   `json:"failed"`
}

// Test-only coordinator. Manager commands travel over its inherited bounded
// pipe protocol to the parent: ONLY the parent terminates/reaps its own helpers.
// Image/placement/cgroups are explicit models; no systemctl/VMM is executed.
func TestRuntimeStopCrashHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_TEST_STOP_CRASH_ROOT")
	if root == "" {
		return
	}
	mainPID, e := strconv.Atoi(os.Getenv("XANDBOX_TEST_STOP_MAIN"))
	if e != nil {
		os.Exit(71)
	}
	ingressPID, e := strconv.Atoi(os.Getenv("XANDBOX_TEST_STOP_INGRESS"))
	if e != nil {
		os.Exit(72)
	}
	dir, e := os.Open(root)
	if e != nil {
		os.Exit(73)
	}
	f := &filesystem{root: dir, hook: func(at string) error {
		if at == os.Getenv("XANDBOX_TEST_STOP_CRASH_CUT") {
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
	if os.Getenv("XANDBOX_TEST_FINISH_STOP") == "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, e = s.finishAndStopWithProofs(ctx, os.Getenv("XANDBOX_TEST_STOP_BASE"), runtimeReq("b"), c, m, proof)
	} else {
		_, e = s.stopWithProofs(context.Background(), os.Getenv("XANDBOX_TEST_STOP_BASE"), runtimeReq("b"), c, m, proof)
	}
	if e == nil && os.Getenv("XANDBOX_TEST_FINISH_STOP") != "1" && os.Getenv("XANDBOX_TEST_STOP_CRASH_CUT") == "runtime-state-locked" {
		e = s.ownStoppedStateWithProof(context.Background(), os.Getenv("XANDBOX_TEST_STOP_BASE"), runtimeReq("b"), m, proof.empty)
	}
	if e != nil {
		os.Exit(76)
	}
	os.Exit(0)
}
func TestRuntimeStopActualCoordinatorSIGKILLRecoversAfterOperatorDeath(t *testing.T) {
	runRuntimeStopCrashRecovery(t, nil, []string{"runtime-stop-intent-durable", "runtime-stop-after-" + IngressUnit, "runtime-stop-after-" + MainUnit, "runtime-stop-receipt-renamed", "runtime-state-locked"})
}
func runRuntimeStopCrashRecovery(t *testing.T, prepare func(*stopTestModel, *runtimeScope), cuts []string) {
	runRuntimeStopCrashRecoveryMode(t, prepare, cuts, false)
}
func runRuntimeStopCrashRecoveryMode(t *testing.T, prepare func(*stopTestModel, *runtimeScope), cuts []string, finish bool) {
	for _, cut := range cuts {
		t.Run(cut, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			if prepare == nil {
				x.drain(t, s)
			} else {
				prepare(x, s)
			}
			s.close()
			before := runtimeProtectedBytes(t, x.f, x.tx)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRuntimeStopCrashHelper$")
			cmd.Env = []string{"GOMAXPROCS=2", "XANDBOX_TEST_STOP_CRASH_ROOT=" + x.f.root.Name(), "XANDBOX_TEST_STOP_MAIN=" + strconv.Itoa(x.children[MainUnit].Process.Pid), "XANDBOX_TEST_STOP_INGRESS=" + strconv.Itoa(x.children[IngressUnit].Process.Pid), "XANDBOX_TEST_STOP_CRASH_CUT=" + cut, "XANDBOX_TEST_STOP_BASE=" + digest(encode(x.tx))}
			if finish {
				cmd.Env = append(cmd.Env, "XANDBOX_TEST_FINISH_STOP=1")
			}
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
			served := make(chan error, 1)
			go func() {
				scanner := bufio.NewScanner(out)
				scanner.Buffer(make([]byte, 4096), 32768)
				for scanner.Scan() {
					var args []string
					if json.Unmarshal(scanner.Bytes(), &args) != nil || len(args) < 1 || len(args) > 8 {
						served <- ErrPolicy
						return
					}
					data, e := x.manager.command(ctx, args)
					if err := json.NewEncoder(in).Encode(stopManagerReply{Data: data, Failed: e != nil}); err != nil {
						served <- err
						return
					}
				}
				served <- scanner.Err()
			}()
			// Drain the inherited protocol to EOF BEFORE Wait closes StdoutPipe.
			serveErr := <-served
			if serveErr != nil {
				_ = cmd.Process.Kill()
			} // Only this owned coordinator.
			e = cmd.Wait()
			in.Close()
			out.Close()
			var exited *exec.ExitError
			if !errors.As(e, &exited) {
				t.Fatal("coordinator did not die", e, serveErr)
			}
			status, ok := exited.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("not actual coordinator SIGKILL", e, serveErr)
			}
			if serveErr != nil {
				t.Fatal("manager model transport failed", serveErr)
			}
			fresh, e := os.Open(x.f.root.Name())
			if e != nil {
				t.Fatal(e)
			}
			defer fresh.Close()
			x.f = &filesystem{root: fresh}
			x.manager.fs = x.f
			s = x.scope(t)
			client := x.client
			if !x.alive[MainUnit] {
				client = nil
			}
			var r runtimeStopResult
			if finish {
				p, err := s.finishAndStopWithProofs(ctx, digest(encode(x.tx)), runtimeReq("b"), client, x.manager, x.proof)
				e = err
				if p == nil || s.state == nil {
					t.Fatal("composed recovery lost known work/state", p, e)
				}
				r.ExecutionStopped = true
			} else {
				r, e = x.stop(ctx, s, client)
			}
			if e != nil || !r.ExecutionStopped || r.ResourcesReclaimed || r.ActivationAllowed || len(x.jobs) != 2 {
				t.Fatal("fresh coordinator recovery", r, e, x.jobs)
			}
			if cut == "runtime-state-locked" || finish {
				if e = ownStateModel(ctx, x, s); e != nil {
					t.Fatal("kernel did not release dead coordinator state lock", e)
				}
				other, e := x.f.openRuntimeState()
				if e != nil {
					t.Fatal(e)
				}
				if e = acquireRuntimeState(other); !errors.Is(e, unix.EWOULDBLOCK) {
					other.close()
					t.Fatal("fresh scope did not retain original lease", e)
				}
				other.close()
			}
			unchangedRuntimeProtected(t, x.f, before)
			if _, e = x.f.startupFilesLocked(ctx); e == nil {
				t.Fatal("abrupt stop recovery unfenced startup")
			}
		})
	}
}
