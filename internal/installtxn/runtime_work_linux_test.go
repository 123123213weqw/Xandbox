//go:build linux

package installtxn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"golang.org/x/sys/unix"
)

func quiesceModel(ctx context.Context, x *stopTestModel, s *runtimeScope) (*runtimeAcceptedWorkProof, error) {
	return s.quiesceAcceptedWorkWithProof(ctx, digest(encode(x.tx)), runtimeReq("b"), x.client, x.manager, x.proof.process)
}
func TestRuntimeWorkRequiresOriginalV2ReadyOwnerBoundedContextAndHeldScope(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	if p, e := quiesceModel(context.Background(), x, s); p != nil || !errors.Is(e, ErrPolicy) {
		t.Fatal(p, e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if p, e := quiesceModel(ctx, x, s); p != nil || e == nil {
		t.Fatal("missing WAL accepted", p, e)
	}
	x.drain(t, s)
	if p, e := quiesceModel(ctx, x, s); p != nil || !errors.Is(e, ErrConflict) {
		t.Fatal("v1 ordinary drain adopted", p, e)
	}
}
func TestRuntimeWorkOpaqueProofHasOriginalScopeWALAndIncarnationNotReclaim(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	x.maintain(t, s)
	protected := runtimeProtectedBytes(t, x.f, x.tx)
	p, e := x.f.runtimeDrainReadIntent()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	proofCalls := 0
	process := func(ctx context.Context, tx transaction, unit string, id nodecontrol.ProcessIdentity) error {
		proofCalls++
		lock, e := x.f.existingLock(ctx, true)
		if e != nil {
			return e
		}
		lock()
		bounded, done := context.WithTimeout(ctx, 10*time.Millisecond)
		defer done()
		if free, e := x.f.operationLock(bounded, false); e == nil {
			free()
			return ErrConflict
		} else if !errors.Is(e, context.DeadlineExceeded) {
			return e
		}
		return x.proof.process(ctx, tx, unit, id)
	}
	proof, e := s.quiesceAcceptedWorkWithProof(ctx, p.Base, p.Request, x.client, x.manager, process)
	if e != nil || proof == nil || proof.scope != s || proof.intent != digest(encode(p)) || proof.process != p.Process || proof.record != *p.Maintenance || !proof.terminal.Complete() || proofCalls != 2 {
		t.Fatal(proof, e, proofCalls)
	}
	if len(x.jobs) != 0 || s.state != nil {
		t.Fatal("finish-only stage issued Stop/acquired daemon state")
	}
	if _, e = x.f.startupFilesLocked(ctx); !errors.Is(e, ErrInventory) {
		t.Fatal("work success bypassed startup fence", e)
	}
	unchangedRuntimeProtected(t, x.f, protected)
}
func TestRuntimeWorkCutsNeverPersistSuccessAndSameLiveOwnerCanRetry(t *testing.T) {
	for _, cut := range []string{"runtime-work-before-freeze", "runtime-work-after-terminal"} {
		t.Run(cut, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			x.maintain(t, s)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			hit := false
			x.f.hook = func(at string) error {
				if at == cut {
					hit = true
					return interrupted
				}
				return nil
			}
			if p, e := quiesceModel(ctx, x, s); p != nil || !errors.Is(e, interrupted) || !hit {
				t.Fatal(p, e)
			}
			x.f.hook = nil
			p, e := quiesceModel(ctx, x, s)
			if e != nil || p == nil || !p.terminal.Complete() {
				t.Fatal(p, e)
			}
			names, e := x.f.names(runtimeDrainRoot)
			if e != nil || len(names) != 2 {
				t.Fatal("work certificate persisted", names, e)
			}
			if len(x.jobs) != 0 {
				t.Fatal("retry issued Stop")
			}
		})
	}
}
func TestRuntimeWorkAuthorityChangedAfterTerminalRefusesProof(t *testing.T) {
	for _, kind := range []string{"wal", "installed", "manager", "peer-death"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			x.maintain(t, s)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			hit := false
			x.f.hook = func(at string) error {
				if at != "runtime-work-after-terminal" {
					return nil
				}
				hit = true
				switch kind {
				case "wal":
					return os.WriteFile(x.f.root.Name()+runtimeDrainRoot+"/drain.json", []byte("{}"), 0600)
				case "installed":
					return os.WriteFile(x.f.root.Name()+rolePath("daemon"), []byte("changed"), 0755)
				case "manager":
					x.alive[MainUnit] = false
				case "peer-death":
					if e := x.children[MainUnit].Process.Kill(); e != nil {
						return e
					}
					if e := x.children[MainUnit].Wait(); e == nil {
						return ErrConflict
					}
					x.alive[MainUnit] = false
				}
				return nil
			}
			if proof, e := quiesceModel(ctx, x, s); proof != nil || e == nil || !hit {
				t.Fatal("changed authority certified", proof, e)
			}
			if len(x.jobs) != 0 {
				t.Fatal("failure issued manager mutation")
			}
		})
	}
}

// A test ELF hosts real Core execution and admission/terminal paths, the real
// private node endpoint and ORIGINAL BSD lock. Its mock-backed command cannot
// launch a host shell/VM. Only the parent's owned stdin releases the test call.
type workHelperDriver struct {
	sandbox.Driver
	release  <-chan struct{}
	exitCode int
}

func (d *workHelperDriver) Exec(context.Context, sandbox.Ref, sandbox.ExecRequest, int) (sandbox.Output, error) {
	<-d.release
	return sandbox.Output{ExitCode: d.exitCode}, nil
}
func TestRuntimeWorkOperatorHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_TEST_WORK_ROOT")
	if root == "" {
		return
	}
	lock, e := os.OpenFile(root+stateDir+"/controller.lock", os.O_RDWR|unix.O_NOFOLLOW, 0)
	if e != nil {
		os.Exit(71)
	}
	defer lock.Close()
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		os.Exit(72)
	}
	f, e := nodecontrol.OpenStore(root + stateDir)
	if e != nil {
		os.Exit(73)
	}
	g := sandbox.NewAdmissionGate(false)
	c, e := nodecontrol.New(f, g)
	if e != nil {
		os.Exit(74)
	}
	ledger, e := sandbox.NewFileStore(root + stateDir + "/ledger")
	if e != nil {
		os.Exit(75)
	}
	d, e := sandbox.NewMockDriver(root + stateDir + "/instances")
	if e != nil {
		os.Exit(76)
	}
	release := make(chan struct{})
	controlled := &workHelperDriver{Driver: d, release: release}
	if os.Getenv("XANDBOX_TEST_WORK_RESULT") == "failed" {
		controlled.exitCode = 9
	}
	core, e := sandbox.NewManager(ledger, controlled, sandbox.Options{AdmissionGate: g})
	if e != nil {
		os.Exit(77)
	}
	r, e := core.Create(context.Background(), sandbox.CreateRequest{})
	if e != nil {
		os.Exit(78)
	}
	if _, e = core.Exec(r.ID, sandbox.ExecRequest{Generation: r.Generation, Argv: []string{"controlled-test-call"}}); e != nil {
		os.Exit(79)
	}

	journal, e := session.NewFileStore(root + stateDir + "/sessions")
	if e != nil {
		os.Exit(81)
	}
	broker, e := session.New(core, journal, session.Options{RetryInterval: time.Millisecond})
	if e != nil {
		os.Exit(82)
	}
	if c.AttachRuntime(core, broker) != nil {
		os.Exit(83)
	}
	server, e := nodecontrol.Start(root+stateDir, c, core.Stats)
	if e != nil {
		os.Exit(80)
	}
	fmt.Println("READY")
	input := bufio.NewReader(os.Stdin)
	_, _ = input.ReadString('\n')
	close(release)
	fmt.Println("RELEASED")
	_, _ = input.ReadString('\n')
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = server.Close(ctx)
	_ = core.Close(ctx)
}
func runtimeWorkChild(t *testing.T, x *stopTestModel, outcome string) (io.WriteCloser, *bufio.Reader) {
	t.Helper()
	// Replace ONLY the initial owned test helper before any maintenance intent.
	x.client.Close()
	old := x.children[MainUnit]
	if e := old.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if e := old.Wait(); e == nil {
		t.Fatal("own helper death not observed")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRuntimeWorkOperatorHelper$")
	cmd.Env = []string{"GOMAXPROCS=2", "XANDBOX_TEST_WORK_ROOT=" + x.f.root.Name(), "XANDBOX_TEST_WORK_RESULT=" + outcome}
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
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
		out.Close()
	})
	reader := bufio.NewReader(out)
	ready := make(chan string, 1)
	go func() { line, _ := reader.ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "READY\n" {
			t.Fatal("work helper not ready", line)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("work helper deadline")
	}
	x.children[MainUnit] = cmd
	x.client, e = nodecontrol.NewPinnedClient(x.f.root.Name()+stateDir, cmd.Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(x.client.Close)
	return in, reader
}
func TestRuntimeWorkDeadlineKeepsActualJobAndFenceThenSameOwnerFinishes(t *testing.T) {
	x := stopModel(t, "")
	input, _ := runtimeWorkChild(t, x, "success")
	s := x.scope(t)
	x.maintain(t, s)
	intent, err := x.f.runtimeDrainReadIntent()
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := x.client.QuiesceMaintenance(context.Background(), *intent.Maintenance)
	if err != nil || frozen.Work.Pending != 1 || frozen.Work.Complete() {
		t.Fatal(frozen, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	proof, e := quiesceModel(ctx, x, s)
	cancel()
	if proof != nil || !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("pending call certified", proof, e)
	}
	p, e := x.f.runtimeDrainReadIntent()
	if e != nil {
		t.Fatal(e)
	}
	r, e := x.client.QuiesceMaintenance(context.Background(), *p.Maintenance)
	if e != nil || r.Work.Pending != 1 || r.Work.Complete() {
		t.Fatal(r, e)
	}
	if len(x.jobs) != 0 || !x.alive[MainUnit] || !x.alive[IngressUnit] {
		t.Fatal("timeout stopped processes")
	}
	if _, e = input.Write([]byte("finish\n")); e != nil {
		t.Fatal(e)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	proof, e = quiesceModel(ctx, x, s)
	if e != nil || proof == nil || !proof.terminal.Complete() || proof.terminal.Succeeded != 1 {
		t.Fatal(proof, e)
	}
	if len(x.jobs) != 0 {
		t.Fatal("completion issued Stop")
	}
}
func TestRuntimeWorkActualNonzeroResultRefusesProofDespiteZeroPending(t *testing.T) {
	x := stopModel(t, "")
	input, _ := runtimeWorkChild(t, x, "failed")
	s := x.scope(t)
	x.maintain(t, s)
	intent, err := x.f.runtimeDrainReadIntent()
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := x.client.QuiesceMaintenance(context.Background(), *intent.Maintenance)
	if err != nil || frozen.Work.Pending != 1 || frozen.Work.Complete() {
		t.Fatal(frozen, err)
	}
	if _, e := input.Write([]byte("finish\n")); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	proof, e := quiesceModel(ctx, x, s)
	if proof != nil || !errors.Is(e, errAcceptedWork) {
		t.Fatal("failed actual execution certified", proof, e)
	}
	p, e := x.f.runtimeDrainReadIntent()
	if e != nil {
		t.Fatal(e)
	}
	r, e := x.client.QuiesceMaintenance(ctx, *p.Maintenance)
	if e != nil || r.Work.Pending != 0 || r.Work.Failed != 1 || r.Work.Complete() {
		t.Fatal(r, e)
	}
	if len(x.jobs) != 0 {
		t.Fatal("failure issued Stop")
	}
}
