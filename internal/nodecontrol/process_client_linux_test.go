//go:build linux

package nodecontrol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

// Test ELF only; own private Unix endpoint/controller, no daemon/VM/systemd.
func TestPinnedProcessHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_TEST_PINNED_ROOT")
	if root == "" {
		return
	}
	store, e := OpenStore(root)
	if e != nil {
		os.Exit(71)
	}
	c, e := New(store, sandbox.NewAdmissionGate(false))
	if e != nil {
		os.Exit(72)
	}
	s, e := Start(root, c, func() sandbox.Stats { return sandbox.Stats{Capacity: 4, Active: 1} })
	if e != nil {
		os.Exit(73)
	}
	fmt.Println("READY")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if s.Close(ctx) != nil || c.Close(ctx) != nil {
		os.Exit(74)
	}
}
func pinnedChild(t *testing.T, root string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestPinnedProcessHelper$")
	cmd.Env = []string{"GOMAXPROCS=2", "XANDBOX_TEST_PINNED_ROOT=" + root}
	input, e := cmd.StdinPipe()
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
		input.Close()
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
		out.Close()
	})
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(out).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "READY\n" {
			t.Fatal("helper did not become ready")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("helper start deadline")
	}
	return cmd
}
func pinnedServer(t *testing.T, h http.Handler) string {
	t.Helper()
	root := shortRoot(t)
	path := filepath.Join(root, SocketName)
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	s := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
	go s.Serve(l)
	t.Cleanup(func() { s.Close() })
	return root
}

func TestPinnedProcessExactDrainAndDurableRetry(t *testing.T) {
	root := shortRoot(t)
	store, e := OpenStore(root)
	if e != nil {
		t.Fatal(e)
	}
	g := sandbox.NewAdmissionGate(false)
	control, e := New(store, g)
	if e != nil {
		t.Fatal(e)
	}
	s, e := Start(root, control, func() sandbox.Stats { return sandbox.Stats{Capacity: 4, Active: 1} })
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	defer control.Close(context.Background())
	c, e := NewPinnedClient(root, os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if !c.Identity().Valid() {
		t.Fatal("missing live incarnation")
	}
	dir, e := os.Open(root)
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	if e = c.VerifyDirectory(dir); e != nil {
		t.Fatal(e)
	}
	before, e := c.Status(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	cmd := command(before.Control.Committed, "b")
	r, e := c.Drain(context.Background(), cmd)
	if e != nil || r.Control.AdmissionOpen || r.Control.Committed.Revision != 2 || r.ResourceObservation.Active != 1 {
		t.Fatal(r, e)
	}
	if again, e := c.Drain(context.Background(), cmd); e != nil || again.Control != r.Control {
		t.Fatal("exact drain retry", e)
	}
	loaded, e := store.Load()
	if e != nil || loaded != r.Control.Committed {
		t.Fatal("disk drain not committed", e)
	}
	other, e := os.Open(shortRoot(t))
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if e = c.VerifyDirectory(other); e == nil {
		t.Fatal("different root accepted")
	}
}

func TestPinnedProcessSameUIDWrongPeerAndDeadIncarnationRefuse(t *testing.T) {
	root := shortRoot(t)
	child := pinnedChild(t, root)
	wrong, e := NewPinnedClient(root, os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	defer wrong.Close()
	if _, e = wrong.Status(context.Background()); e == nil {
		t.Fatal("same UID different PID accepted")
	}
	correct, e := NewPinnedClient(root, child.Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	defer correct.Close()
	if _, e = correct.Status(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if e = child.Wait(); e == nil {
		t.Fatal("own helper death not observed")
	}
	replacement := pinnedChild(t, root)
	_ = replacement
	legacy, e := NewClient(root)
	if e != nil {
		t.Fatal(e)
	}
	defer legacy.Close()
	if _, e = legacy.Status(context.Background()); e != nil {
		t.Fatal("replacement negative-control premise", e)
	}
	if _, e = correct.Status(context.Background()); e == nil {
		t.Fatal("dead pidfd adopted replacement server")
	}
}

func TestPinnedProcessClosedLeaseCannotReturnInflightReply(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	root := pinnedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		json.NewEncoder(w).Encode(Reply{Control: Status{Version: 1, Committed: initialState(), Phase: "ready", DesiredMode: ModeOpen, AdmissionOpen: true}})
	}))
	c, e := NewPinnedClient(root, os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := c.Status(ctx); done <- e }()
	select {
	case <-entered:
	case <-ctx.Done():
		close(release)
		t.Fatal("request did not enter server")
	}
	c.Close()
	close(release)
	if e = <-done; e == nil {
		t.Fatal("closed lease returned accepted reply")
	}
	if _, e = c.Status(ctx); e == nil {
		t.Fatal("closed lease reused")
	}
	c.Close()
}

func TestPinnedProcessDrainRejectsValidShapeButWrongCASReply(t *testing.T) {
	for _, kind := range []string{"open", "epoch", "revision", "request", "expected", "pending"} {
		t.Run(kind, func(t *testing.T) {
			s := State{Version: 1, Epoch: initialState().Epoch, Revision: 2, Mode: ModeDrained, LastRequestID: strings.Repeat("b", 32), LastExpectedRevision: 1}
			view := Status{Version: 1, Committed: s, Phase: "ready", DesiredMode: ModeDrained}
			switch kind {
			case "open":
				view.Committed.Mode = ModeOpen
				view.DesiredMode = ModeOpen
				view.AdmissionOpen = true
			case "epoch":
				view.Committed.Epoch = strings.Repeat("c", 32)
			case "revision":
				view.Committed.Revision = 3
				view.Committed.LastExpectedRevision = 2
			case "request":
				view.Committed.LastRequestID = strings.Repeat("c", 32)
			case "expected":
				view.Committed.Revision = 4
				view.Committed.LastExpectedRevision = 3
			case "pending":
				view.Phase = "pending"
				view.PendingRequestID = strings.Repeat("c", 32)
			}
			root := pinnedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(Reply{Control: view}) }))
			c, e := NewPinnedClient(root, os.Getpid())
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			if _, e = c.Drain(context.Background(), command(initialState(), "b")); e == nil {
				t.Fatal("wrong exact command accepted")
			}
		})
	}
}

func TestPinnedProcessStatBoundsAndCloseRace(t *testing.T) {
	raw := []byte("42 (name with ) and spaces) S " + strings.Repeat("0 ", 18) + "123 0\n")
	if n, e := processStart(raw, 42); e != nil || n != 123 {
		t.Fatal("comm parsing", n, e)
	}
	for _, b := range [][]byte{nil, []byte("wrong"), []byte("42 (x) S 0"), bytesReplace(raw, []byte("123"), []byte("0123"))} {
		if _, e := processStart(b, 42); e == nil {
			t.Fatal("malformed stat accepted")
		}
	}
	root := shortRoot(t)
	c, e := NewPinnedClient(root, os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 20; j++ {
				c.client.live()
				c.Close()
			}
		}()
	}
	group.Wait()
	if !errors.Is(c.client.live(), ErrProcessPin) {
		t.Fatal("closed pidfd remains live")
	}
	for _, pid := range []int{-1, 0, 1} {
		if _, e := NewPinnedClient(root, pid); e == nil {
			t.Fatal("invalid PID accepted")
		}
	}
}
func bytesReplace(b, old, next []byte) []byte {
	return []byte(strings.Replace(string(b), string(old), string(next), 1))
}

func TestPinnedProcessInterruptedPollRetriesAreBounded(t *testing.T) {
	for _, kind := range []string{"interrupted-then-live", "interrupted-then-dead", "storm", "unsupported"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			e := pollLiveProcess(123, func(fds []unix.PollFd, timeout int) (int, error) {
				calls++
				if len(fds) != 1 || fds[0].Fd != 123 || fds[0].Events != unix.POLLIN || timeout != 0 {
					t.Fatal("changed FD/probe")
				}
				if kind == "unsupported" {
					return -1, unix.ENOSYS
				}
				if calls <= 2 || kind == "storm" {
					return -1, unix.EINTR
				}
				if kind == "interrupted-then-dead" {
					fds[0].Revents = unix.POLLIN
					return 1, nil
				}
				return 0, nil
			})
			switch kind {
			case "interrupted-then-live":
				if e != nil || calls != 3 {
					t.Fatal(e, calls)
				}
			case "interrupted-then-dead":
				if !errors.Is(e, ErrProcessPin) || calls != 3 {
					t.Fatal(e, calls)
				}
			case "storm":
				if !errors.Is(e, unix.EINTR) || calls != 4 {
					t.Fatal("signal storm accepted/unbounded", e, calls)
				}
			case "unsupported":
				if !errors.Is(e, unix.ENOSYS) || calls != 1 {
					t.Fatal("unsupported syscall fallback", e, calls)
				}
			}
		})
	}
}

func TestPinnedProcessExitRequiresOpenKernelLeaseNotClosedClient(t *testing.T) {
	root := shortRoot(t)
	child := pinnedChild(t, root)
	w, e := NewProcessWatch(child.Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	c, e := NewPinnedClient(root, child.Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if dead, e := w.Exited(); e != nil || dead {
		t.Fatal("live process certified dead", dead, e)
	}
	if e = child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if e = child.Wait(); e == nil {
		t.Fatal("child not terminated")
	}
	for _, exit := range []func() (bool, error){w.Exited, c.Exited} {
		if dead, e := exit(); e != nil || !dead {
			t.Fatal("held pidfd did not prove known death", dead, e)
		}
	}
	w.Close()
	c.Close()
	if dead, e := w.Exited(); e == nil || dead {
		t.Fatal("closed watch became death proof")
	}
	if dead, e := c.Exited(); e == nil || dead {
		t.Fatal("closed client became death proof")
	}
}
func TestPinnedProcessExitPollStrictEventsAndInterruptedBudget(t *testing.T) {
	for _, kind := range []string{"live", "exit", "reaped", "hup-only", "invalid", "interrupted-exit", "storm", "unsupported"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			dead, e := pollExitedProcess(12, func(fds []unix.PollFd, timeout int) (int, error) {
				calls++
				if timeout != 0 || len(fds) != 1 || fds[0].Fd != 12 {
					t.Fatal("different kernel probe")
				}
				if kind == "storm" || kind == "interrupted-exit" && calls == 1 {
					return -1, unix.EINTR
				}
				switch kind {
				case "live":
					return 0, nil
				case "unsupported":
					return -1, unix.ENOSYS
				case "hup-only":
					fds[0].Revents = unix.POLLHUP
				case "invalid":
					fds[0].Revents = unix.POLLNVAL
				case "reaped":
					fds[0].Revents = unix.POLLIN | unix.POLLHUP
				default:
					fds[0].Revents = unix.POLLIN
				}
				return 1, nil
			})
			want := kind == "exit" || kind == "reaped" || kind == "interrupted-exit"
			if dead != want || want && e != nil || kind == "live" && e != nil {
				t.Fatal(kind, dead, e)
			}
			if !want && kind != "live" && e == nil {
				t.Fatal("untrusted event certified absence")
			}
			if kind == "storm" && (calls != 4 || !errors.Is(e, unix.EINTR)) {
				t.Fatal("unbounded storm", calls, e)
			}
		})
	}
}
