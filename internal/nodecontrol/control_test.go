package nodecontrol

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func shortRoot(t *testing.T) string {
	t.Helper()
	p, e := os.MkdirTemp("", "xb-nc-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(p) })
	return p
}
func initialState() State {
	return State{Version: 1, Epoch: strings.Repeat("a", 32), Revision: 1, Mode: ModeOpen}
}
func command(s State, ch string) Command {
	return Command{Version: 1, Epoch: s.Epoch, ExpectedRevision: s.Revision, RequestID: strings.Repeat(ch, 32)}
}

type memoryStore struct {
	mu         sync.Mutex
	state      State
	fail       error
	postCommit bool
	entered    chan struct{}
	release    chan struct{}
	calls      int
}

func (f *memoryStore) Load() (State, error) { f.mu.Lock(); defer f.mu.Unlock(); return f.state, nil }
func (f *memoryStore) Save(old, next State) error {
	f.mu.Lock()
	f.calls++
	fail, post, entered, release := f.fail, f.postCommit, f.entered, f.release
	f.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		<-release
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != old {
		return ErrConflict
	}
	if fail == nil || post {
		f.state = next
	}
	return fail
}
func TestControllerDrainResumeCASReplayRestart(t *testing.T) {
	root := shortRoot(t)
	fs, e := OpenStore(root)
	if e != nil {
		t.Fatal(e)
	}
	g := sandbox.NewAdmissionGate(false)
	c, e := New(fs, g)
	if e != nil {
		t.Fatal(e)
	}
	before := c.Status()
	if !before.AdmissionOpen || before.Committed.Mode != ModeOpen {
		t.Fatal(before)
	}
	req := command(before.Committed, "b")
	drained, e := c.Change(context.Background(), ModeDrained, req)
	if e != nil || drained.AdmissionOpen || drained.Committed.Revision != 2 {
		t.Fatal(drained, e)
	}
	if replay, e := c.Change(context.Background(), ModeDrained, req); e != nil || replay != drained {
		t.Fatal("exact last command retry", e)
	}
	for _, bad := range []Command{command(before.Committed, "c"), {Version: 1, Epoch: strings.Repeat("c", 32), ExpectedRevision: 2, RequestID: strings.Repeat("d", 32)}} {
		if _, e = c.Change(context.Background(), ModeOpen, bad); !errors.Is(e, ErrConflict) {
			t.Fatal("stale authority accepted", e)
		}
	}
	if _, e = c.Change(context.Background(), ModeOpen, req); !errors.Is(e, ErrConflict) {
		t.Fatal("request ID target changed", e)
	}
	if e = c.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	fs, e = OpenStore(root)
	if e != nil {
		t.Fatal(e)
	}
	g2 := sandbox.NewAdmissionGate(true)
	c, e = New(fs, g2)
	if e != nil {
		t.Fatal(e)
	}
	if c.Status().AdmissionOpen || c.Status().Committed != drained.Committed {
		t.Fatal("acknowledged drain lost on restart")
	}
	opened, e := c.Change(context.Background(), ModeOpen, command(drained.Committed, "e"))
	if e != nil || !opened.AdmissionOpen || opened.Committed.Revision != 3 {
		t.Fatal(opened, e)
	}
	if e = c.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func TestControllerPendingPersistenceNeverHoldsStatusOrAdmissionFence(t *testing.T) {
	f := &memoryStore{state: initialState(), entered: make(chan struct{}, 1), release: make(chan struct{})}
	g := sandbox.NewAdmissionGate(false)
	c, e := New(f, g)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := c.Change(ctx, ModeDrained, command(initialState(), "b")); done <- e }()
	<-f.entered
	cancel() // Accepted intent completes, not silently undone.
	status := make(chan Status, 1)
	go func() { status <- c.Status() }()
	select {
	case s := <-status:
		if s.Phase != "pending" || s.AdmissionOpen {
			t.Fatal(s)
		}
	case <-time.After(time.Second):
		t.Fatal("status waited behind Save")
	}
	if _, e = c.Change(context.Background(), ModeOpen, command(initialState(), "c")); !errors.Is(e, ErrBusy) {
		t.Fatal(e)
	}
	close(f.release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if c.Status().Committed.Mode != ModeDrained || c.Status().AdmissionOpen {
		t.Fatal("accepted cancelled command was rolled back")
	}
}
func TestControllerUncertainPreOrPostCommitFencesUntilExclusiveRestart(t *testing.T) {
	for _, post := range []bool{false, true} {
		t.Run(map[bool]string{false: "pre", true: "post"}[post], func(t *testing.T) {
			f := &memoryStore{state: initialState(), fail: errors.New("disk failure"), postCommit: post}
			g := sandbox.NewAdmissionGate(false)
			c, e := New(f, g)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = c.Change(context.Background(), ModeDrained, command(initialState(), "b")); !errors.Is(e, ErrFenced) {
				t.Fatal(e)
			}
			if c.Status().AdmissionOpen || c.Status().Phase != "fenced" {
				t.Fatal("failure reopened admission")
			}
			if _, e = c.Change(context.Background(), ModeOpen, command(initialState(), "c")); !errors.Is(e, ErrFenced) {
				t.Fatal("uncertainty overwritten", e)
			}
			c.Close(context.Background())
			f.mu.Lock()
			f.fail = nil
			f.mu.Unlock()
			restarted, e := New(f, sandbox.NewAdmissionGate(false))
			if e != nil {
				t.Fatal(e)
			}
			// No acknowledged drain exists in this failed call. Restart uses actual
			// committed namespace truth, not an invented rollback of an ambiguous IO.
			if restarted.Status().AdmissionOpen == post {
				t.Fatal("wrong pre/post commit recovery")
			}
		})
	}
}
func TestControllerCloseCannotReleasePendingWriterOrReopenGate(t *testing.T) {
	s := initialState()
	s.Mode = ModeDrained
	f := &memoryStore{state: s, entered: make(chan struct{}, 1), release: make(chan struct{})}
	g := sandbox.NewAdmissionGate(false)
	c, e := New(f, g)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := c.Change(context.Background(), ModeOpen, command(s, "b")); done <- e }()
	<-f.entered
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if e = c.Close(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("pending writer not reported", e)
	}
	if c.Status().AdmissionOpen || c.Status().Phase != "closed" {
		t.Fatal(c.Status())
	}
	close(f.release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if g.Open() {
		t.Fatal("late resume reopened a closing process")
	}
	if e = c.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func TestControllerInvalidCancelledAndExhaustedCommandsHaveNoMutation(t *testing.T) {
	f := &memoryStore{state: initialState()}
	c, e := New(f, sandbox.NewAdmissionGate(false))
	if e != nil {
		t.Fatal(e)
	}
	bad := command(initialState(), "b")
	bad.Version = 2
	if _, e = c.Change(context.Background(), ModeDrained, bad); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = c.Change(ctx, ModeDrained, command(initialState(), "b")); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	f.mu.Lock()
	calls := f.calls
	f.mu.Unlock()
	if calls != 0 || !c.Status().AdmissionOpen {
		t.Fatal("unaccepted request changed state")
	}
	s := initialState()
	s.Revision = math.MaxUint64 - 1
	s.LastExpectedRevision = s.Revision - 1
	s.LastRequestID = strings.Repeat("d", 32)
	f = &memoryStore{state: s}
	c, e = New(f, sandbox.NewAdmissionGate(false))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Change(context.Background(), ModeOpen, command(s, "e")); !errors.Is(e, ErrExhausted) {
		t.Fatal(e)
	}
	end, e := c.Change(context.Background(), ModeDrained, command(s, "f"))
	if e != nil || end.Committed.Revision != math.MaxUint64 || end.AdmissionOpen {
		t.Fatal(end, e)
	}
	if _, e = c.Change(context.Background(), ModeOpen, command(end.Committed, "a")); !errors.Is(e, ErrExhausted) {
		t.Fatal(e)
	}
}
func TestFileStoreLegacyMissingTamperedUnknownAndTempBounds(t *testing.T) {
	for _, name := range []string{"sessions", "instances", "firecracker"} {
		t.Run("used-"+name, func(t *testing.T) {
			root := shortRoot(t)
			if e := os.Mkdir(filepath.Join(root, name), 0700); e != nil {
				t.Fatal(e)
			}
			fs, e := OpenStore(root)
			if e != nil {
				t.Fatal(e)
			}
			s, e := fs.Load()
			if e != nil || s.Mode != ModeDrained {
				t.Fatal("used root silently opened", s, e)
			}
		})
	}
	for _, name := range []string{"missing-state", "wrong-identity", "unknown-entry", "symlink-state", "hardlink-state", "bad-mode"} {
		t.Run(name, func(t *testing.T) {
			root := shortRoot(t)
			fs, e := OpenStore(root)
			if e != nil {
				t.Fatal(e)
			}
			p := filepath.Join(root, "admission", "state.json")
			switch name {
			case "missing-state":
				os.Remove(p)
			case "wrong-identity":
				os.WriteFile(filepath.Join(root, "admission.identity"), []byte(`{"version":1,"epoch":"bad"}`), 0600)
			case "unknown-entry":
				os.WriteFile(filepath.Join(root, "admission", "unknown"), nil, 0600)
			case "symlink-state":
				os.Rename(p, filepath.Join(root, "outside"))
				os.Symlink(filepath.Join(root, "outside"), p)
			case "hardlink-state":
				os.Link(p, filepath.Join(root, "alias"))
			case "bad-mode":
				os.Chmod(p, 0644)
			}
			if _, e = fs.Load(); e == nil {
				t.Fatal("live tampering accepted")
			}
			if _, e = OpenStore(root); e == nil {
				t.Fatal("bad startup repaired/adopted")
			}
		})
	}
	root := shortRoot(t)
	fs, e := OpenStore(root)
	if e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 32; n++ {
		p := filepath.Join(root, "admission", ".state-"+strings.Repeat("1", n%5+1)+string(rune('0'+n/5)))
		if e = os.WriteFile(p, []byte("not committed JSON"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = fs.Load(); e != nil {
		t.Fatal("bounded uncommitted temps adopted or rejected", e)
	}
	if e = os.WriteFile(filepath.Join(root, "admission", ".identity-999999"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = fs.Load(); e == nil {
		t.Fatal("temp namespace bound not enforced")
	}
}

func TestFileStoreMissingBothMetadataCannotReplayOldResumeOnUsedRoot(t *testing.T) {
	root := shortRoot(t)
	f, e := OpenStore(root)
	if e != nil {
		t.Fatal(e)
	}
	c, e := New(f, sandbox.NewAdmissionGate(false))
	if e != nil {
		t.Fatal(e)
	}
	before := c.Status().Committed
	drained, e := c.Change(context.Background(), ModeDrained, command(before, "b"))
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(root, "sessions"), 0700); e != nil {
		t.Fatal(e)
	}
	// Simulate metadata loss between exclusive owners, not a supported repair.
	for _, name := range []string{"admission/state.json", "admission.identity"} {
		if e = os.Remove(filepath.Join(root, name)); e != nil {
			t.Fatal(e)
		}
	}
	f, e = OpenStore(root)
	if e != nil {
		t.Fatal(e)
	}
	c, e = New(f, sandbox.NewAdmissionGate(false))
	if e != nil {
		t.Fatal(e)
	}
	after := c.Status()
	if after.AdmissionOpen || after.Committed.Mode != ModeDrained || after.Committed.Epoch == before.Epoch {
		t.Fatal("lost metadata restored old/open authority", after)
	}
	if _, e = c.Change(context.Background(), ModeOpen, command(drained.Committed, "c")); !errors.Is(e, ErrConflict) {
		t.Fatal("old epoch resume accepted", e)
	}
}

func TestFileStorePartialInitializationAndDirectoryReplacement(t *testing.T) {
	root := shortRoot(t)
	f, e := OpenStore(root)
	if e != nil {
		t.Fatal(e)
	}
	before, e := f.Load()
	if e != nil {
		t.Fatal(e)
	}
	// State rename committed, identity creation not yet committed: recover the
	// state epoch rather than minting a new open command authority.
	if e = os.Remove(filepath.Join(root, "admission.identity")); e != nil {
		t.Fatal(e)
	}
	f, e = OpenStore(root)
	if e != nil {
		t.Fatal(e)
	}
	after, e := f.Load()
	if e != nil || after != before {
		t.Fatal("partial initialization changed committed state", after, e)
	}
	old := filepath.Join(root, "admission-old")
	if e = os.Rename(filepath.Join(root, "admission"), old); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(root, "admission"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = f.Load(); e == nil {
		t.Fatal("replaced admission directory accepted")
	}
}
