//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func TestUnfinishedWorkersRetainStateLockThroughProcessExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.lock")
	unlock, err := lockState(path)
	if err != nil {
		t.Fatal(err)
	}
	releaseStateLock(unlock, true)
	t.Cleanup(func() {
		if retainedStateLock != nil {
			retainedStateLock()
			retainedStateLock = nil
		}
	})
	runtime.GC()
	if second, err := lockState(path); err == nil {
		second()
		t.Fatal("second controller admitted while old worker may still write")
	}
	retainedStateLock()
	retainedStateLock = nil
	second, err := lockState(path)
	if err != nil {
		t.Fatal(err)
	}
	releaseStateLock(second, false)
	third, err := lockState(path)
	if err != nil {
		t.Fatal("quiescent lock not released: ", err)
	}
	third()
}

type blockedControlStore struct {
	state            nodecontrol.State
	entered, release chan struct{}
}

func (s *blockedControlStore) Load() (nodecontrol.State, error) { return s.state, nil }
func (s *blockedControlStore) Save(_, next nodecontrol.State) error {
	s.entered <- struct{}{}
	<-s.release
	return nil
}
func TestUnfinishedControlWriterAlsoRetainsExclusiveStateLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.lock")
	unlock, e := lockState(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if retainedStateLock != nil {
			retainedStateLock()
			retainedStateLock = nil
		}
	})
	f := &blockedControlStore{state: nodecontrol.State{Version: 1, Epoch: strings.Repeat("a", 32), Revision: 1, Mode: nodecontrol.ModeOpen}, entered: make(chan struct{}, 1), release: make(chan struct{})}
	c, e := nodecontrol.New(f, sandbox.NewAdmissionGate(false))
	if e != nil {
		t.Fatal(e)
	}
	var once sync.Once
	release := func() { once.Do(func() { close(f.release) }) }
	defer release()
	done := make(chan error, 1)
	go func() {
		_, e := c.Change(context.Background(), nodecontrol.ModeDrained, nodecontrol.Command{Version: 1, Epoch: f.state.Epoch, ExpectedRevision: 1, RequestID: strings.Repeat("b", 32)})
		done <- e
	}()
	<-f.entered
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	e = c.Close(ctx)
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	releaseStateLock(unlock, e != nil)
	runtime.GC()
	if second, e := lockState(path); e == nil {
		second()
		t.Fatal("new controller raced unresolved operator persistence")
	}
	release()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if e = c.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	retainedStateLock()
	retainedStateLock = nil
	second, e := lockState(path)
	if e != nil {
		t.Fatal(e)
	}
	second()
}
func TestControllerLockRejectsAliasesAndPublicFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "public"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "controller.lock")
			target := filepath.Join(dir, "target")
			if e := os.WriteFile(target, nil, 0600); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "symlink":
				os.Symlink(target, path)
			case "hardlink":
				os.Link(target, path)
			case "public":
				os.WriteFile(path, nil, 0644)
				if e := os.Chmod(path, 0644); e != nil {
					t.Fatal(e)
				}
			}
			if unlock, e := lockState(path); e == nil {
				unlock()
				t.Fatal("untrusted state lock adopted")
			}
		})
	}
}
