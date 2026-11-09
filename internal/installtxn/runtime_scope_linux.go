//go:build linux

package installtxn

import (
	"context"
	"os"
	"sync"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"golang.org/x/sys/unix"
)

// runtimeScope owns one ORIGINAL operation EX lease across maintenance stages.
// It is not a stopped/reclaimed certificate and never authorizes file selection.
// No public constructor, borrowed FD, bypass flag or caller-selected root exists.
type runtimeScope struct {
	mu     sync.Mutex
	fs     *filesystem
	lock   *os.File
	rootID os.FileInfo
	state  *runtimeStateLease // Separate original daemon BSD flock, acquired only AFTER stop proof.
}

func (f *filesystem) beginRuntimeScope(ctx context.Context) (*runtimeScope, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	in, e := f.acquireOperationLock(ctx, true)
	if e != nil {
		return nil, e
	}
	root, e := f.root.Stat()
	if e != nil {
		in.Close()
		return nil, e
	}
	return &runtimeScope{fs: f, lock: in, rootID: root}, nil
}
func (s *runtimeScope) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != nil {
		s.state.close()
		s.state = nil
	}
	if s.lock != nil {
		s.lock.Close()
		s.lock = nil
	}
}
func (s *runtimeScope) valid(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.lock == nil || s.fs == nil {
		return ErrConflict
	}
	root, e := s.fs.root.Stat()
	if e != nil {
		return e
	}
	if !os.SameFile(root, s.rootID) {
		return ErrInventory
	}
	before, e := s.lock.Stat()
	if e != nil {
		return e
	}
	if before.Size() != 0 || trustedStat(int(s.lock.Fd()), false, 0600) != nil {
		return ErrInventory
	}
	current, e := s.fs.open(Root+"/.lock", unix.O_RDONLY, 0600)
	if e != nil {
		return e
	}
	defer current.Close()
	after, e := current.Stat()
	if e != nil {
		return e
	}
	if !os.SameFile(before, after) || after.Size() != 0 {
		return ErrInventory
	}
	if s.state != nil {
		return s.state.verify(s.fs)
	}
	return nil
}

// Serialize a complete stage against close and other stages on this scope.
// Stage implementations use the existing flock ONLY around file operations;
// no flock or operation-lock reacquisition is hidden in this adapter.
func (s *runtimeScope) run(ctx context.Context, work func(*filesystem) error) error {
	if s == nil || work == nil {
		return ErrPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.valid(ctx); e != nil {
		return e
	}
	if e := work(s.fs); e != nil {
		return e
	}
	return s.valid(ctx)
}
func (s *runtimeScope) drain(ctx context.Context, base, request string, client *nodecontrol.PinnedClient) (runtimeDrainResult, error) {
	var result runtimeDrainResult
	e := s.run(ctx, func(f *filesystem) error {
		var e error
		result, e = f.runtimeDrainInScope(ctx, base, request, client)
		return e
	})
	if e != nil {
		return runtimeDrainResult{}, e
	}
	return result, nil
}
