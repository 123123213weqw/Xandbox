//go:build linux || darwin

package firecracker

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

// Every acquisition opens a distinct descriptor. Never unlink the lock file:
// process-local mutexes or replacing its inode cannot serialize an admin CLI.
func catalogLock(ctx context.Context, path string) (func(), error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	info, e := f.Stat()
	if e != nil {
		return nil, e
	}
	st, yes := info.Sys().(*syscall.Stat_t)
	link, e := os.Lstat(path)
	if e != nil || !yes || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || !os.SameFile(info, link) {
		return nil, errors.New("catalog lock must be private, owned and stable")
	}
	for {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			ok = true
			return func() { f.Close() }, nil
		}
		if !errors.Is(e, syscall.EWOULDBLOCK) && !errors.Is(e, syscall.EAGAIN) {
			return nil, e
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}
func catalogOwned(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid())
}
