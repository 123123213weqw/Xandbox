//go:build linux

package serviceready

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"testing"
	"time"
)

func TestOnePIDClosedInventory(t *testing.T) {
	for _, s := range []string{"0", "1", "01", "2 3", "2\n3", "-2", "+2", "9999999999999999999999"} {
		if _, e := onePID([]byte(s)); e == nil {
			t.Fatal("invalid process inventory")
		}
	}
	if _, e := onePID(nil); !errors.Is(e, unix.EAGAIN) {
		t.Fatal("empty startup control must wait")
	}
	if p, e := onePID([]byte("123\n")); e != nil || p != 123 {
		t.Fatal(e)
	}
}
func TestActualPidfdAliveAndClosedRefused(t *testing.T) {
	fd, e := unix.PidfdOpen(os.Getpid(), 0)
	if e != nil {
		t.Fatal("pidfd is required", e)
	}
	if e = alive(fd); e != nil {
		t.Fatal(e)
	}
	unix.Close(fd)
	if alive(fd) == nil {
		t.Fatal("closed descriptor accepted")
	}
}
func TestOnlyTransientReadinessRetriesAndDeadline(t *testing.T) {
	for _, e := range []error{unix.ENOENT, unix.ECONNREFUSED, unix.ESRCH, unix.EAGAIN, context.DeadlineExceeded} {
		if !retryable(e) {
			t.Fatal("startup transient", e)
		}
	}
	for _, e := range []error{errPolicy, unix.EACCES, unix.ENOSYS, unix.EINVAL} {
		if retryable(e) {
			t.Fatal("permanent error retried", e)
		}
	}
	calls := 0
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	e := waitReady(ctx, func(context.Context) error { calls++; return unix.ENOENT })
	if !errors.Is(e, context.DeadlineExceeded) || calls != 1 {
		t.Fatal("bounded startup wait", calls, e)
	}
	calls = 0
	e = waitReady(context.Background(), func(context.Context) error { calls++; return errPolicy })
	if e != errPolicy || calls != 1 {
		t.Fatal("semantic failure must not be hidden")
	}
}
