//go:build linux

package firecracker

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/hostclock"
	"github.com/123123213weqw/Xandbox/internal/lease"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

func TestLeasePipeSaturationNeverBlocksControllerProgress(t *testing.T) {
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	now, e := hostclock.NowNS()
	if e != nil {
		t.Fatal(e)
	}
	p, e := newProcess(w, strings.Repeat("1", 64), now+int64(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	size, e := unix.FcntlInt(uintptr(p.leaseFD), unix.F_GETPIPE_SZ, 0)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		for n := 0; n < size/lease.FrameSize+2; n++ {
			p.leaseMu.Lock()
			p.nextRenew = 0
			p.leaseMu.Unlock()
			if e := p.refreshLease(); e != nil {
				done <- e
				return
			}
		}
		done <- nil
	}()
	select {
	case e := <-done:
		if !errors.Is(e, sandbox.ErrBackendFenced) {
			t.Fatalf("saturation did not fence: %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pipe write blocked")
	}
	p.leaseMu.Lock()
	closed := p.leaseClosed
	p.leaseMu.Unlock()
	if !closed {
		t.Fatal("failed lease pipe kept open")
	}
	if e := p.refreshLease(); !errors.Is(e, sandbox.ErrBackendFenced) {
		t.Fatal("closed lease revived")
	}
}
