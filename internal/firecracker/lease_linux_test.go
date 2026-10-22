//go:build linux

package firecracker

import (
	"errors"
	"io"
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

func TestRevokeLeaseIsCapabilityOnlyBoundedAndCannotRevive(t *testing.T) {
	ref := sandbox.Ref{ID: strings.Repeat("1", 32), Generation: strings.Repeat("2", 32)}
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
	p, e := newProcess(w, ref.ID+ref.Generation, now+int64(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	// No registry, config, cgroup or disk exists in this test. A revocation
	// must rely exclusively on the live pipe capability, not discover/adopt one.
	d := &driver{procs: map[string]*process{}}
	if e = d.RevokeLease(ref); e != nil {
		t.Fatal(e)
	}
	d.mu.Lock()
	d.procs[ref.ID+ref.Generation] = p
	d.mu.Unlock() // Late Prepare publication.
	other := ref
	other.Generation = strings.Repeat("3", 32)
	if e = d.RevokeLease(other); e != nil {
		t.Fatal(e)
	}
	if e = p.refreshLease(); e != nil {
		t.Fatal("wrong Ref revoked a live capability", e)
	}
	bounded := func() {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- d.RevokeLease(ref) }()
		select {
		case e := <-done:
			if e != nil {
				t.Fatal(e)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatal("revocation waited for a contended lock")
		}
	}
	d.mu.Lock()
	bounded()
	d.mu.Unlock()
	p.leaseMu.Lock()
	bounded()
	p.leaseMu.Unlock()
	if e = d.RevokeLease(ref); e != nil {
		t.Fatal(e)
	}
	finished := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(r); finished <- b }()
	select {
	case b := <-finished:
		if len(b) < lease.FrameSize || len(b)%lease.FrameSize != 0 {
			t.Fatal("initial frame/EOF mismatch", len(b))
		}
	case <-time.After(time.Second):
		t.Fatal("owned guardian reader did not receive EOF")
	}
	if e = p.refreshLease(); !errors.Is(e, sandbox.ErrBackendFenced) {
		t.Fatal("revoked lease revived", e)
	}
	if e = d.RevokeLease(ref); e != nil {
		t.Fatal("repeat revocation not idempotent", e)
	}
	if e = d.RevokeLease(sandbox.Ref{ID: "invalid", Generation: "invalid"}); !errors.Is(e, sandbox.ErrInvalid) {
		t.Fatal("invalid Ref accepted", e)
	}
}
