//go:build linux

package warden

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/hostclock"
	"github.com/123123213weqw/Xandbox/internal/lease"
)

func TestKernelTimerDoesNotWaitForPartialLeaseFrame(t *testing.T) {
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
	b, _ := lease.ParseBinding(strings.Repeat("1", 64))
	stopped := make(chan struct{})
	var once sync.Once
	ready, timer, e := beginLease(r, b, now+int64(100*time.Millisecond), func() { once.Do(func() { close(stopped) }) })
	if e != nil {
		t.Fatal(e)
	}
	defer timer.Close()
	w.Write([]byte("XB"))
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("partial frame suppressed kernel expiry")
	}
	select {
	case <-ready:
		t.Fatal("partial packet enabled child launch")
	default:
	}
}
func TestKernelHardTimerSurvivesContinuousValidRenewal(t *testing.T) {
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
	hard := now + int64(200*time.Millisecond)
	b, _ := lease.ParseBinding(strings.Repeat("2", 64))
	stopped := make(chan struct{})
	var once sync.Once
	ready, timer, e := beginLease(r, b, hard, func() { once.Do(func() { close(stopped) }) })
	if e != nil {
		t.Fatal(e)
	}
	defer timer.Close()
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for seq := uint64(1); ; seq++ {
			p := lease.Encode(b, seq, hard)
			if _, e := w.Write(p[:]); e != nil {
				return
			}
			select {
			case <-stopped:
				return
			case <-ticker.C:
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("valid initial lease didn't enable launch")
	}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("renewal extended absolute hard TTL")
	}
	w.Close()
	select {
	case <-sent:
	case <-time.After(time.Second):
		t.Fatal("sender didn't quiesce")
	}
}
