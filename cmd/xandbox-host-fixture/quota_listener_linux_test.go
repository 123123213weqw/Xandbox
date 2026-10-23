//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

func TestQuotaListenerFixedModesRecordsAndOwners(t *testing.T) {
	ref := sandbox.Ref{ID: strings.Repeat("1", 32), Generation: strings.Repeat("2", 32)}
	for i, m := range []quotaLossMode{quotaLossReserve, quotaLossRelease} {
		if m.name() == "" || m.phase() == "" || m.base() == "" || m.runtimeRoot() == "" || m.group() == "" || m.uid() != 480028+4*i || m.recoveryChild() == "" {
			t.Fatal("wrong fixed binding")
		}
		if n, ok := quotaLossName(m.name()); !ok || n != m {
			t.Fatal("unknown fixed name")
		}
		if b, e := quotaSyscallBase(m.name()); e != nil || b != m.base() {
			t.Fatal("wrong base")
		}
		if r, e := quotaSyscallRuntime(m.name()); e != nil || r != m.runtimeRoot() {
			t.Fatal("wrong runtime")
		}
		o := clearWindowOwner{Version: 3, Ref: ref, UID: m.uid(), ProjectID: quotaFirst, QuotaAttempted: true}
		b, _ := json.Marshal(o)
		if e := decodeQuotaLossOwner(m, b, ref); e != nil {
			t.Fatal(e)
		}
		for _, change := range []func(*clearWindowOwner){func(o *clearWindowOwner) { o.UID++ }, func(o *clearWindowOwner) { o.ProjectID++ }, func(o *clearWindowOwner) { o.QuotaAttempted = false }, func(o *clearWindowOwner) { o.InitializationAttempted = true }, func(o *clearWindowOwner) { o.Version = 4 }, func(o *clearWindowOwner) { o.TemplateID = "x" }} {
			bad := o
			change(&bad)
			b, _ := json.Marshal(bad)
			if decodeQuotaLossOwner(m, b, ref) == nil {
				t.Fatal("unknown owner adopted")
			}
		}
		r := quotaRecord{}
		if m == quotaLossRelease {
			r.BHard = 192 << 10
			r.IHard = 128
		}
		if quotaLossRecord(m, r) != nil {
			t.Fatal("fixed quota rejected")
		}
		for _, change := range []func(*quotaRecord){func(r *quotaRecord) { r.BHard++ }, func(r *quotaRecord) { r.IHard++ }, func(r *quotaRecord) { r.BSoft = 1 }, func(r *quotaRecord) { r.ISoft = 1 }, func(r *quotaRecord) { r.Space = 1 }, func(r *quotaRecord) { r.Inodes = 1 }, func(r *quotaRecord) { r.BTime = 1 }, func(r *quotaRecord) { r.ITime = 1 }} {
			bad := r
			change(&bad)
			if quotaLossRecord(m, bad) == nil {
				t.Fatal("unknown quota adopted")
			}
		}
	}
	m := quotaLossMode(255)
	if m.name() != "" || m.phase() != "" || m.base() != "" || m.runtimeRoot() != "" || m.group() != "" || m.uid() != 0 || m.recoveryChild() != "" || quotaLossRecord(m, quotaRecord{}) == nil {
		t.Fatal("unknown mode accepted")
	}
	for _, name := range []string{"listener-loss-unknown", "../listener-loss-reserve", "listener-loss-release/extra"} {
		if _, ok := quotaLossName(name); ok {
			t.Fatal("arbitrary case")
		}
		if _, e := quotaSyscallBase(name); e == nil {
			t.Fatal("arbitrary base")
		}
	}
}
func TestQuotaListenerLossCannotRunOnL0OrAcceptTargets(t *testing.T) {
	n := &node{quotaDriver: true}
	for _, m := range []quotaLossMode{quotaLossReserve, quotaLossRelease, 255} {
		if _, e := n.quotaListenerCheckpoint(context.Background(), m); e == nil {
			t.Fatal("L0 checkpoint")
		}
		if _, e := n.quotaListenerRecover(context.Background(), m); e == nil {
			t.Fatal("L0 recovery")
		}
		if runQuotaListenerRecoveryDaemon(m) == nil {
			t.Fatal("L0 child")
		}
	}
	if (&quotaNotifier{}).prepareListenerLoss(quotaNotif{}) == nil {
		t.Fatal("L0 listener close")
	}
	if _, e := (&quotaNotifier{}).startListenerExitTrace(quotaNotif{}); e == nil {
		t.Fatal("L0 exit observer")
	}
	if quotaRetainedReclaiming(context.Background(), nil, firecracker.Config{}, "", sandbox.Ref{}, nil) == nil {
		t.Fatal("L0 ledger")
	}
	for _, op := range []string{"quota-listener-reserve-checkpoint", "quota-listener-reserve-recover", "quota-listener-release-checkpoint", "quota-listener-release-recover"} {
		if (nodeRequest{Version: 1, Operation: op}).validate() != nil {
			t.Fatal("fixed op rejected")
		}
		if (nodeRequest{Version: 1, Operation: op, Phase: "/dev/vda"}).validate() == nil {
			t.Fatal("parameterized listener")
		}
	}
}
func TestQuotaListenerReturnProgramOnlyExactOwnedQuotactl(t *testing.T) {
	p, e := quotaExitProgramOn(7, 110, 111, true)
	if e != nil {
		t.Fatal(e)
	}
	id := uint64(110)<<32 | 111
	got := emulateQuotaExit(t, p, id, int64(unix.SYS_QUOTACTL_FD), -int64(unix.ENOSYS), 0, false, false)
	if got.Seen != 1 || got.Return != -int64(unix.ENOSYS) {
		t.Fatal("kernel return changed")
	}
	for _, tc := range []struct {
		id   uint64
		nr   int64
		seen uint64
	}{{id + 1, int64(unix.SYS_QUOTACTL_FD), 0}, {id + (1 << 32), int64(unix.SYS_QUOTACTL_FD), 0}, {id, int64(unix.SYS_SYNCFS), 0}, {id, int64(unix.SYS_QUOTACTL_FD), 1}} {
		got = emulateQuotaExit(t, p, tc.id, tc.nr, -38, tc.seen, false, false)
		if got.Seen != tc.seen || got.Return != 42 {
			t.Fatal("foreign event overwrote latch")
		}
	}
}
func TestQuotaListenerCloseIsIdempotentAfterServeEnded(t *testing.T) {
	o := &quotaNotifier{stop: make(chan struct{}), done: make(chan struct{})}
	close(o.done)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if o.close() != nil {
				t.Error("closed observer error")
			}
		}()
	}
	wg.Wait()
}
