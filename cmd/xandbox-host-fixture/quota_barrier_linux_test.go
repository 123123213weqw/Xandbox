//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

func TestQuotaBarrierCannotRunOnL0OrAcceptArguments(t *testing.T) {
	n := &node{}
	if _, e := n.quotaBarrierCheckpoint(context.Background()); e == nil {
		t.Fatal("checkpoint escaped guard")
	}
	if _, e := n.recoverQuotaBarrier(context.Background()); e == nil {
		t.Fatal("recovery escaped guard")
	}
	if e := runQuotaBarrierRecoveryDaemon(); e == nil {
		t.Fatal("unobserved recovery escaped guard")
	}
	for _, op := range []string{"quota-barrier-checkpoint", "quota-barrier-recover"} {
		if e := (nodeRequest{Version: 1, Operation: op}).validate(); e != nil {
			t.Fatal(e)
		}
		if e := (nodeRequest{Version: 1, Operation: op, Phase: "/dev/vda"}).validate(); e == nil {
			t.Fatal("parameter surface")
		}
	}
}
func TestQuotaOwnerSelectorRequiresExactOwnerNotJustReservedRange(t *testing.T) {
	for _, cmd := range []uint64{0x80000702, 0x80000802} {
		q := quotaNotif{Data: quotaNotifData{NR: int32(unix.SYS_QUOTACTL_FD), Args: [6]uint64{7, cmd, uint64(quotaFirst)}}}
		if e := quotaOwnerSelector(q, quotaFirst); e != nil {
			t.Fatal(e)
		}
		for _, id := range []uint64{0, uint64(quotaFirst + 1), 1<<32 | uint64(quotaFirst)} {
			q.Data.Args[2] = id
			if e := quotaOwnerSelector(q, quotaFirst); e == nil {
				t.Fatal("wrong owner selector accepted")
			}
		}
	}
}
func TestQuotaBarrierRejectsSeccompKillableDAsFilesystemEvidence(t *testing.T) {
	status := "Name:\tsandboxd\nState:\tD (disk sleep)\n"
	raw := strconv.Itoa(unix.SYS_SYNCFS) + " 0x7 0 0 0 0 0"
	stack := "io_schedule\nfilemap_fdatawait_range\nsync_filesystem\n__x64_sys_syncfs\n"
	if !barrierKernelStack(status, raw, stack, 7) {
		t.Fatal("actual filesystem barrier not recognized")
	}
	for _, bad := range []struct {
		status, raw, stack string
		fd                 uint64
	}{
		{status, raw, "seccomp_do_user_notification\n__secure_computing\n", 7},
		{status, raw, stack + "seccomp", 7}, {strings.ReplaceAll(status, "D (", "S ("), raw, stack, 7},
		{status, "74 0x7", stack, 7}, {status, raw, stack, 8}, {status, raw, "__x64_sys_syncfs\n", 7},
	} {
		if barrierKernelStack(bad.status, bad.raw, bad.stack, bad.fd) {
			t.Fatal("non-filesystem or wrong syscall accepted")
		}
	}
}
func TestQuotaBarrierOwnerIsFixedAttemptedPreForkGeneration(t *testing.T) {
	r := sandbox.Ref{ID: strings.Repeat("1", 32), Generation: strings.Repeat("2", 32)}
	o := clearWindowOwner{Version: 3, Ref: r, UID: 480024, ProjectID: quotaFirst, QuotaAttempted: true}
	encode := func(o clearWindowOwner) []byte {
		b, e := json.Marshal(o)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	if e := decodeQuotaBarrierOwner(encode(o), r); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*clearWindowOwner){func(o *clearWindowOwner) { o.UID++ }, func(o *clearWindowOwner) { o.ProjectID++ }, func(o *clearWindowOwner) { o.QuotaAttempted = false }, func(o *clearWindowOwner) { o.InitializationAttempted = true }, func(o *clearWindowOwner) { o.Version = 4 }, func(o *clearWindowOwner) { o.Ref.Generation = strings.Repeat("a", 32) }} {
		bad := o
		change(&bad)
		if e := decodeQuotaBarrierOwner(encode(bad), r); e == nil {
			t.Fatal("invalid pre-fork owner accepted")
		}
	}
}
