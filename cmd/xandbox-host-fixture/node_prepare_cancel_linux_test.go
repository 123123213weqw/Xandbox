//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

func nodeCancelEvents() []prepareTraceEvent {
	rows := []struct {
		p     string
		g, ax uint64
	}{
		{"enter", 1, 99}, {"selected", 1, 0}, {"ok", 1, 0}, {"node_ok", 1, 0},
		{"enter", 2, 99}, {"enter", 3, 99}, {"selected", 2, 1}, {"cancel", 2, 123},
		{"release", 1, 99}, {"released", 1, 0}, {"selected", 3, 0}, {"ok", 3, 0}, {"node_ok", 3, 0}, {"release", 3, 99}, {"released", 3, 0},
	}
	var out []prepareTraceEvent
	for i, r := range rows {
		out = append(out, prepareTraceEvent{tid: i + 1, cpu: i % 8, nanos: uint64(i + 1), name: r.p, g: r.g, ax: r.ax})
	}
	return out
}
func TestNodeCancelTraceRequiresUnconsumedCancellationAndRealSerialPermit(t *testing.T) {
	valid := nodeCancelEvents()
	for n, want := range map[int][3]int{0: {0, 0, 0}, 4: {4, 0, 0}, 5: {4, 1, 0}, 6: {4, 1, 1}, 8: {4, 3, 1}, 15: {6, 3, 6}} {
		s, e := validateNodeCancelTrace(valid[:n])
		if e != nil || s.Stages != want {
			t.Fatal(n, s, e)
		}
	}
	complete := func(events []prepareTraceEvent) bool {
		s, e := validateNodeCancelTrace(events)
		return e == nil && len(events) == 15 && s.Stages == [3]int{6, 3, 6} && s.Held == 0
	}
	if !complete(valid) {
		t.Fatal("valid canceled waiter")
	}
	for i := range valid {
		for _, mode := range []string{"omit", "duplicate", "foreign-g", "foreign-point"} {
			t.Run(fmt.Sprintf("%d-%s", i, mode), func(t *testing.T) {
				e := append([]prepareTraceEvent(nil), valid...)
				switch mode {
				case "omit":
					e = append(e[:i], e[i+1:]...)
				case "duplicate":
					e = append(e, e[i])
				case "foreign-g":
					e[i].g = 999
				case "foreign-point":
					e[i].name = "race_release"
				}
				if complete(e) {
					t.Fatal("missing/foreign transition accepted")
				}
			})
		}
	}
	for _, change := range []func([]prepareTraceEvent){
		func(e []prepareTraceEvent) { e[6].ax = 0 }, func(e []prepareTraceEvent) { e[7].ax = 0 },
		func(e []prepareTraceEvent) { e[8].ax = 100 }, func(e []prepareTraceEvent) { e[4].ax = 100 },
		func(e []prepareTraceEvent) { e[8], e[6] = e[6], e[8] }, func(e []prepareTraceEvent) { e[10], e[8] = e[8], e[10] },
		func(e []prepareTraceEvent) { e[0].g = 0 },
	} {
		e := append([]prepareTraceEvent(nil), valid...)
		change(e)
		if complete(e) {
			t.Fatal("bad gate/branch/release accepted")
		}
	}
	rows := normalizedNodeCancelTrace(valid)
	for i, row := range rows {
		want := 2
		if valid[i].name == "selected" {
			want = 3
		}
		if len(row) != want {
			t.Fatal("raw identity or register exported")
		}
	}
	bad := append([]prepareTraceEvent(nil), valid...)
	bad[6].ax = 0xfeedbeef
	row := normalizedNodeCancelTrace(bad)[6]
	if _, ok := row["selected_case"]; ok || row["selected_case_invalid"] != true {
		t.Fatal("unexpected raw register escaped normalization")
	}
}
func TestNodePrepareWriteFilterOnlyBoundedWritesPreservesArchitectureGuards(t *testing.T) {
	p, e := nodePrepareCopyProgram()
	if e != nil {
		t.Fatal(e)
	}
	run := func(arch, nr uint32, count uint64) uint32 {
		var a uint32
		for pc := 0; pc < len(p); pc++ {
			i := p[pc]
			switch i.Code {
			case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
				switch i.K {
				case 0:
					a = nr
				case 4:
					a = arch
				case 32:
					a = uint32(count)
				case 36:
					a = uint32(count >> 32)
				default:
					t.Fatal("unexpected data/pointer fetch")
				}
			case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
				if a == i.K {
					pc += int(i.Jt)
				} else {
					pc += int(i.Jf)
				}
			case unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K:
				if a >= i.K {
					pc += int(i.Jt)
				} else {
					pc += int(i.Jf)
				}
			case unix.BPF_JMP | unix.BPF_JGT | unix.BPF_K:
				if a > i.K {
					pc += int(i.Jt)
				} else {
					pc += int(i.Jf)
				}
			case unix.BPF_RET | unix.BPF_K:
				return i.K
			default:
				t.Fatal("unexpected BPF instruction")
			}
		}
		t.Fatal("filter escaped")
		return 0
	}
	for _, count := range []uint64{1, 64, 4096, copyChunk} {
		if run(unix.AUDIT_ARCH_X86_64, unix.SYS_WRITE, count) != unix.SECCOMP_RET_USER_NOTIF {
			t.Fatal("bounded metadata/workspace write not observed")
		}
	}
	for _, count := range []uint64{0, copyChunk + 1, 1 << 32, 1<<32 | copyChunk} {
		if run(unix.AUDIT_ARCH_X86_64, unix.SYS_WRITE, count) != unix.SECCOMP_RET_ALLOW {
			t.Fatal("unexpected unbounded write trap")
		}
	}
	for _, nr := range []uint32{unix.SYS_READ, unix.SYS_FSYNC, unix.SYS_QUOTACTL_FD} {
		if run(unix.AUDIT_ARCH_X86_64, nr, copyChunk) != unix.SECCOMP_RET_ALLOW {
			t.Fatal("unrelated syscall changed")
		}
	}
	for _, arch := range []uint32{unix.AUDIT_ARCH_I386, unix.AUDIT_ARCH_AARCH64} {
		if run(arch, unix.SYS_WRITE, 1) != unix.SECCOMP_RET_KILL_PROCESS {
			t.Fatal("architecture guard lost")
		}
	}
	if run(unix.AUDIT_ARCH_X86_64, unix.SYS_WRITE|1<<30, 1) != unix.SECCOMP_RET_KILL_PROCESS {
		t.Fatal("x32 guard lost")
	}
}
func TestNodePrepareCancellationRoutesRejectSharedL0(t *testing.T) {
	ctx := context.Background()
	n := &node{}
	if runNodePrepareCopyDaemon() == nil {
		t.Fatal("child escaped L1")
	}
	if _, e := n.startNodePrepareObserved(ctx); e == nil {
		t.Fatal("start escaped L1")
	}
	if _, e := n.nodePrepareCancel(ctx); e == nil {
		t.Fatal("case escaped L1")
	}
	if _, _, e := nodePrepareRecord("x"); e == nil {
		t.Fatal("ledger scan escaped L1")
	}
	if _, e := nodePrepareGroupEmpty(sandbox.Ref{}); e == nil {
		t.Fatal("cgroup scan escaped L1")
	}
	if n.stopNodePrepareObserved(ctx, nil, false) == nil {
		t.Fatal("stop escaped L1")
	}
	o := &nodePrepareCopyObserver{}
	if o.heldValid() == nil {
		t.Fatal("held observer escaped L1")
	}
	q := nodeRequest{Version: 1, Operation: "node-prepare-cancel"}
	if e := q.validate(); e != nil {
		t.Fatal(e)
	}
	q.Phase = "unbounded"
	if q.validate() == nil {
		t.Fatal("phase accepted")
	}
}
