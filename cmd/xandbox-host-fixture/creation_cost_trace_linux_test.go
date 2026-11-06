//go:build linux && xandbox_host_fixture

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

func TestCreationCostFixedSyscallBoundaryParser(t *testing.T) {
	for _, id := range []int{74, 306, 443, 277, 0, 232, -1} {
		v := fmt.Sprintf("%d 0x1 0x2 0x3 0x4 0x5 0x6 0x7 0x8\n", id)
		if id == -1 {
			v = "-1 0x1 0x2\n"
		}
		got, e := costSelectedSyscall([]byte(v))
		if e != nil || got != (id == 74 || id == 306 || id == 443 || id == 277) {
			t.Fatal(id, got, e)
		}
	}
}
func TestCreationCostBoundaryMalformedFailsClosed(t *testing.T) {
	for _, v := range []string{"", "running", "74", "-1", "-2 0x1 0x2", "74 0x1 0x2", "74 0x1 0x2 0x3 0x4 0x5 0x6 0x7 bad", "-1 0x1 0x10000000000000000"} {
		if _, e := costSelectedSyscall([]byte(v)); e == nil {
			t.Fatal("malformed boundary accepted", v)
		}
	}
}
func TestCreationCostPrivateConsoleFramesReassembleExact(t *testing.T) {
	for _, n := range []int{1, 2047, 2048, 2049, 8191, 1 << 20} {
		b := bytes.Repeat([]byte("Z"), n)
		rows, e := costPackets("checkpoint", b)
		if e != nil {
			t.Fatal(e)
		}
		var out []byte
		sum := sha256.Sum256(b)
		for i, row := range rows {
			var x struct {
				Scope                string
				Index, Chunks, Bytes int
				SHA256, Data         string
			}
			if e = json.Unmarshal(row, &x); e != nil {
				t.Fatal(e)
			}
			if x.Scope != "checkpoint" || x.Index != i || x.Chunks != len(rows) || x.Bytes != n || x.SHA256 != hex.EncodeToString(sum[:]) || len(row) > 4096 {
				t.Fatal("frame metadata")
			}
			data, e := base64.StdEncoding.Strict().DecodeString(x.Data)
			if e != nil {
				t.Fatal(e)
			}
			out = append(out, data...)
		}
		if !bytes.Equal(out, b) {
			t.Fatal("payload mismatch")
		}
	}
}
func TestCreationCostPrivateFrameBounds(t *testing.T) {
	for _, x := range []struct {
		scope string
		data  []byte
	}{{"arbitrary", []byte("x")}, {"cold", nil}, {"checkpoint", make([]byte, (1<<20)+1)}} {
		if _, e := costPackets(x.scope, x.data); e == nil {
			t.Fatal("unbounded/unknown packet accepted")
		}
	}
}
func TestCreationCostObserverRefusesOrdinaryHostBeforeAnyTraceOrSignal(t *testing.T) {
	if requireNode() == nil {
		t.Fatal("host-refusal test must run outside the owned L1")
	}
	if _, e := startCreationCostTraceForMode(creationCostObserve, 1, "checkpoint"); e == nil {
		t.Fatal("ordinary host trace enabled")
	}
}
func TestCreationCostNilCloseHasNoEffect(t *testing.T) {
	var p *creationCostTrace
	if e := p.close(); e != nil {
		t.Fatal(e)
	}
}
func TestCreationCostFixedEventSet(t *testing.T) {
	want := []string{"syscalls/sys_enter_quotactl_fd", "syscalls/sys_exit_quotactl_fd", "syscalls/sys_enter_syncfs", "syscalls/sys_exit_syncfs", "syscalls/sys_enter_fsync", "syscalls/sys_exit_fsync", "syscalls/sys_enter_sync_file_range", "syscalls/sys_exit_sync_file_range", "task/task_newtask"}
	if len(want) != len(costTraceEvents) {
		t.Fatal("event count")
	}
	for i := range want {
		if want[i] != costTraceEvents[i] {
			t.Fatal("event selector changed")
		}
	}
}

func TestCreationCostAnchorSnapshotRefusesOrdinaryHost(t *testing.T) {
	if requireNode() == nil {
		t.Fatal("host-only refusal expected")
	}
	if _, e := costAnchors(1); e == nil {
		t.Fatal("host FD inspection enabled")
	}
}
