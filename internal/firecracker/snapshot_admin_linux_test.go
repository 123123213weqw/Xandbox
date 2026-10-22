//go:build linux

package firecracker

import (
	"strings"
	"testing"
)

func TestSnapshotHostABINormalizesAndRejectsDifferentCPUs(t *testing.T) {
	cpu := "processor : 0\nvendor_id : GenuineIntel\ncpu family : 6\nmodel : 85\nstepping : 7\nmicrocode : 0x01\nflags : vmx sse fpu\n\nprocessor : 1\nvendor_id : GenuineIntel\ncpu family : 6\nmodel : 85\nstepping : 7\nmicrocode : 0x01\nflags : fpu vmx sse\n"
	a, e := snapshotHostABI("amd64", "kernel-pinned", cpu)
	if e != nil {
		t.Fatal(e)
	}
	b, e := snapshotHostABI("amd64", "kernel-pinned", strings.ReplaceAll(cpu, "vmx sse fpu", "fpu sse vmx"))
	if e != nil || a != b {
		t.Fatal("flag order changed ABI", e)
	}
	b, e = snapshotHostABI("amd64", "different-kernel", cpu)
	if e != nil || a == b {
		t.Fatal("host kernel change not fenced")
	}
	if _, e = snapshotHostABI("amd64", "kernel-pinned", strings.Replace(cpu, "0x01", "0x02", 1)); e == nil {
		t.Fatal("heterogeneous microcode accepted")
	}
	if _, e = snapshotHostABI("arm64", "kernel-pinned", cpu); e == nil {
		t.Fatal("unsupported portable restore accepted")
	}
}
