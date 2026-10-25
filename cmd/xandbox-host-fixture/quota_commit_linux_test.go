//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"encoding/binary"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestFixedCommitModesAndBoundaryRecords(t *testing.T) {
	modes := []quotaCommitMode{quotaReserveHold, quotaReserveEIO, quotaReleasePreHold, quotaReleasePostHold}
	phases := []string{quotaBarrierPhase, "reserve-quota-syncfs-real-eio", "release-preclear-quota-syncfs-held", "release-postclear-quota-syncfs-held"}
	ordinals := []int{1, 1, 2, 3}
	sets := []int{1, 1, 1, 2}
	limits := quotaRecord{BHard: 192 << 10, IHard: 128}
	for i, m := range modes {
		if m.phase() != phases[i] || m.ordinal() != ordinals[i] || expectedCommitSets(m) != sets[i] || m.release() != (i >= 2) {
			t.Fatal("wrong fixed mode")
		}
		good := limits
		if m == quotaReleasePostHold {
			good = quotaRecord{}
		}
		if e := validateCommitBoundary(m, good); e != nil {
			t.Fatal(e)
		}
		bad := good
		bad.Space = 1
		if e := validateCommitBoundary(m, bad); (e == nil) != (m == quotaReleasePreHold) {
			t.Fatal("wrong usage boundary")
		}
		for _, change := range []func(*quotaRecord){func(r *quotaRecord) { r.BHard++ }, func(r *quotaRecord) { r.BSoft = 1 }, func(r *quotaRecord) { r.ISoft = 1 }, func(r *quotaRecord) { r.IHard++ }, func(r *quotaRecord) { r.BTime = 1 }, func(r *quotaRecord) { r.ITime = 1 }, func(r *quotaRecord) { r.Space = 193 << 20 }, func(r *quotaRecord) { r.Inodes = 129 }} {
			bad = good
			change(&bad)
			if validateCommitBoundary(m, bad) == nil {
				t.Fatal("unknown limits/usage accepted")
			}
		}
	}
	for _, m := range []quotaCommitMode{4, 255} {
		if m.phase() != "" || m.ordinal() != 0 || m.release() || expectedCommitSets(m) != 0 || validateCommitBoundary(m, quotaRecord{}) == nil {
			t.Fatal("unknown mode accepted")
		}
	}
}
func TestCommitFaultsAndExitObserverCannotRunOnL0(t *testing.T) {
	n := &node{}
	for _, m := range []quotaCommitMode{quotaReserveEIO, quotaReleasePreHold, quotaReleasePostHold, 255} {
		if _, e := n.quotaBarrierCheckpointOn(context.Background(), m); e == nil {
			t.Fatal("L0 checkpoint")
		}
		if _, e := n.recoverQuotaBarrierOn(context.Background(), m); e == nil {
			t.Fatal("L0 recovery")
		}
	}
	for _, op := range []string{"quota-commit-eio-checkpoint", "quota-commit-eio-recover", "quota-preclear-hold-checkpoint", "quota-preclear-hold-recover", "quota-postclear-hold-checkpoint", "quota-postclear-hold-recover"} {
		if (nodeRequest{Version: 1, Operation: op}).validate() != nil {
			t.Fatal("fixed op rejected")
		}
		if (nodeRequest{Version: 1, Operation: op, Phase: "2"}).validate() == nil {
			t.Fatal("arbitrary target")
		}
	}
	if _, e := quotaBPF(unix.BPF_MAP_CREATE, make([]byte, 72)); e == nil {
		t.Fatal("L0 BPF")
	}
	if _, e := (&quotaNotifier{}).startExitTrace(quotaNotif{}); e == nil {
		t.Fatal("L0 trace")
	}
	if _, e := (&quotaExitTrace{}).read(); e == nil {
		t.Fatal("L0 map read")
	}
}

// A deliberately small interpreter checks the exact emitted instruction stream,
// not a second high-level implementation of the observer. It never loads BPF.
func emulateQuotaExit(t *testing.T, p []quotaBPFInstruction, pidtid uint64, nr, ret int64, seen uint64, probeFail, lookupFail bool) quotaExitResult {
	t.Helper()
	mem := map[uint64]byte{}
	put := func(a, v uint64, n int) {
		for i := 0; i < n; i++ {
			mem[a+uint64(i)] = byte(v >> (8 * i))
		}
	}
	get := func(a uint64, n int) uint64 {
		var v uint64
		for i := 0; i < n; i++ {
			v |= uint64(mem[a+uint64(i)]) << (8 * i)
		}
		return v
	}
	const raw, regs, value, stack = uint64(0x100), uint64(0x1000), uint64(0x2000), uint64(0x3000)
	put(raw, regs, 8)
	put(raw+8, uint64(ret), 8)
	put(regs+120, uint64(nr), 8)
	put(value, seen, 8)
	put(value+8, 42, 8)
	r := [11]uint64{}
	r[1] = raw
	r[10] = stack
	for pc, steps := 0, 0; pc < len(p) && steps < 64; pc, steps = pc+1, steps+1 {
		x := p[pc]
		d, s := x.Registers&15, x.Registers>>4
		if d > 10 || s > 10 {
			t.Fatal("bad register")
		}
		addr := func() uint64 { return r[s] + uint64(int64(x.Offset)) }
		switch x.Code {
		case 0xbf:
			r[d] = r[s]
		case 0xb7:
			r[d] = uint64(int64(x.Immediate))
		case 0x07:
			r[d] += uint64(int64(x.Immediate))
		case 0x18:
			if pc+1 >= len(p) || p[pc+1].Code != 0 {
				t.Fatal("bad LDDW")
			}
			r[d] = uint64(uint32(x.Immediate)) | uint64(uint32(p[pc+1].Immediate))<<32
			pc++
		case 0x79:
			r[d] = get(addr(), 8)
		case 0x62:
			put(r[d]+uint64(int64(x.Offset)), uint64(uint32(x.Immediate)), 4)
		case 0x7b:
			put(r[d]+uint64(int64(x.Offset)), r[s], 8)
		case 0xdb:
			a := r[d] + uint64(int64(x.Offset))
			put(a, get(a, 8)+r[s], 8)
		case 0x5d:
			if r[d] != r[s] {
				pc += int(x.Offset)
			}
		case 0x55:
			if r[d] != uint64(int64(x.Immediate)) {
				pc += int(x.Offset)
			}
		case 0x15:
			if r[d] == uint64(int64(x.Immediate)) {
				pc += int(x.Offset)
			}
		case 0x85:
			switch x.Immediate {
			case 14:
				r[0] = pidtid
			case 113:
				if probeFail {
					r[0] = 1
				} else {
					if r[2] != 8 || r[3] != regs+120 {
						t.Fatal("unexpected kernel read")
					}
					put(r[1], get(r[3], 8), 8)
					r[0] = 0
				}
			case 1:
				if get(r[2], 4) != 0 {
					t.Fatal("nonzero map key")
				}
				r[0] = value
				if lookupFail {
					r[0] = 0
				}
			default:
				t.Fatal("unexpected helper")
			}
			r[1], r[2], r[3], r[4], r[5] = 0, 0, 0, 0, 0
		case 0x95:
			return quotaExitResult{Seen: get(value, 8), Return: int64(get(value+8, 8))}
		default:
			t.Fatalf("unexpected opcode %x", x.Code)
		}
	}
	t.Fatal("unterminated program")
	return quotaExitResult{}
}
func TestQuotaExitInstructionABIAndExactFirstReturn(t *testing.T) {
	if unsafe.Sizeof(quotaBPFInstruction{}) != 8 || unsafe.Sizeof(quotaExitResult{}) != 16 || unsafe.Offsetof(quotaExitResult{}.Return) != 8 {
		t.Fatal("unexpected native UAPI layout")
	}
	p, e := quotaExitProgram(17, 110, 111)
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][3]int{{-1, 110, 111}, {17, 0, 111}, {17, 110, 0}, {17, 1 << 31, 111}} {
		if _, e := quotaExitProgram(bad[0], bad[1], bad[2]); e == nil {
			t.Fatal("invalid program target")
		}
	}
	var encoded [8]byte
	binary.LittleEndian.PutUint32(encoded[4:], uint32(p[0].Immediate))
	if p[0].Code != 0xbf || p[0].Registers != 0x16 {
		t.Fatal("raw context not saved")
	}
	identity := uint64(110)<<32 | 111
	for _, ret := range []int64{-int64(unix.EIO), 0, -int64(unix.ENOSPC)} {
		got := emulateQuotaExit(t, p, identity, int64(unix.SYS_SYNCFS), ret, 0, false, false)
		if got.Seen != 1 || got.Return != ret {
			t.Fatal("return changed or not observed", got)
		}
	}
	for _, tc := range []struct {
		id            uint64
		nr            int64
		seen          uint64
		probe, lookup bool
	}{{identity + 1, int64(unix.SYS_SYNCFS), 0, false, false}, {identity + (1 << 32), int64(unix.SYS_SYNCFS), 0, false, false}, {identity, 74, 0, false, false}, {identity, int64(unix.SYS_SYNCFS), 1, false, false}, {identity, int64(unix.SYS_SYNCFS), 0, true, false}, {identity, int64(unix.SYS_SYNCFS), 0, false, true}} {
		got := emulateQuotaExit(t, p, tc.id, tc.nr, -5, tc.seen, tc.probe, tc.lookup)
		if got.Seen != tc.seen || got.Return != 42 {
			t.Fatal("foreign/later/failed-read event overwrote latch", got)
		}
	}
}
