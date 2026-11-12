//go:build linux

package installtxn

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"strconv"
	"strings"
	"testing"
)

// Independent exact ce053ce parser oracle. Do not call the candidate from it.
func originalStateKernelLockOwnerCe053(raw []byte, id runtimeStateIdentity, pid int) error {
	if len(raw) == 0 || len(raw) > 4<<20 || raw[len(raw)-1] != '\n' {
		return ErrInventory
	}
	found := 0
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		v := strings.Fields(line)
		blocked := len(v) == 9 && v[1] == "->"
		if blocked {
			v = append(v[:1], v[2:]...)
		}
		if len(v) != 8 {
			return ErrInventory
		}
		parts := strings.Split(v[5], ":")
		if len(parts) != 3 {
			return ErrInventory
		}
		major, a := strconv.ParseUint(parts[0], 16, 32)
		minor, b := strconv.ParseUint(parts[1], 16, 32)
		inode, c := strconv.ParseUint(parts[2], 10, 64)
		if a != nil || b != nil || c != nil {
			return ErrInventory
		}
		if major != uint64(unix.Major(id.LockDevice)) || minor != uint64(unix.Minor(id.LockDevice)) || inode != id.LockInode {
			continue
		}
		if blocked || v[1] != "FLOCK" || v[2] != "ADVISORY" || v[3] != "WRITE" || v[4] != strconv.Itoa(pid) || v[6] != "0" || v[7] != "EOF" {
			return ErrConflict
		}
		found++
	}
	if found != 1 {
		return ErrConflict
	}
	return nil
}

func TestRuntimeStateProofKernelParserMatchesIndependentOriginal(t *testing.T) {
	id := runtimeStateIdentity{LockDevice: unix.Mkdev(8, 1), LockInode: 99}
	good := "1: FLOCK ADVISORY WRITE 123 08:01:99 0 EOF\n"
	raw := [][]byte{[]byte(good), nil, []byte("\n"), []byte(good + good), []byte(strings.Replace(good, "123", "124", 1)), []byte("9: FLOCK ADVISORY WRITE 124 08:02:100 0 EOF\n"), []byte("2: -> " + good[3:]), []byte(good[:len(good)-1])}
	words := strings.Fields(good)
	for i := range words {
		for _, value := range []string{"", "-1", "18446744073709551616", "0", "123", "POSIX", "OFDLCK", "READ", "08:01:99", "08:xx:99", "1:2:3:4", "\u212a", "\x00", " ", "EOF"} {
			row := append([]string(nil), words...)
			row[i] = value
			raw = append(raw, []byte(strings.Join(row, " ")+"\n"))
		}
	}
	seed := uint32(0x19f4a3)
	for n := 0; n < 4096; n++ {
		b := []byte(good)
		for k := 0; k < 1+n%5; k++ {
			seed = 1664525*seed + 1013904223
			b[int(seed)%len(b)] = byte(seed >> 24)
		}
		raw = append(raw, b)
	}
	for _, n := range []int{4<<20 - 1, 4 << 20, 4<<20 + 1} {
		b := make([]byte, n)
		copy(b, good)
		b[n-1] = '\n'
		raw = append(raw, b)
	}
	for i, b := range raw {
		old, got := originalStateKernelLockOwnerCe053(b, id, 123), stateKernelLockOwner(b, id, 123)
		if (old == nil) != (got == nil) || errors.Is(old, ErrConflict) != errors.Is(got, ErrConflict) || errors.Is(old, ErrInventory) != errors.Is(got, ErrInventory) {
			t.Fatal("old decision changed", i)
		}
	}
	cases := []struct {
		raw   string
		label string
	}{
		{"8: FLOCK ADVISORY WRITE 1 08:02:100 0 EOF\n", "state-lock-owner-missing"},
		{good + good, "state-lock-owner-ambiguous/lock-rows-two/exact-text"},
		{strings.Replace(good, "123", "124", 1), "state-lock-owner-mismatch"},
		{strings.TrimSuffix(good, "\n"), "state-lock-record-syntax"},
	}
	for _, c := range cases {
		e := stateKernelLockOwner([]byte(c.raw), id, 123)
		if e == nil || e.Error() != "runtime proof:/"+c.label {
			t.Fatal("not specific fixed kernel phase", c.label, e)
		}
	}
}
func TestRuntimeStateProofActualStopReportsFixedPresignalCutAndKeepsCause(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	x.drain(t, s)
	cause := errors.New("private-raw-path-or-process-description")
	x.f.hook = func(at string) error {
		if at == "runtime-stop-before-"+IngressUnit {
			return cause
		}
		return nil
	}
	result, e := x.stop(context.Background(), s, x.client)
	if !errors.Is(e, cause) || e.Error() != "runtime proof:/stop-before-signal-cut" || result.ExecutionStopped || len(x.jobs) != 0 {
		t.Fatal("wrong effect/provenance", e, x.jobs)
	}
}
