//go:build linux

package installtxn

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRuntimeStateProofLockRowTopologyKeepsExactOwnerPredicate(t *testing.T) {
	id := runtimeStateIdentity{LockDevice: unix.Mkdev(8, 1), LockInode: 99}
	good := "1: FLOCK ADVISORY WRITE 123 08:01:99 0 EOF\n"
	other := "2: FLOCK ADVISORY WRITE 456 08:02:100 0 EOF\n"
	cases := []struct{ name, raw, suffix string }{
		{"exact-two", good + good, "/lock-rows-two/exact-text"},
		{"exact-three", strings.Repeat(good, 3), "/lock-rows-three/exact-text"},
		{"exact-many", strings.Repeat(good, 4), "/lock-rows-many/exact-text"},
		{"saturated", strings.Repeat(good, 4096), "/lock-rows-many/exact-text"},
		{"same-ordinal-whitespace", good + "1:\tFLOCK  ADVISORY WRITE 123 08:01:99 0 EOF\n", "/lock-rows-two/same-ordinal"},
		{"same-ordinal-number-spelling", good + "1: FLOCK ADVISORY WRITE 123 0008:0001:099 0 EOF\n", "/lock-rows-two/same-ordinal"},
		{"different-ordinal", good + "2:" + good[2:], "/lock-rows-two/different-ordinal"},
		{"different-ordinal-spelling", good + "01:" + good[2:], "/lock-rows-two/different-ordinal"},
		{"private-ordinal-never-retained", strings.ReplaceAll(good+good, "1:", "private-raw-ordinal:"), "/lock-rows-two/exact-text"},
		{"foreign-interleaved", good + other + good, "/lock-rows-two/exact-text"},
		{"mixed-three", good + good + "2:" + good[2:], "/lock-rows-three/different-ordinal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			old := originalStateKernelLockOwnerCe053([]byte(c.raw), id, 123)
			got := stateKernelLockOwner([]byte(c.raw), id, 123)
			if !errors.Is(old, ErrConflict) || !errors.Is(got, ErrConflict) || errors.Is(got, ErrInventory) || got.Error() != "runtime proof:/state-lock-owner-ambiguous"+c.suffix {
				t.Fatal("old rejection waived or topology not exact")
			}
			var e *runtimeProofError
			if !errors.As(got, &e) || e.stage != proofStateLockOwnerAmbiguous {
				t.Fatal("typed ambiguity cause lost")
			}
		})
	}
}

func TestRuntimeStateProofLockRowDiagnosticsNeverHideLaterRejection(t *testing.T) {
	id := runtimeStateIdentity{LockDevice: unix.Mkdev(8, 1), LockInode: 99}
	good := "1: FLOCK ADVISORY WRITE 123 08:01:99 0 EOF\n"
	bad := []string{
		"partial\n", "\n", "8: FLOCK ADVISORY WRITE 456 08:xx:100 0 EOF\n",
		"2: -> FLOCK ADVISORY WRITE 123 08:01:99 0 EOF\n",
		"2: FLOCK ADVISORY WRITE 124 08:01:99 0 EOF\n",
		"2: POSIX ADVISORY WRITE 123 08:01:99 0 EOF\n",
		"2: FLOCK ADVISORY READ 123 08:01:99 0 EOF\n",
		"2: FLOCK ADVISORY WRITE 123 08:01:99 1 EOF\n",
	}
	for _, tail := range bad {
		for _, raw := range []string{tail + good + good, good + tail + good, good + good + tail} {
			old, got := originalStateKernelLockOwnerCe053([]byte(raw), id, 123), stateKernelLockOwner([]byte(raw), id, 123)
			if old == nil || got == nil || errors.Is(old, ErrConflict) != errors.Is(got, ErrConflict) || errors.Is(old, ErrInventory) != errors.Is(got, ErrInventory) || strings.Contains(got.Error(), "/lock-rows-") {
				t.Fatal("early ambiguity classification bypassed an original predicate")
			}
		}
	}
	// Different permutations/ordinals/foreign rows retain the independent old
	// parser's decision; row topology never becomes authority or a dedup rule.
	rows := []string{good, good, "7:" + good[2:], "9: FLOCK ADVISORY WRITE 456 08:02:100 0 EOF\n"}
	for a := range rows {
		for b := range rows {
			for c := range rows {
				raw := []byte(rows[a] + rows[b] + rows[c])
				old, got := originalStateKernelLockOwnerCe053(raw, id, 123), stateKernelLockOwner(raw, id, 123)
				if (old == nil) != (got == nil) || errors.Is(old, ErrConflict) != errors.Is(got, ErrConflict) || errors.Is(old, ErrInventory) != errors.Is(got, ErrInventory) {
					t.Fatal("row arrangement changed old authority")
				}
			}
		}
	}
}
