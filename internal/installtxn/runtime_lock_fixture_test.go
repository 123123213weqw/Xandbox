package installtxn

import (
	"strconv"
	"strings"
	"testing"
)

type runtimeLockTopologyCase struct{ name, raw, suffix string }

// Portable fixture construction contract: exercise ordinal redaction without
// accidentally corrupting the device/inode or changing the intended policy.
func runtimeLockTopologyCases() []runtimeLockTopologyCase {
	good := "1: FLOCK ADVISORY WRITE 123 08:01:99 0 EOF\n"
	other := "2: FLOCK ADVISORY WRITE 456 08:02:100 0 EOF\n"
	return []runtimeLockTopologyCase{
		{"exact-two", good + good, "/lock-rows-two/exact-text"},
		{"exact-three", strings.Repeat(good, 3), "/lock-rows-three/exact-text"},
		{"exact-many", strings.Repeat(good, 4), "/lock-rows-many/exact-text"},
		{"saturated", strings.Repeat(good, 4096), "/lock-rows-many/exact-text"},
		{"same-ordinal-whitespace", good + "1:\tFLOCK  ADVISORY WRITE 123 08:01:99 0 EOF\n", "/lock-rows-two/same-ordinal"},
		{"same-ordinal-number-spelling", good + "1: FLOCK ADVISORY WRITE 123 0008:0001:099 0 EOF\n", "/lock-rows-two/same-ordinal"},
		{"different-ordinal", good + "2:" + good[2:], "/lock-rows-two/different-ordinal"},
		{"different-ordinal-spelling", good + "01:" + good[2:], "/lock-rows-two/different-ordinal"},
		{"private-ordinal-never-retained", strings.Repeat("private-raw-ordinal:"+good[2:], 2), "/lock-rows-two/exact-text"},
		{"foreign-interleaved", good + other + good, "/lock-rows-two/exact-text"},
		{"mixed-three", good + good + "2:" + good[2:], "/lock-rows-three/different-ordinal"},
	}
}
func TestRuntimeStateLockDiagnosticFixtureColumnsKeepOriginalOwner(t *testing.T) {
	expected := []string{"exact-two", "exact-three", "exact-many", "saturated", "same-ordinal-whitespace", "same-ordinal-number-spelling", "different-ordinal", "different-ordinal-spelling", "private-ordinal-never-retained", "foreign-interleaved", "mixed-three"}
	cases := runtimeLockTopologyCases()
	if len(cases) != len(expected) {
		t.Fatal("topology cases dropped")
	}
	for i, c := range cases {
		if c.name != expected[i] {
			t.Fatal("topology cases changed")
		}
		matches := 0
		for _, line := range strings.Split(strings.TrimSuffix(c.raw, "\n"), "\n") {
			f := strings.Fields(line)
			if len(f) != 8 {
				t.Fatal("malformed intended-valid fixture row")
			}
			parts := strings.Split(f[5], ":")
			if len(parts) != 3 {
				t.Fatal("fixture identity shape")
			}
			major, a := strconv.ParseUint(parts[0], 16, 32)
			minor, b := strconv.ParseUint(parts[1], 16, 32)
			inode, e := strconv.ParseUint(parts[2], 10, 64)
			if a != nil || b != nil || e != nil || major != 8 {
				t.Fatal("fixture identity was corrupted")
			}
			if f[1] != "FLOCK" || f[2] != "ADVISORY" || f[3] != "WRITE" || f[6] != "0" || f[7] != "EOF" {
				t.Fatal("fixture lock policy was corrupted")
			}
			if minor == 2 && inode == 100 && f[4] == "456" && c.name == "foreign-interleaved" {
				continue
			}
			if minor != 1 || inode != 99 || f[4] != "123" {
				t.Fatal("fixture no longer targets original owner")
			}
			matches++
			if c.name == "private-ordinal-never-retained" && (f[0] != "private-raw-ordinal:" || f[5] != "08:01:99") {
				t.Fatal("ordinal redaction case changed non-ordinal columns")
			}
		}
		if matches < 2 {
			t.Fatal("ambiguity fixture lost duplicate matches")
		}
	}
	// The original blanket replacement also matches the minor-device separator.
	// Keep a counterexample so this fixture-construction mistake cannot return.
	broken := strings.ReplaceAll("1: FLOCK ADVISORY WRITE 123 08:01:99 0 EOF\n", "1:", "private-raw-ordinal:")
	field := strings.Fields(broken)[5]
	parts := strings.Split(field, ":")
	if field == "08:01:99" || len(parts) != 3 {
		t.Fatal("broken-fixture counterexample changed")
	}
	if _, e := strconv.ParseUint(parts[1], 16, 32); e == nil {
		t.Fatal("broken blanket replacement did not corrupt minor-device syntax")
	}
}
