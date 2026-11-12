package installtxn

import (
	"bytes"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func stateFDInfoFixture(row string) []byte {
	return []byte("pos:\t0\nflags:\t02000002\nmnt_id:\t17\nino:\t99\n" + row)
}

func TestRuntimeStateFDInfoClosedHeaderAndSingleLock(t *testing.T) {
	row := "1: FLOCK ADVISORY WRITE 123 08:01:99 0 EOF\n"
	good := stateFDInfoFixture("lock:\t" + row)
	for _, kind := range []string{"valid", "spaces", "large-position", "no-lock", "two-locks", "unknown", "duplicate-header", "reordered-header", "wrong-inode", "zero-inode", "no-LF", "extra-LF", "leading-key-space", "blank-row", "flags-no-prefix", "flags-leading-zero", "flags-overflow", "position-overflow", "negative-position", "mount-zero", "mount-overflow", "inode-overflow", "NUL", "invalid-UTF8"} {
		t.Run(kind, func(t *testing.T) {
			raw := append([]byte(nil), good...)
			inode := uint64(99)
			switch kind {
			case "spaces":
				raw = bytes.ReplaceAll(raw, []byte("\t"), []byte("  "))
			case "large-position":
				raw = bytes.Replace(raw, []byte("pos:\t0"), []byte("pos:\t9223372036854775807"), 1)
			case "no-lock":
				raw = stateFDInfoFixture("")
			case "two-locks":
				raw = append(raw, []byte("lock:\t"+row)...)
			case "unknown":
				raw = append(raw, []byte("future:\tprivate-value\n")...)
			case "duplicate-header":
				raw = append(raw, []byte("ino:\t99\n")...)
			case "reordered-header":
				raw = bytes.Replace(raw, []byte("pos:\t0\nflags:\t02000002"), []byte("flags:\t02000002\npos:\t0"), 1)
			case "wrong-inode":
				inode++
			case "zero-inode":
				inode = 0
			case "no-LF":
				raw = raw[:len(raw)-1]
			case "extra-LF":
				raw = append(raw, '\n')
			case "leading-key-space":
				raw = bytes.Replace(raw, []byte("lock:"), []byte(" lock:"), 1)
			case "blank-row":
				raw = stateFDInfoFixture("lock:\t\n")
			case "flags-no-prefix":
				raw = bytes.Replace(raw, []byte("02000002"), []byte("2000002"), 1)
			case "flags-leading-zero":
				raw = bytes.Replace(raw, []byte("02000002"), []byte("002000002"), 1)
			case "flags-overflow":
				raw = bytes.Replace(raw, []byte("02000002"), []byte("040000000000"), 1)
			case "position-overflow":
				raw = bytes.Replace(raw, []byte("pos:\t0"), []byte("pos:\t9223372036854775808"), 1)
			case "negative-position":
				raw = bytes.Replace(raw, []byte("pos:\t0"), []byte("pos:\t-1"), 1)
			case "mount-zero":
				raw = bytes.Replace(raw, []byte("mnt_id:\t17"), []byte("mnt_id:\t0"), 1)
			case "mount-overflow":
				raw = bytes.Replace(raw, []byte("mnt_id:\t17"), []byte("mnt_id:\t2147483648"), 1)
			case "inode-overflow":
				raw = bytes.Replace(raw, []byte("ino:\t99"), []byte("ino:\t18446744073709551616"), 1)
			case "NUL", "invalid-UTF8":
				value := byte(0)
				if kind == "invalid-UTF8" {
					value = 255
				}
				raw = append([]byte{value}, raw...)
			}
			before := append([]byte(nil), raw...)
			got, e := stateFDInfoLockRecord(raw, inode)
			positive := kind == "valid" || kind == "spaces" || kind == "large-position"
			if (e == nil) != positive || !bytes.Equal(before, raw) {
				t.Fatal("closed fdinfo grammar/caller bytes changed", e)
			}
			if positive && string(got) != row {
				t.Fatal("kernel row fields changed")
			}
			if !positive && (got != nil || !errors.Is(e, ErrInventory) && !errors.Is(e, ErrConflict)) {
				t.Fatal("rejected record returned a witness", e)
			}
		})
	}
}

func TestRuntimeStateFDInfoExactByteCeilingAndFreshRows(t *testing.T) {
	row := "1: FLOCK ADVISORY WRITE 123 08:01:99 0 EOF\n"
	good := stateFDInfoFixture("lock:\t" + row)
	for _, n := range []int{stateFDInfoLimit - 1, stateFDInfoLimit, stateFDInfoLimit + 1} {
		raw := bytes.Replace(good, []byte("lock:\t"), []byte("lock:"+strings.Repeat(" ", n-len(good)+1)), 1)
		if len(raw) != n {
			t.Fatal("ceiling fixture length", strconv.Itoa(len(raw)))
		}
		got, e := stateFDInfoLockRecord(raw, 99)
		if (e == nil) != (n <= stateFDInfoLimit) || e == nil && string(got) != row || e != nil && got != nil {
			t.Fatal("byte cap changed or partial witness published", n, e)
		}
	}
	got, e := stateFDInfoLockRecord(good, 99)
	if e != nil {
		t.Fatal(e)
	}
	copy(good, bytes.Repeat([]byte{'x'}, len(good)))
	if string(got) != row {
		t.Fatal("returned row aliases caller buffer")
	}
	for n := 0; n < len(good); n++ {
		if got, e = stateFDInfoLockRecord(good[:n], 99); e == nil || got != nil {
			t.Fatal("truncated mutated bytes authorized", n)
		}
	}
}

func TestRuntimeStateFDDiscoveryNamesAreBoundedAndUnchanged(t *testing.T) {
	for _, kind := range []string{"empty", "valid", "maximum", "too-many", "duplicate", "negative", "plus", "leading-zero", "overflow", "path", "blank", "unicode"} {
		t.Run(kind, func(t *testing.T) {
			names := []string{"0", "1", "42", "2147483647"}
			switch kind {
			case "empty":
				names = nil
			case "maximum", "too-many":
				n := stateOwnerFDLimit
				if kind == "too-many" {
					n++
				}
				names = make([]string, n)
				for i := range names {
					names[i] = strconv.Itoa(i)
				}
			case "duplicate":
				names = append(names, "42")
			case "negative":
				names[0] = "-1"
			case "plus":
				names[0] = "+1"
			case "leading-zero":
				names[0] = "00"
			case "overflow":
				names[0] = "2147483648"
			case "path":
				names[0] = "../0"
			case "blank":
				names[0] = ""
			case "unicode":
				names[0] = "１２"
			}
			before := append([]string(nil), names...)
			e := stateFDNames(names)
			positive := kind == "empty" || kind == "valid" || kind == "maximum"
			if (e == nil) != positive || !reflect.DeepEqual(before, names) {
				t.Fatal("discovery list truncated, mutated or uncertain", e)
			}
		})
	}
}
