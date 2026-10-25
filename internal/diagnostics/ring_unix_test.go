//go:build linux || darwin

package diagnostics

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "diagnostics")
	if e := os.Mkdir(d, 0700); e != nil {
		t.Fatal(e)
	}
	return d
}
func testEvent(n int64) Event {
	return Event{Kind: PrepareFailed, Reason: Other, TimeNS: n, DroppedBefore: uint64(n)}
}
func testRing(t *testing.T, dir string) *ring {
	t.Helper()
	r, e := openRing(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.close() })
	return r
}
func TestRingWrapRestartAndPrivateBoundedView(t *testing.T) {
	dir := testDir(t)
	r, e := openRing(dir)
	if e != nil {
		t.Fatal(e)
	}
	for i := int64(1); i <= 300; i++ {
		if e = r.append(testEvent(i)); e != nil {
			t.Fatal(e)
		}
	}
	if other, e := Start(dir); e == nil {
		other.Close(context.Background())
		t.Fatal("second writer")
	}
	view, e := Read(dir)
	if e != nil {
		t.Fatal(e)
	}
	if view.ObservedSequence != 300 || view.Overwritten != 172 || view.RetainedCapacity != 128 || len(view.Records) != 128 {
		t.Fatal(view)
	}
	if view.Records[0].Sequence != 173 || view.Records[127].Sequence != 300 {
		t.Fatal("window")
	}
	// Read uses an independently opened read-only FD and cannot append/publish.
	f, e := openNamed(dir, "events.ring", RingBytes, unix.O_RDONLY)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.WriteAt([]byte{1}, 0); e == nil {
		t.Fatal("reader fd writable")
	}
	f.Close()
	info, _ := os.Stat(filepath.Join(dir, "events.ring"))
	lock, _ := os.Stat(filepath.Join(dir, "logger.lock"))
	if info.Size() != RingBytes || info.Mode().Perm() != 0600 || lock.Size() != 0 || lock.Mode().Perm() != 0600 {
		t.Fatal(info, lock)
	}
	raw, _ := json.Marshal(view)
	if !bytes.Contains(raw, []byte(`"kind":"prepare_failed"`)) || len(raw) > 32768 {
		t.Fatal("bounded closed JSON view")
	}
	if e = r.close(); e != nil {
		t.Fatal(e)
	}
	again, e := Start(dir)
	if e != nil {
		t.Fatal(e)
	}
	if !again.Emit(ProcessStopped, Other) {
		t.Fatal("emit")
	}
	closeTest(t, again)
	view, e = Read(dir)
	if e != nil || view.ObservedSequence != 302 || view.Records[127].Event.Kind != CollectorClosed {
		t.Fatal(view, e)
	}
	names, e := names(dir)
	if e != nil || len(names) != 2 {
		t.Fatal(names, e)
	}
}
func TestStagingAndTornHeaderLeaveCommittedWindow(t *testing.T) {
	dir := testDir(t)
	r := testRing(t, dir)
	for i := int64(1); i <= 200; i++ {
		if e := r.append(testEvent(i)); e != nil {
			t.Fatal(e)
		}
	}
	before, e := Read(dir)
	if e != nil {
		t.Fatal(e)
	}
	// Unit simulation ONLY: data stage exists but no valid published header.
	// This is not a claim of a physical media crash or durability fault test.
	b := encodeRecord(201, testEvent(201))
	if _, e = r.file.WriteAt(b[:], slot(201)); e != nil {
		t.Fatal(e)
	}
	if e = r.file.Sync(); e != nil {
		t.Fatal(e)
	}
	after, e := Read(dir)
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("stage changed committed view", e)
	}
	h := encodeHeader(header{seq: 201, scope: r.head.scope})
	h[25] ^= 1
	if _, e = r.file.WriteAt(h[:], HeaderBytes); e != nil {
		t.Fatal(e)
	}
	r.file.Sync()
	after, e = Read(dir)
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("torn inactive header changed window", e)
	}
	// Normal production open chooses the valid prior header and replaces only
	// the unpublished staging slot. No journal/lock repair in this test.
	r.close()
	r2, e := openRing(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer r2.close()
	if r2.head.seq != 200 {
		t.Fatal(r2.head)
	}
	if e = r2.append(testEvent(999)); e != nil {
		t.Fatal(e)
	}
	after, e = Read(dir)
	if e != nil || after.ObservedSequence != 201 || after.Records[127].Event.TimeNS != 999 {
		t.Fatal(after, e)
	}
}
func TestCorruptCommittedRecordIsNotSilentlyResetOrOlderFallback(t *testing.T) {
	dir := testDir(t)
	r, e := openRing(dir)
	if e != nil {
		t.Fatal(e)
	}
	for i := int64(1); i <= 4; i++ {
		if e = r.append(testEvent(i)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = r.file.WriteAt([]byte{255}, slot(4)+20); e != nil {
		t.Fatal(e)
	}
	r.file.Sync()
	r.close()
	before, _ := os.ReadFile(filepath.Join(dir, "events.ring"))
	if _, e = Read(dir); e == nil {
		t.Fatal("corrupt committed record read")
	}
	if v, e := Start(dir); e == nil {
		v.Close(context.Background())
		t.Fatal("corrupt record reset or fallback")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "events.ring"))
	if !bytes.Equal(before, after) {
		t.Fatal("authority rewritten")
	}
}
func TestRingRejectsUnsafeOrPartialInventoryWithoutRepair(t *testing.T) {
	cases := []struct {
		name   string
		change func(string) error
	}{
		{"unknown", func(d string) error { return os.WriteFile(filepath.Join(d, "foreign"), []byte("preserve"), 0600) }},
		{"symlink_ring", func(d string) error {
			if e := os.Remove(filepath.Join(d, "events.ring")); e != nil {
				return e
			}
			return os.Symlink("logger.lock", filepath.Join(d, "events.ring"))
		}},
		{"hardlink_ring", func(d string) error {
			return os.Link(filepath.Join(d, "events.ring"), filepath.Join(filepath.Dir(d), "extra-link"))
		}},
		{"oversize", func(d string) error { return os.Truncate(filepath.Join(d, "events.ring"), RingBytes+1) }},
		{"short", func(d string) error { return os.Truncate(filepath.Join(d, "events.ring"), RingBytes-1) }},
		{"permissions", func(d string) error { return os.Chmod(filepath.Join(d, "events.ring"), 0640) }},
		{"lock_nonempty", func(d string) error { return os.WriteFile(filepath.Join(d, "logger.lock"), []byte{1}, 0600) }},
		{"lock_symlink", func(d string) error {
			if e := os.Remove(filepath.Join(d, "logger.lock")); e != nil {
				return e
			}
			return os.Symlink("events.ring", filepath.Join(d, "logger.lock"))
		}},
		{"lock_fifo", func(d string) error {
			if e := os.Remove(filepath.Join(d, "logger.lock")); e != nil {
				return e
			}
			return unix.Mkfifo(filepath.Join(d, "logger.lock"), 0600)
		}},
		{"missing_ring", func(d string) error { return os.Remove(filepath.Join(d, "events.ring")) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := testDir(t)
			r, e := openRing(d)
			if e != nil {
				t.Fatal(e)
			}
			r.close()
			if e = tc.change(d); e != nil {
				t.Fatal(e)
			}
			before, _ := os.ReadDir(d)
			if v, e := Start(d); e == nil {
				v.Close(context.Background())
				t.Fatal("unsafe inventory accepted")
			}
			after, _ := os.ReadDir(d)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("inventory repaired")
			}
		})
	}
	// Existing lock but no ring is an interrupted bootstrap, not fresh state.
	d := testDir(t)
	os.WriteFile(filepath.Join(d, "logger.lock"), nil, 0600)
	if v, e := Start(d); e == nil {
		v.Close(context.Background())
		t.Fatal("partial bootstrap reset")
	}
	if _, e := os.Stat(filepath.Join(d, "events.ring")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("partial initialized")
	}
}
func TestRingScopeAndDirectoryValidation(t *testing.T) {
	d := testDir(t)
	r, e := openRing(d)
	if e != nil {
		t.Fatal(e)
	}
	r.close()
	renamed := filepath.Join(filepath.Dir(d), "renamed")
	if e = os.Rename(d, renamed); e != nil {
		t.Fatal(e)
	}
	if _, e = Read(renamed); e == nil {
		t.Fatal("scope relocated")
	}
	if l, e := Start(renamed); e == nil {
		l.Close(context.Background())
		t.Fatal("scope rewritten")
	}
	for _, bad := range []string{"relative", renamed + "/../renamed", renamed + "/"} {
		if _, e = Read(bad); e == nil {
			t.Fatal("unclean read")
		}
		if l, e := Start(bad); e == nil {
			l.Close(context.Background())
			t.Fatal("unclean start")
		}
	}
	link := filepath.Join(filepath.Dir(d), "link")
	os.Symlink(renamed, link)
	if l, e := Start(link); e == nil {
		l.Close(context.Background())
		t.Fatal("leaf symlink")
	}
}
func TestFormatRejectsCRCReservedVersionEnumsAndSequence(t *testing.T) {
	scope := scopeFor("/private/test")
	h := encodeHeader(header{seq: 3, scope: scope})
	r := encodeRecord(3, testEvent(1))
	for _, index := range []int{0, 8, 12, 16, 20, 32, 64, 124} {
		b := h
		b[index] ^= 1
		if _, e := decodeHeader(b[:], scope); e == nil {
			t.Fatal("header mutation", index)
		}
		if index != 124 {
			binary.LittleEndian.PutUint32(b[124:], sum(b[:124]))
			if _, e := decodeHeader(b[:], scope); e == nil {
				t.Fatal("header semantics", index)
			}
		}
	}
	for _, index := range []int{0, 8, 9, 10, 11, 16, 24, 40, 124} {
		b := r
		b[index] = 255
		if _, e := decodeRecord(b[:], 3); e == nil {
			t.Fatal("record mutation", index)
		}
		if index != 24 && index != 124 {
			binary.LittleEndian.PutUint32(b[124:], sum(b[:124]))
			if _, e := decodeRecord(b[:], 3); e == nil {
				t.Fatal("record semantics", index)
			}
		}
	}
	if _, e := decodeHeader(h[:127], scope); e == nil {
		t.Fatal("short header")
	}
	if _, e := decodeRecord(r[:127], 3); e == nil {
		t.Fatal("short record")
	}
}
func TestLiveReadHasBoundedRetryDuringWrap(t *testing.T) {
	d := testDir(t)
	l, e := Start(d)
	if e != nil {
		t.Fatal(e)
	}
	for range 3000 {
		l.Emit(PrepareFailed, Other)
		if v, e := Read(d); e == nil && (len(v.Records) > RetainedRecords || v.Overwritten > v.ObservedSequence) {
			t.Fatal("unbounded live view")
		}
	}
	closeTest(t, l)
	v, e := Read(d)
	if e != nil || v.Records[len(v.Records)-1].Event.Kind != CollectorClosed {
		t.Fatal(e)
	}
	if len(v.Records) > RetainedRecords || l.Stats().WriteErrors != 0 {
		t.Fatal("writer failed")
	}
}
func TestClosedViewContainsNoInputPaths(t *testing.T) {
	d := testDir(t)
	l, e := Start(d)
	if e != nil {
		t.Fatal(e)
	}
	l.Emit(ServiceMock, Configuration)
	closeTest(t, l)
	v, e := Read(d)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte(d)) || bytes.Contains(raw, []byte("diagnostics")) || len(raw) > 32768 {
		t.Fatal("path in view")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e = l.Close(ctx); e != nil {
		t.Fatal(e)
	}
}
