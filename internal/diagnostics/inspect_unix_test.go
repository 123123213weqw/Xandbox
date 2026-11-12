//go:build linux || darwin

package diagnostics

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPersistedSnapshotMatchesOrdinaryCompleteWrappedReader(t *testing.T) {
	dir := testDir(t)
	r := testRing(t, dir)
	for n := int64(1); n <= 140; n++ {
		if e := r.append(testEvent(n)); e != nil {
			t.Fatal(e)
		}
	}
	raw, e := os.ReadFile(filepath.Join(dir, "events.ring"))
	if e != nil {
		t.Fatal(e)
	}
	want, e := Read(dir)
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodePersistedSnapshot(dir, raw)
	if e != nil || !reflect.DeepEqual(want, got) || got.ObservedSequence != 140 || len(got.Records) != RetainedRecords {
		t.Fatal(got, e)
	}
}

func TestPersistedSnapshotRejectsBoundsScopeCommittedCorruptionAndFutureEnums(t *testing.T) {
	dir := testDir(t)
	r := testRing(t, dir)
	if e := r.append(testEvent(1)); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(dir, "events.ring"))
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"empty", "short", "long", "scope", "relative", "unclean", "headers", "record-crc", "kind", "reason", "sequence", "reserved", "time"} {
		t.Run(kind, func(t *testing.T) {
			b := bytes.Clone(raw)
			path := dir
			at := int(slot(1))
			switch kind {
			case "empty":
				b = nil
			case "short":
				b = b[:len(b)-1]
			case "long":
				b = append(b, 0)
			case "scope":
				path += "-foreign"
			case "relative":
				path = "relative"
			case "unclean":
				path += "/."
			case "headers":
				b[0] ^= 1
				b[HeaderBytes] ^= 1
			case "record-crc":
				b[at+20] ^= 1
			default:
				switch kind {
				case "kind":
					b[at+9] = byte(kindCount)
				case "reason":
					b[at+10] = byte(reasonCount)
				case "sequence":
					binary.LittleEndian.PutUint64(b[at+16:], 2)
				case "reserved":
					b[at+40] = 1
				case "time":
					binary.LittleEndian.PutUint64(b[at+24:], 0)
				}
				binary.LittleEndian.PutUint32(b[at+124:], sum(b[at:at+124]))
			}
			if got, e := DecodePersistedSnapshot(path, b); e == nil || !reflect.DeepEqual(got, Snapshot{}) {
				t.Fatal("invalid snapshot published", got, e)
			}
		})
	}
}

func TestPersistedSnapshotKeepsOrdinaryStagingAndTornBankSemantics(t *testing.T) {
	dir := testDir(t)
	r := testRing(t, dir)
	if e := r.append(testEvent(1)); e != nil {
		t.Fatal(e)
	}
	want, e := Read(dir)
	if e != nil {
		t.Fatal(e)
	}
	staged := encodeRecord(2, testEvent(2))
	if _, e = r.file.WriteAt(staged[:], slot(2)); e != nil {
		t.Fatal(e)
	}
	torn := encodeHeader(header{seq: 2, scope: r.head.scope})
	torn[124] ^= 1
	if _, e = r.file.WriteAt(torn[:], 0); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(dir, "events.ring"))
	if e != nil {
		t.Fatal(e)
	}
	ordinary, e := Read(dir)
	if e != nil || !reflect.DeepEqual(want, ordinary) {
		t.Fatal(ordinary, e)
	}
	got, e := DecodePersistedSnapshot(dir, raw)
	if e != nil || !reflect.DeepEqual(want, got) {
		t.Fatal(got, e)
	}
}

func TestPersistedSnapshotPureAfterSourceMovedAndInputUnchanged(t *testing.T) {
	dir := testDir(t)
	r := testRing(t, dir)
	raw, e := os.ReadFile(filepath.Join(dir, "events.ring"))
	if e != nil {
		t.Fatal(e)
	}
	before := bytes.Clone(raw)
	if e = r.close(); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(dir, dir+"-moved"); e != nil {
		t.Fatal(e)
	}
	got, e := DecodePersistedSnapshot(dir, raw)
	if e != nil || got.ObservedSequence != 0 || !bytes.Equal(before, raw) {
		t.Fatal(got, e)
	}
	if _, e = os.Stat(dir); !os.IsNotExist(e) {
		t.Fatal("parser created source path")
	}
}
