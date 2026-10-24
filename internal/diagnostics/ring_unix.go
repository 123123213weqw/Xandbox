//go:build linux || darwin

package diagnostics

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"math"
	"os"
	"path/filepath"
	"syscall"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"golang.org/x/sys/unix"
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)
var ringMagic = [8]byte{'X', 'B', 'D', 'R', 'I', 'N', 'G', 1}
var eventMagic = [8]byte{'X', 'B', 'D', 'E', 'V', 'E', 'N', 1}

type header struct {
	seq   uint64
	scope [32]byte
}
type ring struct {
	file, lock *os.File
	head       header
}

func sum(b []byte) uint32 { return crc32.Checksum(b, crcTable) }
func encodeHeader(h header) [HeaderBytes]byte {
	var b [HeaderBytes]byte
	copy(b[:8], ringMagic[:])
	binary.LittleEndian.PutUint32(b[8:12], 1)
	binary.LittleEndian.PutUint32(b[12:16], RetainedRecords)
	binary.LittleEndian.PutUint32(b[16:20], FrameBytes)
	binary.LittleEndian.PutUint64(b[24:32], h.seq)
	copy(b[32:64], h.scope[:])
	binary.LittleEndian.PutUint32(b[124:], sum(b[:124]))
	return b
}
func decodeHeader(b []byte, scope [32]byte) (header, error) {
	var h header
	if len(b) != HeaderBytes || !bytes.Equal(b[:8], ringMagic[:]) || binary.LittleEndian.Uint32(b[8:12]) != 1 || binary.LittleEndian.Uint32(b[12:16]) != RetainedRecords || binary.LittleEndian.Uint32(b[16:20]) != FrameBytes || binary.LittleEndian.Uint32(b[124:]) != sum(b[:124]) || !bytes.Equal(b[32:64], scope[:]) {
		return h, ErrWrite
	}
	for _, v := range append(append([]byte(nil), b[20:24]...), b[64:124]...) {
		if v != 0 {
			return h, ErrWrite
		}
	}
	h.seq = binary.LittleEndian.Uint64(b[24:32])
	h.scope = scope
	if h.seq >= math.MaxUint64-1 {
		return header{}, ErrWrite
	}
	return h, nil
}
func encodeRecord(seq uint64, e Event) [FrameBytes]byte {
	var b [FrameBytes]byte
	copy(b[:8], eventMagic[:])
	b[8] = 1
	b[9] = byte(e.Kind)
	b[10] = byte(e.Reason)
	binary.LittleEndian.PutUint64(b[16:24], seq)
	binary.LittleEndian.PutUint64(b[24:32], uint64(e.TimeNS))
	binary.LittleEndian.PutUint64(b[32:40], e.DroppedBefore)
	binary.LittleEndian.PutUint32(b[124:], sum(b[:124]))
	return b
}
func decodeRecord(b []byte, seq uint64) (Record, error) {
	var r Record
	if len(b) != FrameBytes || !bytes.Equal(b[:8], eventMagic[:]) || b[8] != 1 || binary.LittleEndian.Uint64(b[16:24]) != seq || binary.LittleEndian.Uint32(b[124:]) != sum(b[:124]) {
		return r, ErrWrite
	}
	for _, v := range append(append([]byte(nil), b[11:16]...), b[40:124]...) {
		if v != 0 {
			return r, ErrWrite
		}
	}
	r = Record{Sequence: seq, Event: Event{Kind: Kind(b[9]), Reason: Reason(b[10]), TimeNS: int64(binary.LittleEndian.Uint64(b[24:32])), DroppedBefore: binary.LittleEndian.Uint64(b[32:40])}}
	if seq == 0 || !r.Event.valid() {
		return Record{}, ErrWrite
	}
	return r, nil
}
func slot(seq uint64) int64 { return 2*HeaderBytes + int64(seq%(RetainedRecords+1))*FrameBytes }
func scopeFor(dir string) [32]byte {
	return sha256.Sum256([]byte("Xandbox daemon diagnostics v1\x00" + dir))
}
func privateRegular(f *os.File, size int64) (os.FileInfo, error) {
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	v, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || v.Uid != uint32(os.Geteuid()) || v.Nlink != 1 || st.Size() != size {
		return nil, ErrWrite
	}
	return st, nil
}
func openNamed(dir, name string, size int64, access int) (*os.File, error) {
	before, e := os.Lstat(filepath.Join(dir, name))
	if e != nil {
		return nil, e
	}
	fd, e := unix.Open(filepath.Join(dir, name), access|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "diagnostic-store")
	after, e := privateRegular(f, size)
	if e != nil || !os.SameFile(before, after) {
		f.Close()
		return nil, ErrWrite
	}
	return f, nil
}
func names(dir string) ([]string, error) {
	d, e := os.Open(dir)
	if e != nil {
		return nil, e
	}
	defer d.Close()
	n, e := d.Readdirnames(3)
	if e != nil && !errors.Is(e, io.EOF) {
		return nil, e
	}
	if len(n) > 2 {
		return nil, ErrWrite
	}
	return n, nil
}
func openRing(dir string) (out *ring, err error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, ErrWrite
	}
	if info, e := os.Lstat(dir); e == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return nil, ErrWrite
	}
	if _, e := privatefile.EnsureDirectory(dir); e != nil {
		return nil, e
	}
	fd, e := unix.Open(filepath.Join(dir, "logger.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	fresh := e == nil
	if errors.Is(e, unix.EEXIST) {
		fd, e = unix.Open(filepath.Join(dir, "logger.lock"), unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	}
	if e != nil {
		return nil, e
	}
	lock := os.NewFile(uintptr(fd), "diagnostic-lock")
	var f *os.File
	defer func() {
		if err != nil {
			if f != nil {
				f.Close()
			}
			lock.Close()
		}
	}()
	info, e := privateRegular(lock, 0)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return nil, ErrWrite
	}
	current, e := os.Lstat(filepath.Join(dir, "logger.lock"))
	if e != nil || !os.SameFile(info, current) {
		return nil, ErrWrite
	}
	ns, e := names(dir)
	if e != nil {
		return nil, e
	}
	r := &ring{lock: lock, head: header{scope: scopeFor(dir)}}
	if fresh {
		if len(ns) != 1 || ns[0] != "logger.lock" {
			return nil, ErrWrite
		}
		if e = lock.Sync(); e != nil {
			return nil, e
		}
		fd, e = unix.Open(filepath.Join(dir, "events.ring"), unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
		if e != nil {
			return nil, e
		}
		f = os.NewFile(uintptr(fd), "diagnostic-ring")
		if e = f.Truncate(RingBytes); e != nil {
			return nil, e
		}
		b := encodeHeader(r.head)
		if n, e := f.WriteAt(b[:], 0); e != nil || n != len(b) {
			return nil, ErrWrite
		}
		if e = f.Sync(); e != nil {
			return nil, e
		}
		d, e := os.Open(dir)
		if e != nil {
			return nil, e
		}
		e = d.Sync()
		d.Close()
		if e != nil {
			return nil, e
		}
	} else {
		if len(ns) != 2 || !((ns[0] == "logger.lock" && ns[1] == "events.ring") || (ns[1] == "logger.lock" && ns[0] == "events.ring")) {
			return nil, ErrWrite
		}
		f, e = openNamed(dir, "events.ring", RingBytes, unix.O_RDWR)
		if e != nil {
			return nil, e
		}
		h, e := readHead(f, r.head.scope)
		if e != nil {
			return nil, e
		}
		if _, e = readRecords(f, h); e != nil {
			return nil, e
		}
		r.head = h
		// An earlier failed header sync may still be visible in the cache. Validate
		// and sync it before allowing this new writer to advertise readiness.
		if e = f.Sync(); e != nil {
			return nil, e
		}
	}
	r.file = f
	return r, nil
}
func (r *ring) append(e Event) error {
	if !e.valid() || r.head.seq >= math.MaxUint64-2 {
		return ErrWrite
	}
	next := r.head
	next.seq++
	b := encodeRecord(next.seq, e)
	// Capacity+1 slots: staging never overwrites the current committed window.
	if n, err := r.file.WriteAt(b[:], slot(next.seq)); err != nil || n != len(b) {
		return ErrWrite
	}
	if err := r.file.Sync(); err != nil {
		return err
	}
	h := encodeHeader(next)
	bank := int64(next.seq%2) * HeaderBytes
	if n, err := r.file.WriteAt(h[:], bank); err != nil || n != len(h) {
		return ErrWrite
	}
	if err := r.file.Sync(); err != nil {
		return err
	}
	r.head = next
	return nil
}
func (r *ring) close() error { e := r.file.Close(); return errors.Join(e, r.lock.Close()) }
func Start(dir string) (*Logger, error) {
	r, e := openRing(dir)
	if e != nil {
		return nil, e
	}
	return newLogger(r), nil
}
func readHead(f *os.File, scope [32]byte) (header, error) {
	var b [2 * HeaderBytes]byte
	if n, e := f.ReadAt(b[:], 0); e != nil || n != len(b) {
		return header{}, ErrWrite
	}
	a, ae := decodeHeader(b[:HeaderBytes], scope)
	c, ce := decodeHeader(b[HeaderBytes:], scope)
	if ae != nil && ce != nil {
		return header{}, ErrWrite
	}
	if ae == nil && (ce != nil || a.seq >= c.seq) {
		return a, nil
	}
	return c, nil
}
func readRecords(f *os.File, h header) ([]Record, error) {
	start := uint64(1)
	if h.seq > RetainedRecords {
		start = h.seq - RetainedRecords + 1
	}
	out := make([]Record, 0, RetainedRecords)
	for seq := start; seq <= h.seq; seq++ {
		var b [FrameBytes]byte
		if n, e := f.ReadAt(b[:], slot(seq)); e != nil || n != len(b) {
			return nil, ErrWrite
		}
		r, e := decodeRecord(b[:], seq)
		if e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, nil
}

func Read(dir string) (Snapshot, error) {
	var zero Snapshot
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return zero, ErrWrite
	}
	if _, e := privatefile.ExistingDirectory(dir); e != nil {
		return zero, e
	}
	f, e := openNamed(dir, "events.ring", RingBytes, unix.O_RDONLY)
	if e != nil {
		return zero, e
	}
	defer f.Close()
	for attempt := 0; attempt < 3; attempt++ {
		h, e := readHead(f, scopeFor(dir))
		if e != nil {
			return zero, e
		}
		records, re := readRecords(f, h)
		after, e := readHead(f, h.scope)
		if e != nil {
			return zero, e
		}
		if h != after {
			continue
		}
		if re != nil {
			return zero, re
		}
		overwritten := uint64(0)
		if h.seq > RetainedRecords {
			overwritten = h.seq - RetainedRecords
		}
		return Snapshot{Version: 1, ObservedSequence: h.seq, RetainedCapacity: RetainedRecords, Overwritten: overwritten, Records: records}, nil
	}
	return zero, ErrWrite
}
