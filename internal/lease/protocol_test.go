package lease

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func binding(t *testing.T) Binding {
	t.Helper()
	b, e := ParseBinding(strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestAbsoluteDeadlinesCannotReviveOrExtendHardTTL(t *testing.T) {
	b := binding(t)
	now := int64(time.Minute)
	hard := now + int64(20*time.Second)
	s, e := New(b, now, hard)
	if e != nil {
		t.Fatal(e)
	}
	first := Encode(b, 1, Deadline(now, hard))
	if e := s.Accept(first[:], now); e != nil {
		t.Fatal(e)
	}
	// Data buffered before a controller pause is not granted a fresh window.
	later := now + int64(2*time.Second)
	next := Encode(b, 2, Deadline(later, hard))
	if e := s.Accept(next[:], later); e != nil {
		t.Fatal(e)
	}
	if s.Deadline() != later+int64(Window) {
		t.Fatal("lease deadline not sender absolute value")
	}
	expired := s.Deadline()
	revive := Encode(b, 3, Deadline(expired, hard))
	if s.Accept(revive[:], expired) == nil {
		t.Fatal("renewal revived elapsed lease before timer callback")
	}
	s, _ = New(b, hard-int64(time.Second), hard)
	capPacket := Encode(b, 1, hard)
	if e := s.Accept(capPacket[:], hard-int64(time.Second)); e != nil {
		t.Fatal(e)
	}
	for seq := uint64(2); seq < 20; seq++ {
		p := Encode(b, seq, hard)
		if e := s.Accept(p[:], hard-1); e != nil {
			t.Fatal(e)
		}
	}
	if !s.Due(hard) || s.Deadline() != hard {
		t.Fatal("renewals extended hard deadline")
	}
}
func TestFrameValidationFailsClosed(t *testing.T) {
	b := binding(t)
	now := int64(time.Minute)
	hard := now + int64(time.Hour)
	original := Encode(b, 1, Deadline(now, hard))
	for _, kind := range []string{"length", "magic", "reserved", "binding", "zero-seq", "overflow", "past", "far-future"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := New(b, now, hard)
			p := original
			data := p[:]
			switch kind {
			case "length":
				data = data[:len(data)-1]
			case "magic":
				data[0] = 'Q'
			case "reserved":
				data[4] = 1
			case "binding":
				data[8] ^= 1
			case "zero-seq":
				binary.BigEndian.PutUint64(data[40:], 0)
			case "overflow":
				binary.BigEndian.PutUint64(data[48:], ^uint64(0))
			case "past":
				binary.BigEndian.PutUint64(data[48:], uint64(now))
			case "far-future":
				binary.BigEndian.PutUint64(data[48:], uint64(now+int64(Window)+1))
			}
			if s.Accept(data, now) == nil {
				t.Fatal("invalid frame accepted")
			}
		})
	}
	s, _ := New(b, now, hard)
	if e := s.Accept(original[:], now); e != nil {
		t.Fatal(e)
	}
	if s.Accept(original[:], now+1) == nil {
		t.Fatal("replayed sequence accepted")
	}
	shorten := Encode(b, 2, s.Deadline()-1)
	if s.Accept(shorten[:], now+1) == nil {
		t.Fatal("backwards deadline accepted")
	}
	for _, key := range []string{"", strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 63)} {
		if _, e := ParseBinding(key); e == nil {
			t.Fatal("invalid binding accepted")
		}
	}
	for _, pair := range [][2]int64{{0, 10}, {1, 1}, {1, 0}, {1, 1 + int64(MaxLifetime) + 1}} {
		if _, e := New(b, pair[0], pair[1]); e == nil {
			t.Fatal("invalid lifetime accepted")
		}
	}
}
func FuzzLeaseFrame(f *testing.F) {
	b, _ := ParseBinding(strings.Repeat("1", 64))
	p := Encode(b, 1, int64(time.Minute)+int64(Window))
	f.Add(p[:])
	f.Add([]byte("XBL1"))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, _ := New(b, int64(time.Minute), int64(time.Hour))
		before := s.Deadline()
		err := s.Accept(data, int64(time.Minute))
		if err != nil && s.Deadline() != before {
			t.Fatal("failed packet changed deadline")
		}
		if s.Deadline() > int64(time.Hour) {
			t.Fatal("hard lifetime bypass")
		}
	})
}
