// Package lease implements the fixed, Ref-bound controller-to-warden protocol.
// This pipe is private host control IPC, not a guest or public API transport.
package lease

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"time"
)

const (
	FrameSize     = 56 // One atomic nonblocking pipe write, far below PIPE_BUF.
	Window        = 5 * time.Second
	RenewInterval = time.Second
	MaxLifetime   = 24 * time.Hour
)

type Binding [32]byte

func ParseBinding(key string) (Binding, error) {
	var binding Binding
	if len(key) != 64 {
		return binding, errors.New("invalid lease binding")
	}
	data, err := hex.DecodeString(key)
	if err != nil || hex.EncodeToString(data) != key {
		return binding, errors.New("invalid lease binding")
	}
	copy(binding[:], data)
	return binding, nil
}

func Deadline(now, hard int64) int64 {
	if hard-now <= int64(Window) {
		return hard
	}
	return now + int64(Window)
}

func ValidLifetime(now, hard int64) bool {
	return now > 0 && hard > now && hard-now <= int64(MaxLifetime)
}

func Encode(binding Binding, sequence uint64, deadline int64) [FrameSize]byte {
	var frame [FrameSize]byte
	copy(frame[:4], "XBL1")
	copy(frame[8:40], binding[:])
	binary.BigEndian.PutUint64(frame[40:48], sequence)
	binary.BigEndian.PutUint64(frame[48:56], uint64(deadline))
	return frame
}

// State never permits revival after an elapsed lease, even if a timer callback
// was delayed and a fresh packet races it. Buffered/replayed packets carry the
// sender's absolute deadline; reading them never grants "now + Window".
type State struct {
	binding  Binding
	hard     int64
	end      int64
	sequence uint64
}

func New(binding Binding, now, hard int64) (*State, error) {
	if !ValidLifetime(now, hard) {
		return nil, errors.New("invalid guardian lifetime")
	}
	return &State{binding: binding, hard: hard, end: Deadline(now, hard)}, nil
}

func (s *State) Due(now int64) bool { return now <= 0 || now >= s.end || now >= s.hard }
func (s *State) Deadline() int64    { return s.end }

func (s *State) Accept(frame []byte, now int64) error {
	if len(frame) != FrameSize || string(frame[:4]) != "XBL1" || binary.BigEndian.Uint32(frame[4:8]) != 0 || s.Due(now) {
		return errors.New("invalid or expired guardian lease")
	}
	var binding Binding
	copy(binding[:], frame[8:40])
	sequence := binary.BigEndian.Uint64(frame[40:48])
	value := binary.BigEndian.Uint64(frame[48:56])
	if binding != s.binding || sequence == 0 || sequence <= s.sequence || value > math.MaxInt64 {
		return errors.New("guardian lease identity or sequence mismatch")
	}
	end := int64(value)
	if end <= now || end > s.hard || end-now > int64(Window) || (s.sequence != 0 && end < s.end) {
		return errors.New("guardian lease deadline invalid")
	}
	s.sequence, s.end = sequence, end
	return nil
}
