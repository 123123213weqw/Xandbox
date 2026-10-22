//go:build linux

package warden

import (
	"io"
	"os"
	"sync"

	"github.com/123123213weqw/Xandbox/internal/hostclock"
	"github.com/123123213weqw/Xandbox/internal/lease"
	"golang.org/x/sys/unix"
)

// beginLease arms an absolute CLOCK_BOOTTIME timer independent of the reader
// and controller. A partial pipe frame cannot suppress expiry. No child may be
// launched before ready closes after the first valid Ref-bound lease packet.
func beginLease(reader io.Reader, binding lease.Binding, hard int64, stop func()) (<-chan struct{}, *os.File, error) {
	now, err := hostclock.NowNS()
	if err != nil {
		return nil, nil, err
	}
	state, err := lease.New(binding, now, hard)
	if err != nil {
		return nil, nil, err
	}
	fd, err := unix.TimerfdCreate(unix.CLOCK_BOOTTIME, unix.TFD_CLOEXEC|unix.TFD_NONBLOCK)
	if err != nil {
		return nil, nil, err
	}
	timer := os.NewFile(uintptr(fd), "guardian-boottime-timer")
	arm := func() error {
		value := unix.ItimerSpec{Value: unix.NsecToTimespec(state.Deadline())}
		return unix.TimerfdSettime(fd, unix.TFD_TIMER_ABSTIME, &value, nil)
	}
	if err := arm(); err != nil {
		timer.Close()
		return nil, nil, err
	}
	var mu sync.Mutex
	var first sync.Once
	ready := make(chan struct{})
	go func() {
		var event [8]byte
		for {
			if _, err := io.ReadFull(timer, event[:]); err != nil {
				stop()
				return
			}
			mu.Lock()
			now, err := hostclock.NowNS()
			due := err != nil || state.Due(now)
			mu.Unlock()
			if due {
				stop()
				return
			} // Recheck: an old timer event may race renewal.
		}
	}()
	go func() {
		var frame [lease.FrameSize]byte
		for {
			if _, err := io.ReadFull(reader, frame[:]); err != nil {
				stop()
				return
			}
			mu.Lock()
			now, err := hostclock.NowNS()
			if err == nil {
				err = state.Accept(frame[:], now)
			}
			if err == nil {
				err = arm()
			}
			mu.Unlock()
			if err != nil {
				stop()
				return
			}
			first.Do(func() { close(ready) })
		}
	}()
	return ready, timer, nil
}
