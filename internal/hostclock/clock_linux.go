//go:build linux

// Package hostclock supplies the deadline domain used by controller and warden.
package hostclock

import "golang.org/x/sys/unix"

// NowNS uses the same non-settable, suspend-aware clock in both host processes.
func NowNS() (int64, error) {
	var value unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &value); err != nil {
		return 0, err
	}
	return value.Nano(), nil
}
