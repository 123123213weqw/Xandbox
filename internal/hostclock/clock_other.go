//go:build !linux

package hostclock

import "time"

var origin = time.Now()

// Non-Linux is only a local mock clock, not a cross-process guardian domain.
// Real drivers are unavailable here; it must never be serialized for Linux.
func NowNS() (int64, error) { return int64(time.Since(origin)) + 1, nil }
