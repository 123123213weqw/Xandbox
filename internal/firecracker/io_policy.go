package firecracker

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// IOPolicy is immutable operator policy, not tenant input. The frontend bucket
// caps guest requests even when buffered writeback is attributed to the parent
// that staged the inode; io.max alone cannot guarantee that boundary.
type IOPolicy struct {
	Version             int    `json:"version"`
	FilesystemDevice    string `json:"filesystem_device"`
	Device              string `json:"device"`
	BytesPerSecond      uint64 `json:"bytes_per_second"`
	OperationsPerSecond uint64 `json:"operations_per_second"`
}

func validBlockDevice(s string) bool {
	a, b, ok := strings.Cut(s, ":")
	if !ok {
		return false
	}
	major, e := strconv.ParseUint(a, 10, 12)
	minor, f := strconv.ParseUint(b, 10, 20)
	return e == nil && f == nil && major > 0 && s == fmt.Sprintf("%d:%d", major, minor)
}

func (p IOPolicy) validate() error {
	if p.Version != 1 || !validBlockDevice(p.FilesystemDevice) || !validBlockDevice(p.Device) ||
		p.BytesPerSecond < 1<<20 || p.BytesPerSecond > 1<<30 || p.OperationsPerSecond < 128 || p.OperationsPerSecond > 65536 {
		return errors.New("invalid fixed IO policy or canonical block device")
	}
	return nil
}

func (p IOPolicy) kernelLine() string {
	return fmt.Sprintf("%s rbps=%d wbps=%d riops=%d wiops=%d", p.Device,
		p.BytesPerSecond, p.BytesPerSecond, p.OperationsPerSecond, p.OperationsPerSecond)
}

func (p IOPolicy) verifyKernelLimit(raw string) error {
	fields := strings.Fields(raw)
	want := strings.Fields(p.kernelLine())
	if len(strings.Split(strings.TrimSpace(raw), "\n")) != 1 || len(fields) != 5 || fields[0] != p.Device {
		return errors.New("IO limit readback device/shape mismatch")
	}
	seen := make(map[string]bool)
	for _, field := range fields[1:] {
		if seen[field] {
			return errors.New("duplicate IO limit readback")
		}
		seen[field] = true
	}
	for _, field := range want[1:] {
		if !seen[field] {
			return errors.New("IO limit readback value mismatch")
		}
	}
	return nil
}

type ioBucket struct {
	Size         uint64 `json:"size"`
	RefillTime   uint64 `json:"refill_time"`
	OneTimeBurst uint64 `json:"one_time_burst,omitempty"`
}
type ioRateLimit struct {
	Bandwidth ioBucket `json:"bandwidth"`
	Ops       ioBucket `json:"ops"`
}

func (p IOPolicy) frontendLimit() ioRateLimit {
	// One-second steady buckets, no extra one-time burst. This is combined
	// guest read/write traffic, not a hard per-window physical-media bound.
	return ioRateLimit{Bandwidth: ioBucket{Size: p.BytesPerSecond, RefillTime: 1000},
		Ops: ioBucket{Size: p.OperationsPerSecond, RefillTime: 1000}}
}

func workspaceDrive(p *IOPolicy) map[string]any {
	drive := map[string]any{"drive_id": "workspace", "path_on_host": "/workspace.ext4", "is_root_device": false, "is_read_only": false}
	if p != nil {
		drive["rate_limiter"] = p.frontendLimit()
	}
	return drive
}
