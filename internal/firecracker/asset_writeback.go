package firecracker

import (
	"errors"
	"io"
	"math"
)

// This is a submission cadence, NOT a bound on dirty pages or completion time.
const assetWritebackWindow = 8 << 20

// assetWritebackDestination keeps dense writes and only starts writeback of
// already-written ranges. It has no worker, queue/history, retry or waiting
// for completion. submit must NOT be used as a durability/ownership barrier.
// The ordinary quota/filesystem commit barriers remain unchanged.
type assetWritebackDestination struct {
	assetCopyDestination
	submit             func(offset, length int64) error
	written, submitted int64
	failed             error
}

func (d *assetWritebackDestination) fail(err error) error {
	if d.failed == nil {
		d.failed = err
	}
	return d.failed
}
func (d *assetWritebackDestination) valid() error {
	if d.failed != nil {
		return d.failed
	}
	if d.submit == nil || d.written < 0 || d.submitted < 0 || d.submitted > d.written {
		return d.fail(errors.New("invalid asset writeback state"))
	}
	return nil
}
func (d *assetWritebackDestination) Write(p []byte) (int, error) {
	if err := d.valid(); err != nil {
		return 0, err
	}
	n, err := d.assetCopyDestination.Write(p)
	if err != nil {
		return n, d.fail(err)
	}
	if n != len(p) {
		return n, d.fail(io.ErrShortWrite)
	}
	if d.written > math.MaxInt64-int64(n) {
		return n, d.fail(errors.New("asset writeback size overflow"))
	}
	d.written += int64(n)
	if d.written-d.submitted >= assetWritebackWindow {
		if err := d.submitPending(); err != nil {
			return n, err
		}
	}
	return n, nil
}
func (d *assetWritebackDestination) submitPending() error {
	if err := d.valid(); err != nil {
		return err
	}
	for d.submitted < d.written {
		// Short source reads need not align to the window. Split the actual
		// written prefix without gaps, overlap, zero-length or oversized IO.
		length := min(int64(assetWritebackWindow), d.written-d.submitted)
		if err := d.submit(d.submitted, length); err != nil {
			return d.fail(err)
		}
		d.submitted += length
	}
	return nil
}
func (d *assetWritebackDestination) Truncate(n int64) error {
	if err := d.valid(); err != nil {
		return err
	}
	if n != d.written {
		return d.fail(errors.New("asset writeback requires dense verified EOF"))
	}
	if err := d.assetCopyDestination.Truncate(n); err != nil {
		return d.fail(err)
	}
	return d.submitPending()
}
