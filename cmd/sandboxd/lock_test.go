//go:build linux || darwin

package main

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestUnfinishedWorkersRetainStateLockThroughProcessExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.lock")
	unlock, err := lockState(path)
	if err != nil {
		t.Fatal(err)
	}
	releaseStateLock(unlock, true)
	t.Cleanup(func() {
		if retainedStateLock != nil {
			retainedStateLock()
			retainedStateLock = nil
		}
	})
	runtime.GC()
	if second, err := lockState(path); err == nil {
		second()
		t.Fatal("second controller admitted while old worker may still write")
	}
	retainedStateLock()
	retainedStateLock = nil
	second, err := lockState(path)
	if err != nil {
		t.Fatal(err)
	}
	releaseStateLock(second, false)
	third, err := lockState(path)
	if err != nil {
		t.Fatal("quiescent lock not released: ", err)
	}
	third()
}
