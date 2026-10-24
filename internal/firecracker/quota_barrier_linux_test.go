//go:build linux

package firecracker

import (
	"errors"
	"golang.org/x/sys/unix"
	"reflect"
	"testing"
)

func TestQuotaCommitRequiresBothSyscallsAndPreservesErrors(t *testing.T) {
	for _, test := range []struct {
		quotaErr, fsErr error
		want            []string
	}{
		{nil, nil, []string{"quota", "filesystem"}},
		{unix.EIO, nil, []string{"quota"}},
		{nil, unix.EIO, []string{"quota", "filesystem"}},
		{nil, unix.EROFS, []string{"quota", "filesystem"}},
	} {
		calls := []string{}
		e := quotaCommitBarrier(func() error { calls = append(calls, "quota"); return test.quotaErr }, func() error { calls = append(calls, "filesystem"); return test.fsErr })
		wantErr := test.quotaErr
		if wantErr == nil {
			wantErr = test.fsErr
		}
		if !errors.Is(e, wantErr) || !reflect.DeepEqual(calls, test.want) {
			t.Fatal("quota commit acknowledged too early or hid error", e, calls)
		}
	}
}
