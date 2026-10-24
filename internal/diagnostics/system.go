package diagnostics

import (
	"context"
	"os"
	"syscall"
)

// SystemReason reads only concrete standard-library wrapper fields and our own
// closed Fault. It NEVER calls Error, Is, As, Unwrap or LogValue on an arbitrary
// error implementation. Unknown wrappers (including fmt wrappers) stay Other.
// The depth bound also handles cyclic caller-created PathError/Fault chains.
func SystemReason(err error) Reason {
	fallback := Other
	for range 32 {
		if err == nil {
			return fallback
		}
		if err == context.DeadlineExceeded {
			return Deadline
		}
		if err == context.Canceled {
			return Cancelled
		}
		switch e := err.(type) {
		case syscall.Errno:
			switch e {
			case syscall.EIO:
				return IOFailure
			case syscall.EDQUOT:
				return QuotaExceeded
			case syscall.ENOSPC:
				return NoSpace
			case syscall.EROFS:
				return ReadOnly
			}
			return fallback
		case *os.PathError:
			if e == nil {
				return fallback
			}
			err = e.Err
		case *os.LinkError:
			if e == nil {
				return fallback
			}
			err = e.Err
		case *os.SyscallError:
			if e == nil {
				return fallback
			}
			err = e.Err
		case *Fault:
			if e == nil {
				return fallback
			}
			if e.Reason < reasonCount && e.Reason != Other {
				fallback = e.Reason
			}
			err = e.Cause
		default:
			return fallback
		}
	}
	return fallback
}
