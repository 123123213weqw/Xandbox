//go:build linux

package installtxn

import (
	"context"
	"os"
)

// Only the fixed, test/installation-owned sealed child root may temporarily
// become owner-writable, and only under a bound durable intent + startup fence.
// No shared ancestor permission is changed. A crash leaves recovery fenced;
// restoration is an explicit durable step, not a Go defer relied on for safety.
func (f *filesystem) runtimeGatewayReplace(ctx context.Context, old, next File) error {
	dir, e := f.directory(childRoot)
	if e != nil {
		return e
	}
	defer dir.Close()
	st, e := dir.Stat()
	if e != nil || (st.Mode().Perm() != 0555 && st.Mode().Perm() != 0700) {
		return ErrInventory
	}
	if st.Mode().Perm() == 0555 && f.verify(ctx, next) == nil {
		if e = f.runtimeReplaceFile(ctx, old, next); e != nil {
			return e
		}
		// A retry after the sealed-mode change must sync it before head CAS,
		// even when the visible mode and selected file already look complete.
		return dir.Sync()
	}
	// This also excludes a fresh request's pre-intent current-vector check and
	// a lost-ACK retry without intent: neither can repair an unsealed directory.
	p, e := f.runtimeIntent()
	if e != nil {
		return e
	}
	bound := false
	for i, v := range p.Input.After {
		if v.Path == childRoot+"/gateway" {
			bound = old == p.Prior.Current[i] && next == v && old != next
		}
	}
	if !bound {
		return ErrInventory
	}
	if _, e = f.runtimeBase(p.Input.Base); e != nil {
		return e
	}
	if e = f.exact(runtimeFilesFence, runtimeFenceBytes(nextRuntimeHead(p)), 0600); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if st.Mode().Perm() == 0555 {
		if e = dir.Chmod(0700); e != nil {
			return e
		}
		if e = f.point("runtime-child-writable"); e != nil {
			return e
		}
		if e = dir.Sync(); e != nil {
			return e
		}
		if e = f.point("runtime-child-writable-durable"); e != nil {
			return e
		}
	}
	if e = f.runtimeReplaceFile(ctx, old, next); e != nil {
		return e
	}
	current, e := f.directory(childRoot)
	if e != nil {
		return e
	}
	now, e := current.Stat()
	current.Close()
	if e != nil || !os.SameFile(st, now) || trustedStat(int(dir.Fd()), true, 0700) != nil {
		return ErrInventory
	}
	if e = dir.Chmod(0555); e != nil {
		return e
	}
	if e = f.point("runtime-child-sealed"); e != nil {
		return e
	}
	if e = dir.Sync(); e != nil {
		return e
	}
	return f.point("runtime-child-sealed-durable")
}
