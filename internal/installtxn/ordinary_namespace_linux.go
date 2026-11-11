//go:build linux

package installtxn

import (
	"context"
	"io"
	"strings"

	"golang.org/x/sys/unix"
)

// A NEW ceiling for a complete read-only /etc sibling listing, not a change to
// any existing record, directory, resource, IO or acceptance limit. No sibling
// contents are opened. Overflow is uncertainty, never proof of absence.
const runtimeNamespaceParentLimit = 4096

func runtimeNamespaceNamesVeto(names []string) error {
	if len(names) > runtimeNamespaceParentLimit {
		return ErrInventory
	}
	for _, name := range names {
		// Reserve the entire byte prefix, including future versions, identity
		// anchors and hidden scratches. Do not normalize or inspect their data.
		if strings.HasPrefix(name, "xandbox-runtime") || strings.HasPrefix(name, ".xandbox-runtime") {
			return ErrInventory
		}
	}
	return nil
}

// A NEGATIVE veto, not executable/schema/budget compatibility or permission to
// activate. Ordinary callers hold the ORIGINAL operation lease; startup holds
// its ORIGINAL SH file flock. Existing proofs/checks remain mandatory. There
// is no deletion, repair, cache, manager call or caller-selected namespace.
func (f *filesystem) runtimeNamespaceVeto(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	dir, e := f.directory("/etc")
	if e != nil {
		return e
	}
	defer dir.Close()
	var before, after, linked unix.Stat_t
	if e = unix.Fstat(int(dir.Fd()), &before); e != nil {
		return e
	}
	names, e := dir.Readdirnames(runtimeNamespaceParentLimit + 1)
	if e != nil && e != io.EOF {
		return e
	}
	if e = runtimeNamespaceNamesVeto(names); e != nil {
		return e
	}
	if e = unix.Fstat(int(dir.Fd()), &after); e != nil {
		return e
	}
	// Re-open ONLY for a fresh linked-parent comparison, never replace the
	// original operation lease or move a retained directory's read offset.
	current, e := f.directory("/etc")
	if e != nil {
		return e
	}
	defer current.Close()
	if e = unix.Fstat(int(current.Fd()), &linked); e != nil {
		return e
	}
	if stateEntry(before) != stateEntry(after) || stateEntry(after) != stateEntry(linked) {
		return ErrInventory
	}
	return ctx.Err()
}

func (f *filesystem) ordinaryOperationLock(ctx context.Context, exclusive bool) (func(), error) {
	done, e := f.operationLock(ctx, exclusive)
	if e != nil {
		return nil, e
	}
	if e = f.runtimeNamespaceVeto(ctx); e != nil {
		done()
		return nil, e
	}
	return done, nil // SAME original lease remains held through existing work.
}

func (f *filesystem) ordinaryInitialOperationLock(ctx context.Context) (func(), error) {
	// Refuse BEFORE a fresh bootstrap could create the permanent lock. The
	// original fresh-root bootstrap and lock order are otherwise unchanged.
	if e := f.runtimeNamespaceVeto(ctx); e != nil {
		return nil, e
	}
	done, e := f.initialOperationLock(ctx)
	if e != nil {
		return nil, e
	}
	if e = f.runtimeNamespaceVeto(ctx); e != nil {
		done()
		return nil, e
	}
	return done, nil
}

func (f *filesystem) initialInstallRoot(ctx context.Context) error {
	// Public Apply must also refuse before creating its installation directory.
	if e := f.runtimeNamespaceVeto(ctx); e != nil {
		return e
	}
	return f.mkdir(Root, 0700)
}
