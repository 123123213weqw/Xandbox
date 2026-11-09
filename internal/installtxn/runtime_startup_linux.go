//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

// startupReadLock uses only O_RDONLY + flock, so the real cap0 gate can use it.
// A missing, nonempty or rebound permanent lock is corruption, never repaired.
func (f *filesystem) startupReadLock(ctx context.Context) (func(), error) {
	in, e := f.open(Root+"/.lock", unix.O_RDONLY, 0600)
	if e != nil {
		return nil, e
	}
	before, e := in.Stat()
	if e != nil || before.Size() != 0 {
		in.Close()
		return nil, ErrInventory
	}
	if e = f.point("startup-lock-opened"); e != nil {
		in.Close()
		return nil, e
	}
	unlock, e := flock(ctx, in, false)
	if e != nil {
		return nil, e
	}
	current, e := f.open(Root+"/.lock", unix.O_RDONLY, 0600)
	if e != nil {
		unlock()
		return nil, e
	}
	after, e := current.Stat()
	current.Close()
	if e != nil || after.Size() != 0 || !os.SameFile(before, after) || trustedStat(int(in.Fd()), false, 0600) != nil {
		unlock()
		return nil, ErrInventory
	}
	return unlock, nil
}

// startupFilesLocked is used by the real cap0 ExecStartPre gate while its
// original installer SH flock is held. Until the lifecycle/activation protocol
// exists, ANY side-journal namespace blocks startup, even an empty directory or
// a rolled-back genesis vector with a missing fence. Absence is not recovery.
func (f *filesystem) startupFilesLocked(ctx context.Context) (transaction, error) {
	var zero transaction
	if e := ctx.Err(); e != nil {
		return zero, e
	}
	for _, root := range []string{runtimeFilesRoot, runtimeDrainRoot} {
		if yes, e := f.exists(root); e != nil {
			return zero, e
		} else if yes {
			return zero, ErrInventory
		}
	}
	t, e := f.readTransaction("commit")
	if e != nil {
		return zero, e
	}
	if e = f.verifyTransaction(ctx, t); e != nil {
		return zero, e
	}
	return t, nil
}

// runtimeSelectedFiles is the INTERNAL pre-activation byte/composition proof,
// not permission to execute. It requires (and never removes) the exact startup
// fence. No public CLI or startup gate accepts its result. There is deliberately
// no activation receipt, manager call, artifact execution or mutable-state copy.
// Do not cache it across releasing the lock as an activation certificate.
func (f *filesystem) runtimeSelectedFiles(ctx context.Context) (runtimeFileHead, error) {
	var zero runtimeFileHead
	if e := ctx.Err(); e != nil {
		return zero, e
	}
	// Read-only startup proof needs SH flock only, not an operation lock that
	// would deadlock a future maintenance owner starting its own commit gate.
	unlock, e := f.startupReadLock(ctx)
	if e != nil {
		return zero, e
	}
	defer unlock()
	h, e := f.runtimeHead()
	if e != nil {
		return zero, e
	}
	t, e := f.runtimeBase(h.Base)
	if e != nil {
		return zero, e
	}
	for _, path := range []string{runtimeFilesRoot, runtimeFilesRoot + "/objects"} {
		if e = f.privateDirectory(path, 0700); e != nil {
			return zero, e
		}
	}
	names, e := f.names(runtimeFilesRoot)
	if e != nil || !sameNames(names, []string{"head.json", "objects"}) {
		return zero, ErrInventory
	}
	names, e = f.names(Root)
	expected := []string{".lock", "commit.json", filepath.Base(runtimeFilesFence)}
	expected = append(expected, configNamesFor(t.Plan.Version)...)
	sort.Strings(expected)
	if e != nil || !sameNames(names, expected) {
		return zero, ErrInventory
	}
	if e = f.exact(runtimeFilesFence, runtimeFenceBytes(h), 0600); e != nil {
		return zero, e
	}
	if e = f.runtimeInventory(ctx, &h, nil); e != nil {
		return zero, e
	}
	if e = f.runtimeProtected(ctx, t); e != nil {
		return zero, e
	}
	art, e := descriptor(t.Release)
	if e != nil {
		return zero, e
	}
	selected := map[string]File{}
	for _, v := range h.Current {
		selected[v.Path] = v
		if e = f.verify(ctx, v); e != nil {
			return zero, e
		}
		// Never adopt/remove a leftover target scratch, even if its final target
		// happens to equal a valid selected image.
		scratch := filepath.Dir(v.Path) + "/." + filepath.Base(v.Path) + ".runtime-next"
		if yes, err := f.exists(scratch); err != nil {
			return zero, err
		} else if yes {
			return zero, ErrInventory
		}
		if v.Mode == 0555 {
			in, err := f.open(v.Path, unix.O_RDONLY, v.Mode)
			if err != nil {
				return zero, err
			}
			err = staticProgram(in, v.Bytes)
			in.Close()
			if err != nil {
				return zero, err
			}
		}
	}
	// The child copy is the SAME selected gateway, not a separately authorized
	// executable. No descriptor or caller may override a protected backend pin.
	g, child := selected[rolePath("gateway")], selected[childRoot+"/gateway"]
	if g.SHA256 != child.SHA256 || g.Bytes != child.Bytes {
		return zero, ErrInventory
	}
	for role, old := range art {
		if v, ok := selected[rolePath(role)]; ok {
			old.SHA256, old.Bytes = v.SHA256, v.Bytes
			art[role] = old
		}
	}
	if e = f.verifyGeneratedArtifacts(t.Plan, art); e != nil {
		return zero, e
	}
	// Close both immutable artifact namespaces. Mutable state is NOT certified
	// readable, quiescent or reclaimable by these byte checks.
	names, e = f.names(assetDir)
	expected = nil
	for _, role := range roles {
		if filepath.Dir(rolePath(role)) == assetDir {
			expected = append(expected, filepath.Base(rolePath(role)))
		}
	}
	sort.Strings(expected)
	if e != nil || !sameNames(names, expected) {
		return zero, ErrInventory
	}
	names, e = f.names(childRoot)
	if e != nil || !sameNames(names, []string{"gateway"}) {
		return zero, ErrInventory
	}
	for _, d := range []struct {
		path string
		mode uint32
	}{{Root, 0700}, {DataRoot, 0700}, {assetDir, 0700}, {DataRoot + "/g", 0700}, {childRoot, 0555}} {
		if e = f.privateDirectory(d.path, d.mode); e != nil {
			return zero, e
		}
	}
	// Repeat the exact head/base/fence after all potentially long file reads.
	current, e := f.runtimeHead()
	if e != nil || !bytes.Equal(encode(current), encode(h)) {
		return zero, ErrInventory
	}
	if _, e = f.runtimeBase(h.Base); e != nil {
		return zero, e
	}
	if e = f.exact(runtimeFilesFence, runtimeFenceBytes(h), 0600); e != nil {
		return zero, e
	}
	if e = ctx.Err(); e != nil {
		return zero, e
	}
	return h, nil
}

// runtimeRunningSelf compares the actually executing /proc/self/exe bytes to
// the selected, already statically validated self pin. The genesis Plan.Self
// must NOT be changed to make a new installer pass. This separate internal
// check is not a startup bypass and does not take a caller-specified exe path.
func runtimeRunningSelf(ctx context.Context, pin File) error {
	if pin.Path != SelfPath || pin.Mode != 0555 || pin.Bytes < 1 || pin.Bytes > 64<<20 || !digestPattern.MatchString(pin.SHA256) {
		return ErrPolicy
	}
	in, e := os.Open("/proc/self/exe")
	if e != nil {
		return e
	}
	defer in.Close()
	sum, e := hashFile(ctx, in, pin.Bytes)
	if e != nil {
		return e
	}
	if sum != pin.SHA256 {
		return ErrPolicy
	}
	return nil
}
