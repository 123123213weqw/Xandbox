//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type filesystem struct {
	root *os.File
	hook func(string) error
}

func (f *filesystem) point(stage string) error {
	if f.hook != nil {
		return f.hook(stage)
	}
	return nil
}
func trustedStat(fd int, directory bool, mode uint32) error {
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil {
		return ErrInventory
	}
	kind := uint32(unix.S_IFREG)
	if directory {
		kind = unix.S_IFDIR
	}
	if s.Mode&unix.S_IFMT != kind || (s.Uid != 0 && s.Uid != uint32(os.Geteuid())) || s.Mode&0022 != 0 || s.Mode&07000 != 0 || !directory && (s.Uid != uint32(os.Geteuid()) || s.Nlink != 1) || mode != 0 && s.Mode&0777 != mode {
		return ErrInventory
	}
	return nil
}
func (f *filesystem) directory(path string) (*os.File, error) {
	if !canonical(path) {
		return nil, ErrPolicy
	}
	fd, e := unix.Openat(int(f.root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	for _, name := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if e = trustedStat(fd, true, 0); e != nil {
			unix.Close(fd)
			return nil, e
		}
		next, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	if e = trustedStat(fd, true, 0); e != nil {
		unix.Close(fd)
		return nil, e
	}
	return os.NewFile(uintptr(fd), "install-directory"), nil
}
func (f *filesystem) mkdir(path string, mode uint32) error {
	parent, e := f.directory(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer parent.Close()
	e = unix.Mkdirat(int(parent.Fd()), filepath.Base(path), mode)
	if e != nil && !errors.Is(e, unix.EEXIST) {
		return e
	}
	dir, e := f.directory(path)
	if e != nil {
		return e
	}
	defer dir.Close()
	if e = trustedStat(int(dir.Fd()), true, mode); e != nil {
		return e
	}
	return parent.Sync()
}
func (f *filesystem) open(path string, flags int, mode uint32) (*os.File, error) {
	if !canonical(path) {
		return nil, ErrPolicy
	}
	parent, e := f.directory(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	fd, e := unix.Openat(int(parent.Fd()), filepath.Base(path), flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, mode)
	if e != nil {
		return nil, e
	}
	out := os.NewFile(uintptr(fd), "install-root-file")
	if e = trustedStat(fd, false, mode); e != nil {
		out.Close()
		return nil, e
	}
	return out, nil
}
func (f *filesystem) read(path string, limit int64, mode uint32) ([]byte, error) {
	in, e := f.open(path, unix.O_RDONLY, mode)
	if e != nil {
		return nil, e
	}
	defer in.Close()
	b, e := io.ReadAll(io.LimitReader(in, limit+1))
	if e != nil {
		return nil, e
	}
	if len(b) == 0 || int64(len(b)) > limit {
		return nil, ErrInventory
	}
	return b, nil
}
func (f *filesystem) exists(path string) (bool, error) {
	parent, e := f.directory(filepath.Dir(path))
	if errors.Is(e, unix.ENOENT) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	defer parent.Close()
	var st unix.Stat_t
	e = unix.Fstatat(int(parent.Fd()), filepath.Base(path), &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(e, unix.ENOENT) {
		return false, nil
	}
	return e == nil, e
}
func (f *filesystem) names(path string) ([]string, error) {
	dir, e := f.directory(path)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	v, e := dir.Readdirnames(64)
	if e != nil && e != io.EOF {
		return nil, e
	}
	if len(v) >= 64 {
		return nil, ErrInventory
	}
	sort.Strings(v)
	return v, nil
}
func (f *filesystem) syncDir(path string) error {
	dir, e := f.directory(path)
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func (f *filesystem) lock(ctx context.Context, path string, exclusive bool) (func(), error) {
	in, e := f.open(path, unix.O_RDWR|unix.O_CREAT, 0600)
	if e != nil {
		return nil, e
	}
	if e = f.syncDir(filepath.Dir(path)); e != nil {
		in.Close()
		return nil, e
	}
	return flock(ctx, in, exclusive)
}
func (f *filesystem) existingLock(ctx context.Context, exclusive bool) (func(), error) {
	in, e := f.open(Root+"/.lock", unix.O_RDONLY, 0600)
	if e != nil {
		return nil, e
	}
	return flock(ctx, in, exclusive)
}
func (f *filesystem) initialLock(ctx context.Context) (func(), error) {
	unlock, e := f.existingLock(ctx, true)
	if !errors.Is(e, unix.ENOENT) {
		return unlock, e
	}
	// The sole creation case is an empty fresh installation directory. Losing a
	// permanent lock after any intent/target/commit is corruption, not repair.
	names, e := f.names(Root)
	if e != nil {
		return nil, e
	}
	if len(names) != 0 {
		// A concurrent first installer may have created the original lock since
		// our ENOENT observation. Reopen only; never recreate on this branch.
		return f.existingLock(ctx, true)
	}
	return f.lock(ctx, Root+"/.lock", true)
}
func flock(ctx context.Context, in *os.File, exclusive bool) (func(), error) {
	mode := unix.LOCK_SH
	if exclusive {
		mode = unix.LOCK_EX
	}
	ok := false
	defer func() {
		if !ok {
			in.Close()
		}
	}()
	for {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		e := unix.Flock(int(in.Fd()), mode|unix.LOCK_NB)
		if e == nil {
			ok = true
			return func() { in.Close() }, nil
		}
		if !errors.Is(e, unix.EAGAIN) && !errors.Is(e, unix.EWOULDBLOCK) {
			return nil, e
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

type contextReader struct {
	ctx   context.Context
	input io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.input.Read(p)
}
func hashFile(ctx context.Context, in *os.File, size int64) (string, error) {
	if _, e := in.Seek(0, 0); e != nil {
		return "", e
	}
	h := sha256.New()
	n, e := io.Copy(h, contextReader{ctx, io.LimitReader(in, size+1)})
	if e != nil {
		return "", e
	}
	if n != size {
		return "", ErrInventory
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
func (f *filesystem) verify(ctx context.Context, v File) error {
	in, e := f.open(v.Path, unix.O_RDONLY, v.Mode)
	if e != nil {
		return e
	}
	defer in.Close()
	sum, e := hashFile(ctx, in, v.Bytes)
	if e != nil {
		return e
	}
	if sum != v.SHA256 {
		return ErrInventory
	}
	return in.Sync()
}
func (f *filesystem) exact(path string, data []byte, mode uint32) error {
	b, e := f.read(path, int64(len(data)), mode)
	if e != nil {
		return e
	}
	if !bytes.Equal(data, b) {
		return ErrInventory
	}
	return nil
}
func (f *filesystem) putPrefix(path string, data []byte, mode uint32, stage string) error {
	out, e := f.open(path, unix.O_RDWR|unix.O_CREAT, mode)
	if e != nil {
		return e
	}
	defer out.Close()
	old, e := io.ReadAll(io.LimitReader(out, int64(len(data))+1))
	if e != nil {
		return e
	}
	if len(old) > len(data) || !bytes.Equal(old, data[:len(old)]) {
		return ErrInventory
	}
	if _, e = out.Write(data[len(old):]); e != nil {
		return e
	}
	if e = f.point(stage + "-written"); e != nil {
		return e
	}
	if e = out.Sync(); e != nil {
		return e
	}
	if e = f.point(stage + "-synced"); e != nil {
		return e
	}
	return f.syncDir(filepath.Dir(path))
}
func (f *filesystem) record(name string, data []byte) error {
	path := Root + "/" + name + ".json"
	scratch := Root + "/." + name + ".next"
	if e := f.exact(path, data, 0600); e == nil {
		yes, err := f.exists(scratch)
		if err != nil {
			return err
		}
		if yes {
			return ErrInventory
		}
		return f.syncDir(Root)
	} else if !errors.Is(e, unix.ENOENT) {
		return e
	}
	if e := f.putPrefix(scratch, data, 0600, name); e != nil {
		return e
	}
	dir, e := f.directory(Root)
	if e != nil {
		return e
	}
	defer dir.Close()
	if e = unix.Renameat(int(dir.Fd()), filepath.Base(scratch), int(dir.Fd()), filepath.Base(path)); e != nil {
		return e
	}
	if e = f.point(name + "-renamed"); e != nil {
		return e
	}
	if e = dir.Sync(); e != nil {
		return e
	}
	return f.point(name + "-durable")
}
func (f *filesystem) removeIntent(tx transaction) error {
	path := Root + "/intent.json"
	if e := f.exact(path, encode(tx), 0600); e != nil {
		if errors.Is(e, unix.ENOENT) {
			return nil
		}
		return e
	}
	dir, e := f.directory(Root)
	if e != nil {
		return e
	}
	defer dir.Close()
	if e = unix.Unlinkat(int(dir.Fd()), "intent.json", 0); e != nil {
		return e
	}
	if e = dir.Sync(); e != nil {
		return e
	}
	return f.point("intent-removed")
}

type target struct {
	file   File
	source *os.File
	data   []byte
}

func (f *filesystem) materialize(ctx context.Context, v target) error {
	if e := f.verify(ctx, v.file); e == nil {
		return nil
	} else if !errors.Is(e, unix.ENOENT) {
		partial, err := f.open(v.file.Path, unix.O_RDONLY, 0600)
		if err != nil {
			return err
		}
		partial.Close()
	}
	var input io.ReadSeeker = bytes.NewReader(v.data)
	if v.source != nil {
		input = v.source
	}
	if _, e := input.Seek(0, 0); e != nil {
		return e
	}
	out, e := f.open(v.file.Path, unix.O_RDWR|unix.O_CREAT, 0600)
	if e != nil {
		return e
	}
	defer out.Close()
	st, e := out.Stat()
	if e != nil || st.Size() > v.file.Bytes {
		return ErrInventory
	}
	left := make([]byte, 65536)
	right := make([]byte, 65536)
	remain := st.Size()
	for remain > 0 {
		if e = ctx.Err(); e != nil {
			return e
		}
		size := int64(len(left))
		if remain < size {
			size = remain
		}
		if _, e = io.ReadFull(out, left[:size]); e != nil {
			return e
		}
		if _, e = io.ReadFull(input, right[:size]); e != nil {
			return e
		}
		if !bytes.Equal(left[:size], right[:size]) {
			return ErrInventory
		}
		remain -= size
	}
	if _, e = io.Copy(out, contextReader{ctx, io.LimitReader(input, v.file.Bytes-st.Size()+1)}); e != nil {
		return e
	}
	stage := "file-" + filepath.Base(v.file.Path)
	if e = f.point(stage + "-written"); e != nil {
		return e
	}
	sum, e := hashFile(ctx, out, v.file.Bytes)
	if e != nil {
		return e
	}
	if sum != v.file.SHA256 {
		return ErrInventory
	}
	if e = out.Sync(); e != nil {
		return e
	}
	if e = f.point(stage + "-synced"); e != nil {
		return e
	}
	if e = out.Chmod(os.FileMode(v.file.Mode)); e != nil {
		return e
	}
	if e = out.Sync(); e != nil {
		return e
	}
	if e = f.syncDir(filepath.Dir(v.file.Path)); e != nil {
		return e
	}
	return f.point(stage + "-sealed")
}
