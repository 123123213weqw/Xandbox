//go:build linux

package releasestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

type store struct {
	root *os.File
	hook func(string) error
}

func (s *store) point(stage string) error {
	if s.hook != nil {
		return s.hook(stage)
	}
	return nil
}
func checked(fd int, dir bool, mode uint32) error {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		return ErrInventory
	}
	typ := uint32(unix.S_IFREG)
	if dir {
		typ = unix.S_IFDIR
	}
	if st.Mode&unix.S_IFMT != typ || st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != mode || !dir && st.Nlink != 1 {
		return ErrInventory
	}
	return nil
}
func openDir(parent *os.File, name string) (*os.File, error) {
	fd, e := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	if e = checked(fd, true, 0700); e != nil {
		unix.Close(fd)
		return nil, e
	}
	return os.NewFile(uintptr(fd), "release-directory"), nil
}
func mkdir(parent *os.File, name string) (*os.File, error) {
	e := unix.Mkdirat(int(parent.Fd()), name, 0700)
	if e != nil && !errors.Is(e, unix.EEXIST) {
		return nil, e
	}
	f, e := openDir(parent, name)
	if e != nil {
		return nil, e
	}
	if e = parent.Sync(); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}

// Source ancestry and store ancestry never traverse even a root-owned symlink.
// Root is a trust boundary, not an adversary we purport to isolate from itself.
func trusted(path string, directory bool, private bool) (*os.File, error) {
	if !canonical(path) {
		return nil, ErrPolicy
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, name := range parts {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
			unix.Close(fd)
			return nil, ErrInventory
		}
		flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if index != len(parts)-1 || directory {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, name, flags, 0)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	var st unix.Stat_t
	e = unix.Fstat(fd, &st)
	typ := uint32(unix.S_IFREG)
	if directory {
		typ = unix.S_IFDIR
	}
	if e != nil || st.Mode&unix.S_IFMT != typ || st.Uid != 0 || st.Mode&0022 != 0 || private && st.Mode&0077 != 0 || !directory && st.Nlink != 1 {
		unix.Close(fd)
		return nil, ErrInventory
	}
	return os.NewFile(uintptr(fd), "release-trusted-input"), nil
}
func openStore() (s *store, err error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return nil, ErrPlatform
	}
	parent, e := trusted(filepath.Dir(Root), true, false)
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	root, e := mkdir(parent, filepath.Base(Root))
	if e != nil {
		return nil, e
	}
	return &store{root: root}, nil
}
func (s *store) lock(ctx context.Context) (func(), error) {
	fd, e := unix.Openat(int(s.root.Fd()), ".lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "release-lock")
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	if e = checked(fd, false, 0600); e != nil {
		return nil, e
	}
	if e = s.root.Sync(); e != nil {
		return nil, e
	}
	for {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if e == nil {
			ok = true
			return func() { f.Close() }, nil
		}
		if !errors.Is(e, unix.EWOULDBLOCK) && !errors.Is(e, unix.EAGAIN) {
			return nil, e
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}
func names(dir *os.File) ([]string, error) {
	// Reopening '.' gives an independent directory cursor, not dup's shared offset.
	fd, e := unix.Openat(int(dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "release-inventory")
	defer f.Close()
	v, e := f.Readdirnames(64)
	if e != nil && e != io.EOF {
		return nil, e
	}
	if len(v) >= 64 {
		return nil, ErrInventory
	}
	sort.Strings(v)
	return v, nil
}
func readAt(dir *os.File, name string, limit int64, mode uint32) ([]byte, error) {
	fd, e := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "release-private-record")
	defer f.Close()
	if e = checked(fd, false, mode); e != nil {
		return nil, e
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, e
	}
	if len(b) == 0 || int64(len(b)) > limit {
		return nil, ErrInventory
	}
	return b, nil
}
func (s *store) readRef() (Reference, []byte, error) {
	var r Reference
	b, e := readAt(s.root, "ref.json", MaxManifest, 0600)
	if errors.Is(e, unix.ENOENT) {
		return r, nil, nil
	}
	if e != nil {
		return r, nil, e
	}
	if strictjson.Decode(b, &r) != nil || !validReference(r) || !bytes.Equal(b, encoded(r)) {
		return r, nil, ErrInventory
	}
	return r, b, nil
}
func (s *store) inventory(r Reference, requested *intent) error {
	ns, e := names(s.root)
	if e != nil {
		return e
	}
	for _, n := range ns {
		switch n {
		case ".lock", "objects", "ref.json", "intent.json", ".intent.next", ".ref.next", "pending":
		default:
			return ErrInventory
		}
	}
	if requested == nil {
		for _, n := range ns {
			if n == "intent.json" || n == ".intent.next" || n == ".ref.next" || n == "pending" {
				return ErrConflict
			}
		}
	}
	objects, e := openDir(s.root, "objects")
	if e != nil {
		return e
	}
	defer objects.Close()
	ns, e = names(objects)
	if e != nil {
		return e
	}
	allowed := map[string]bool{}
	if r.Release != "" {
		allowed[r.Release] = true
	}
	if r.Previous != "" {
		allowed[r.Previous] = true
	}
	if requested != nil {
		allowed[hash(description(requested.Manifest))] = true
	}
	for _, n := range ns {
		if !allowed[n] {
			return ErrInventory
		}
		f, e := openDir(objects, n)
		if e != nil {
			return e
		}
		f.Close()
	}
	for _, id := range []string{r.Release, r.Previous} {
		if id != "" {
			found := false
			for _, n := range ns {
				if n == id {
					found = true
				}
			}
			if !found {
				return ErrInventory
			}
		}
	}
	return nil
}

// putExact never overwrites unrelated scratch data. An interrupted prefix is
// resumable only when every existing byte matches this exact bound request.
func (s *store) putExact(dir *os.File, name string, data []byte, mode uint32, stage string) error {
	fd, e := unix.Openat(int(dir.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), "release-transaction-record")
	defer f.Close()
	if e = checked(fd, false, mode); e != nil {
		return e
	}
	old, e := io.ReadAll(io.LimitReader(f, int64(len(data))+1))
	if e != nil {
		return e
	}
	if len(old) > len(data) || !bytes.Equal(old, data[:len(old)]) {
		return ErrInventory
	}
	if _, e = f.Write(data[len(old):]); e != nil {
		return e
	}
	if e = s.point(stage + "-written"); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = s.point(stage + "-synced"); e != nil {
		return e
	}
	return dir.Sync()
}
func (s *store) exact(dir *os.File, name string, data []byte, mode uint32) error {
	b, e := readAt(dir, name, int64(len(data)), mode)
	if e != nil {
		return e
	}
	if !bytes.Equal(b, data) {
		return ErrInventory
	}
	return nil
}
func (s *store) rename(dir *os.File, from, to, stage string) error {
	if e := unix.Renameat(int(dir.Fd()), from, int(dir.Fd()), to); e != nil {
		return e
	}
	if e := s.point(stage + "-renamed"); e != nil {
		return e
	}
	if e := dir.Sync(); e != nil {
		return e
	}
	return s.point(stage + "-durable")
}
func (s *store) saveIntent(in intent) error {
	b := encoded(in)
	if e := s.exact(s.root, "intent.json", b, 0600); e == nil {
		yes, err := exists(s.root, ".intent.next")
		if err != nil {
			return err
		}
		if yes {
			return ErrInventory
		}
		return s.root.Sync()
	} else if !errors.Is(e, unix.ENOENT) {
		return e
	}
	if e := s.putExact(s.root, ".intent.next", b, 0600, "intent"); e != nil {
		return e
	}
	return s.rename(s.root, ".intent.next", "intent.json", "intent")
}
func (s *store) cleanIntent(in intent) error {
	if e := s.exact(s.root, "intent.json", encoded(in), 0600); e != nil {
		if errors.Is(e, unix.ENOENT) {
			return nil
		}
		return e
	}
	if e := unix.Unlinkat(int(s.root.Fd()), "intent.json", 0); e != nil {
		return e
	}
	if e := s.root.Sync(); e != nil {
		return e
	}
	return s.point("intent-removed")
}
func fileMode(role string) uint32 {
	if executable(role) {
		return 0500
	}
	return 0400
}
func sumFile(ctx context.Context, f *os.File, size int64) (string, error) {
	if _, e := f.Seek(0, 0); e != nil {
		return "", e
	}
	h := sha256.New()
	n, e := io.Copy(h, contextReader{ctx, io.LimitReader(f, size+1)})
	if e != nil {
		return "", e
	}
	if n != size {
		return "", ErrInventory
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
func verifyFile(ctx context.Context, dir *os.File, v artifact) error {
	fd, e := unix.Openat(int(dir.Fd()), v.Role, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), "release-artifact")
	defer f.Close()
	if e = checked(fd, false, fileMode(v.Role)); e != nil {
		return e
	}
	h, e := sumFile(ctx, f, v.Bytes)
	if e != nil {
		return e
	}
	if h != v.SHA256 {
		return ErrInventory
	}
	return f.Sync()
}
func verifyBundle(ctx context.Context, objects *os.File, id string) error {
	if !digestPattern.MatchString(id) {
		return ErrInventory
	}
	dir, e := openDir(objects, id)
	if e != nil {
		return e
	}
	defer dir.Close()
	b, e := readAt(dir, "manifest.json", MaxManifest, 0400)
	if e != nil {
		return e
	}
	var r release
	if strictjson.Decode(b, &r) != nil || !bytes.Equal(b, encoded(r)) || hash(b) != id {
		return ErrInventory
	}
	// Reuse the input schema validation with synthetic, non-store source names.
	m := Manifest{Version: r.Version, SourceRevision: r.SourceRevision, Toolchain: r.Toolchain, GOARCH: r.GOARCH}
	for _, v := range r.Files {
		m.Files = append(m.Files, File{v.Role, "/release-source/" + v.Role, v.SHA256, v.Bytes})
	}
	norm, e := normalize(m)
	if e != nil || !bytes.Equal(description(norm), b) {
		return ErrInventory
	}
	ns, e := names(dir)
	if e != nil || len(ns) != len(roles)+1 {
		return ErrInventory
	}
	for _, v := range r.Files {
		if e = verifyFile(ctx, dir, v); e != nil {
			return e
		}
	}
	// The exact cardinality plus all thirteen verified roles leaves only manifest.
	return nil
}
func (s *store) verifyRetained(ctx context.Context, r Reference) error {
	obj, e := openDir(s.root, "objects")
	if e != nil {
		return e
	}
	defer obj.Close()
	for _, id := range []string{r.Release, r.Previous} {
		if id != "" {
			if e = verifyBundle(ctx, obj, id); e != nil {
				return e
			}
		}
	}
	return nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(b)
}
func inputs(ctx context.Context, m Manifest) ([]*os.File, error) {
	files := []*os.File{}
	fail := func(e error) ([]*os.File, error) {
		for _, f := range files {
			f.Close()
		}
		return nil, e
	}
	for _, v := range m.Files {
		if e := ctx.Err(); e != nil {
			return fail(e)
		}
		f, e := trusted(v.Source, false, false)
		if e != nil {
			return fail(e)
		}
		files = append(files, f)
		st, e := f.Stat()
		if e != nil || st.Size() != v.Bytes {
			return fail(ErrPolicy)
		}
		h := sha256.New()
		n, e := io.Copy(h, contextReader{ctx, io.LimitReader(f, v.Bytes+1)})
		if e != nil {
			return fail(e)
		}
		if n != v.Bytes || fmt.Sprintf("%x", h.Sum(nil)) != v.SHA256 {
			return fail(ErrPolicy)
		}
		if _, e = f.Seek(0, 0); e != nil {
			return fail(e)
		}
	}
	return files, nil
}
func (s *store) copy(ctx context.Context, dir *os.File, v File, source *os.File) error {
	// Already sealed files must be exact; they are never opened for writing.
	a := artifact{v.Role, v.SHA256, v.Bytes}
	if e := verifyFile(ctx, dir, a); e == nil {
		return nil
	} else if !errors.Is(e, unix.ENOENT) {
		// Only an owned 0600 partial file of this durable intent is resumable.
		fd, e := unix.Openat(int(dir.Fd()), v.Role, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return e
		}
		e = checked(fd, false, 0600)
		unix.Close(fd)
		if e != nil {
			return e
		}
	}
	fd, e := unix.Openat(int(dir.Fd()), v.Role, unix.O_RDWR|unix.O_CREAT|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	out := os.NewFile(uintptr(fd), "release-partial")
	defer out.Close()
	if e = checked(fd, false, 0600); e != nil {
		return e
	}
	st, e := out.Stat()
	if e != nil || st.Size() > v.Bytes {
		return ErrInventory
	}
	// Verify every prior byte against the same checked input FD before appending.
	if _, e = source.Seek(0, 0); e != nil {
		return e
	}
	remaining := st.Size()
	left := make([]byte, 65536)
	right := make([]byte, 65536)
	for remaining > 0 {
		if e = ctx.Err(); e != nil {
			return e
		}
		size := int64(len(left))
		if remaining < size {
			size = remaining
		}
		if _, e = io.ReadFull(out, left[:size]); e != nil {
			return e
		}
		if _, e = io.ReadFull(source, right[:size]); e != nil {
			return e
		}
		if !bytes.Equal(left[:size], right[:size]) {
			return ErrInventory
		}
		remaining -= size
	}
	if _, e = io.Copy(out, contextReader{ctx, io.LimitReader(source, v.Bytes-st.Size()+1)}); e != nil {
		return e
	}
	if e = s.point("artifact-written-" + v.Role); e != nil {
		return e
	}
	h, e := sumFile(ctx, out, v.Bytes)
	if e != nil {
		return e
	}
	if h != v.SHA256 {
		return ErrInventory
	}
	if e = out.Sync(); e != nil {
		return e
	}
	if e = s.point("artifact-synced-" + v.Role); e != nil {
		return e
	}
	if e = out.Chmod(os.FileMode(fileMode(v.Role))); e != nil {
		return e
	}
	if e = out.Sync(); e != nil {
		return e
	}
	if e = dir.Sync(); e != nil {
		return e
	}
	return s.point("artifact-sealed-" + v.Role)
}
func (s *store) bundle(ctx context.Context, in intent, source []*os.File) error {
	id := hash(description(in.Manifest))
	obj, e := openDir(s.root, "objects")
	if e != nil {
		return e
	}
	defer obj.Close()
	if existing, e := openDir(obj, id); e == nil {
		existing.Close()
		if e = verifyBundle(ctx, obj, id); e != nil {
			return e
		}
		if p, e := openDir(s.root, "pending"); e == nil {
			p.Close()
			return ErrInventory
		} else if !errors.Is(e, unix.ENOENT) {
			return e
		}
		return obj.Sync()
	} else if !errors.Is(e, unix.ENOENT) {
		return e
	}
	pending, e := mkdir(s.root, "pending")
	if e != nil {
		return e
	}
	defer pending.Close()
	ns, e := names(pending)
	if e != nil {
		return e
	}
	allowed := map[string]bool{"manifest.json": true}
	for _, v := range in.Manifest.Files {
		allowed[v.Role] = true
	}
	for _, n := range ns {
		if !allowed[n] {
			return ErrInventory
		}
	}
	for i, v := range in.Manifest.Files {
		if e = s.copy(ctx, pending, v, source[i]); e != nil {
			return e
		}
	}
	desc := description(in.Manifest)
	if e = s.exact(pending, "manifest.json", desc, 0400); e != nil {
		if e = s.putExact(pending, "manifest.json", desc, 0600, "bundle-manifest"); e != nil {
			return e
		}
		fd, err := unix.Openat(int(pending.Fd()), "manifest.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), "release-manifest")
		e = file.Chmod(0400)
		if e == nil {
			e = file.Sync()
		}
		file.Close()
		if e != nil {
			return e
		}
	}
	if e = pending.Sync(); e != nil {
		return e
	}
	if e = s.point("bundle-sealed"); e != nil {
		return e
	}
	// Destination is absent and the process-global store lock is held. Unknown
	// destinations were rejected above, never replaced or recursively removed.
	if e = unix.Renameat(int(s.root.Fd()), "pending", int(obj.Fd()), id); e != nil {
		return e
	}
	if e = s.point("bundle-renamed"); e != nil {
		return e
	}
	if e = obj.Sync(); e != nil {
		return e
	}
	if e = s.root.Sync(); e != nil {
		return e
	}
	if e = verifyBundle(ctx, obj, id); e != nil {
		return e
	}
	return s.point("bundle-durable")
}

func (s *store) readIntent() (intent, error) {
	var in intent
	b, e := readAt(s.root, "intent.json", MaxManifest+1024, 0600)
	if e != nil {
		return in, e
	}
	if strictjson.Decode(b, &in) != nil || in.Version != 1 || !requestPattern.MatchString(in.RequestID) || in.BaseSHA256 != "" && !digestPattern.MatchString(in.BaseSHA256) {
		return in, ErrInventory
	}
	m, e := normalize(in.Manifest)
	if e != nil {
		return in, ErrInventory
	}
	in.Manifest = m
	if !bytes.Equal(b, encoded(in)) {
		return in, ErrInventory
	}
	return in, nil
}
func exists(dir *os.File, name string) (bool, error) {
	var st unix.Stat_t
	e := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(e, unix.ENOENT) {
		return false, nil
	}
	return e == nil, e
}
func (s *store) finish(ctx context.Context, r Reference, in intent) error {
	if r.IntentSHA256 != intentDigest(in) || r.Release != hash(description(in.Manifest)) || r.RequestID != in.RequestID || r.ExpectedRevision != in.ExpectedRevision {
		return ErrInventory
	}
	for _, n := range []string{"pending", ".intent.next", ".ref.next"} {
		yes, e := exists(s.root, n)
		if e != nil {
			return e
		}
		if yes {
			return ErrInventory
		}
	}
	if e := s.verifyRetained(ctx, r); e != nil {
		return e
	}
	// Synchronize the new reference's directory BEFORE acknowledging a recovered
	// post-rename observation or deleting the intent. No in-memory success fence.
	if e := s.root.Sync(); e != nil {
		return e
	}
	return s.cleanIntent(in)
}
func (s *store) publish(ctx context.Context, m Manifest, expected uint64, request string, openInputs func(context.Context, Manifest) ([]*os.File, error)) (Result, error) {
	var zero Result
	var e error
	if m, e = normalize(m); e != nil || !requestPattern.MatchString(request) || expected == ^uint64(0) {
		return zero, ErrPolicy
	}
	unlock, e := s.lock(ctx)
	if e != nil {
		return zero, e
	}
	defer unlock()
	objects, e := mkdir(s.root, "objects")
	if e != nil {
		return zero, e
	}
	objects.Close()
	r, base, e := s.readRef()
	if e != nil {
		return zero, e
	}
	in := intent{Version: 1, RequestID: request, ExpectedRevision: expected, BaseSHA256: hash(base), Manifest: m}
	if len(base) == 0 {
		in.BaseSHA256 = ""
	}
	if r.Revision > 0 && r.RequestID == request {
		if r.ExpectedRevision != expected || r.Release != hash(description(m)) || r.IntentSHA256 != intentDigest(in) {
			return zero, ErrConflict
		}
		if e = s.inventory(r, &in); e != nil {
			return zero, e
		}
		stored, e := s.readIntent()
		if e == nil {
			in = stored
		} else if !errors.Is(e, unix.ENOENT) {
			return zero, e
		}
		if e = s.finish(ctx, r, in); e != nil {
			return zero, e
		}
		return result(r), nil
	}
	// Finish an acknowledged-or-not prior commit only if its retained immutable
	// bundle and exact immutable intent prove that commit. Never forget an intent
	// merely because a later caller wants a different release.
	old, e := s.readIntent()
	if e == nil && r.Revision > 0 && r.IntentSHA256 == intentDigest(old) {
		if e = s.inventory(r, &old); e != nil {
			return zero, e
		}
		if e = s.finish(ctx, r, old); e != nil {
			return zero, e
		}
	} else if e != nil && !errors.Is(e, unix.ENOENT) {
		return zero, e
	}
	if r.Revision != expected || r.Release == hash(description(m)) || r.RequestID == request {
		return zero, ErrConflict
	}
	if r.Previous != "" {
		return zero, ErrCapacity
	}
	if e = s.inventory(r, &in); e != nil {
		return zero, e
	}
	if e = s.verifyRetained(ctx, r); e != nil {
		return zero, e
	}
	files, e := openInputs(ctx, m)
	if e != nil {
		return zero, e
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	if len(files) != len(m.Files) {
		return zero, ErrPolicy
	}
	if e = s.saveIntent(in); e != nil {
		return zero, e
	}
	if e = s.bundle(ctx, in, files); e != nil {
		return zero, e
	}
	if e = ctx.Err(); e != nil {
		return zero, e
	}
	next := Reference{Version: 1, Revision: expected + 1, Release: hash(description(m)), Previous: r.Release, RequestID: request, ExpectedRevision: expected, IntentSHA256: intentDigest(in)}
	if e = s.putExact(s.root, ".ref.next", encoded(next), 0600, "reference"); e != nil {
		return zero, e
	}
	if e = s.rename(s.root, ".ref.next", "ref.json", "reference"); e != nil {
		return zero, e
	}
	if e = s.point("reference-committed"); e != nil {
		return zero, e
	}
	if e = s.finish(ctx, next, in); e != nil {
		return zero, e
	}
	return result(next), nil
}

// Publish requires the complete private input manifest and an explicit CAS.
// Retrying an uncertain result uses the SAME request, manifest and expected
// revision. Existing sources are not needed for an exact already-committed retry.
func Publish(ctx context.Context, manifestPath string, expected uint64, request string) (Result, error) {
	var zero Result
	if !requestPattern.MatchString(request) || expected == ^uint64(0) {
		return zero, ErrPolicy
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return zero, ErrPlatform
	}
	file, e := trusted(manifestPath, false, true)
	if e != nil {
		return zero, e
	}
	raw, e := io.ReadAll(io.LimitReader(file, MaxManifest+1))
	file.Close()
	if e != nil {
		return zero, e
	}
	m, e := Decode(raw)
	if e != nil {
		return zero, e
	}
	s, e := openStore()
	if e != nil {
		return zero, e
	}
	defer s.root.Close()
	return s.publish(ctx, m, expected, request, inputs)
}

// Status refuses a partial transaction; it never silently completes publication
// or represents pending bytes as a committed release. The lock and fsync are not
// a bound on arbitrary filesystem D-state.
func Status(ctx context.Context) (Result, error) {
	var zero Result
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return zero, ErrPlatform
	}
	root, e := trusted(Root, true, true)
	if e != nil {
		return zero, e
	}
	defer root.Close()
	if e = checked(int(root.Fd()), true, 0700); e != nil {
		return zero, e
	}
	return (&store{root: root}).status(ctx)
}
func (s *store) status(ctx context.Context) (Result, error) {
	var zero Result
	unlock, e := s.lock(ctx)
	if e != nil {
		return zero, e
	}
	defer unlock()
	r, _, e := s.readRef()
	if e != nil {
		return zero, e
	}
	if e = s.inventory(r, nil); e != nil {
		return zero, e
	}
	if e = s.verifyRetained(ctx, r); e != nil {
		return zero, e
	}
	if e = s.root.Sync(); e != nil {
		return zero, e
	}
	if r.Revision == 0 {
		return Result{Version: 1}, nil
	}
	return result(r), nil
}
