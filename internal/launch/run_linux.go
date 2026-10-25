//go:build linux

package launch

import (
	"crypto/sha256"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

type failure struct {
	stage string
	cause error
}

func (e *failure) Error() string { return "launch preflight failed" }
func FailureStage(err error) string {
	if e, ok := err.(*failure); ok {
		return e.stage
	}
	return "platform"
}
func trustedStat(fd int, directory, private bool) error {
	var st unix.Stat_t
	if e := unix.Fstat(fd, &st); e != nil {
		return e
	}
	typ := uint32(unix.S_IFREG)
	if directory {
		typ = unix.S_IFDIR
	}
	if st.Mode&unix.S_IFMT != typ || st.Uid != 0 || st.Mode&0022 != 0 || private && st.Mode&0077 != 0 || !directory && st.Nlink != 1 {
		return errors.New("untrusted root object")
	}
	return nil
}

// Walk using directory FDs; never follow root-owned aliases or trust a name
// check followed by a separate unanchored open.
func trustedDirectory(path string, private bool) (*os.File, error) {
	if !canonical(path) {
		return nil, errPolicy
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	if e = trustedStat(fd, true, false); e != nil {
		unix.Close(fd)
		return nil, e
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, name := range parts {
		next, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
		if err = trustedStat(fd, true, private && index == len(parts)-1); err != nil {
			unix.Close(fd)
			return nil, err
		}
	}
	return os.NewFile(uintptr(fd), "launch-directory"), nil
}
func trustedFile(path string, private bool, limit int64) (*os.File, error) {
	if !canonical(path) {
		return nil, errPolicy
	}
	parent, e := trustedDirectory(filepath.Dir(path), false)
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	fd, e := unix.Openat(int(parent.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "launch-root-file")
	if e = trustedStat(fd, false, private); e != nil {
		f.Close()
		return nil, e
	}
	st, e := f.Stat()
	if e != nil || st.Size() < 1 || st.Size() > limit {
		f.Close()
		return nil, errors.New("bounded regular asset required")
	}
	return f, nil
}
func pinnedBytes(a firecracker.Asset, limit int64) ([]byte, error) {
	f, e := trustedFile(a.Path, true, limit)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, e
	}
	if len(raw) > int(limit) || fmt.Sprintf("%x", sha256.Sum256(raw)) != a.SHA256 {
		return nil, errors.New("configuration digest mismatch")
	}
	return raw, nil
}
func writeSnapshot(dir *os.File, name string, raw []byte) error {
	fd, e := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0400)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), "launch-input-snapshot")
	if _, e = f.Write(raw); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return dir.Sync()
}
func staticDaemon(a firecracker.Asset) (*os.File, error) {
	f, e := trustedFile(a.Path, false, 64<<20)
	if e != nil {
		return nil, e
	}
	fail := func(err error) (*os.File, error) { f.Close(); return nil, err }
	st, e := f.Stat()
	if e != nil {
		return fail(e)
	}
	if st.Mode().Perm()&0111 == 0 {
		return fail(errors.New("daemon not executable"))
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, (64<<20)+1)); e != nil {
		return fail(e)
	}
	if fmt.Sprintf("%x", h.Sum(nil)) != a.SHA256 {
		return fail(errors.New("daemon digest mismatch"))
	}
	binary, e := elf.NewFile(f)
	if e != nil {
		return fail(e)
	}
	machine := elf.EM_X86_64
	if runtime.GOARCH == "arm64" {
		machine = elf.EM_AARCH64
	} else if runtime.GOARCH != "amd64" {
		return fail(errors.New("unsupported launcher architecture"))
	}
	if binary.Type != elf.ET_EXEC || binary.Class != elf.ELFCLASS64 || binary.Data != elf.ELFDATA2LSB || binary.Machine != machine || len(binary.Progs) > 256 {
		return fail(errors.New("static native ELF required"))
	}
	for _, p := range binary.Progs {
		if p.Type == elf.PT_INTERP {
			return fail(errors.New("ELF interpreter forbidden"))
		}
	}
	return f, nil
}
func proc(path string, limit int64) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return "", e
	}
	if int64(len(b)) > limit {
		return "", errors.New("bounded proc read required")
	}
	return strings.TrimSpace(string(b)), nil
}
func placement(m Manifest, leaf string) error {
	value, e := proc("/proc/self/cgroup", 4096)
	if e != nil {
		return e
	}
	if value != "0::"+strings.TrimPrefix(m.UnitRoot, "/sys/fs/cgroup")+"/"+leaf {
		return errors.New("exact own unit placement required")
	}
	return nil
}
func safeCapabilities(status string) error {
	seen := map[string]bool{}
	for _, line := range strings.Split(status, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch name {
		case "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb":
			if seen[name] {
				return errPolicy
			}
			seen[name] = true
			v, e := strconv.ParseUint(value, 16, 64)
			if e != nil || v&(1<<24) != 0 {
				return errors.New("CAP_SYS_RESOURCE must be absent")
			}
		case "NoNewPrivs":
			if seen[name] || value != "1" {
				return errPolicy
			}
			seen[name] = true
		case "Uid":
			if seen[name] || !sameWords(value, "0 0 0 0") {
				return errPolicy
			}
			seen[name] = true
		}
	}
	if len(seen) != 7 {
		return errPolicy
	}
	return nil
}
func allThreadCapabilities() error {
	entries, e := os.ReadDir("/proc/self/task")
	if e != nil {
		return e
	}
	if len(entries) < 1 || len(entries) > 256 {
		return errPolicy
	}
	checked := 0
	for _, entry := range entries {
		if _, e = strconv.ParseUint(entry.Name(), 10, 32); e != nil {
			return errPolicy
		}
		raw, err := proc("/proc/self/task/"+entry.Name()+"/status", 64<<10)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if err = safeCapabilities(raw); err != nil {
			return err
		}
		checked++
	}
	if checked == 0 {
		return errPolicy
	}
	return nil
}
func rejectInheritedDescriptors() error {
	entries, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		return e
	}
	if len(entries) > 256 {
		return errPolicy
	}
	for _, entry := range entries {
		n, err := strconv.Atoi(entry.Name())
		if err != nil {
			return errPolicy
		}
		if n <= 2 {
			continue
		}
		flags, err := unix.FcntlInt(uintptr(n), unix.F_GETFD, 0)
		if errors.Is(err, unix.EBADF) {
			continue
		}
		if err != nil {
			return err
		}
		if flags&unix.FD_CLOEXEC == 0 {
			return errors.New("unexpected inheritable descriptor")
		}
	}
	return nil
}
func Run(path string) (retErr error) {
	stage := "platform"
	defer func() {
		if retErr != nil {
			retErr = &failure{stage: stage, cause: retErr}
		}
	}()
	if os.Geteuid() != 0 {
		return errors.New("root service required")
	}
	init, e := proc("/proc/1/comm", 32)
	if e != nil || init != "systemd" {
		return errors.New("systemd PID1 required")
	}
	stage = "manifest"
	file, e := trustedFile(path, true, 16384)
	if e != nil {
		return e
	}
	data, e := io.ReadAll(io.LimitReader(file, 16385))
	file.Close()
	if e != nil {
		return e
	}
	m, e := Decode(data)
	if e != nil {
		return e
	}
	stage = "placement"
	if e = placement(m, "bootstrap"); e != nil {
		return e
	}
	if e = allThreadCapabilities(); e != nil {
		return e
	}
	stage = "asset"
	executable, e := staticDaemon(m.Daemon)
	if e != nil {
		return e
	}
	defer executable.Close()
	stage = "inputs"
	inputs, e := trustedDirectory(m.InputDir, true)
	if e != nil {
		return e
	}
	defer inputs.Close()
	inventory, e := inputs.ReadDir(1)
	if e != nil && e != io.EOF {
		return e
	}
	if len(inventory) != 0 {
		return errors.New("fresh manager runtime directory required")
	}
	backend, e := pinnedBytes(m.Backend, 16384)
	if e != nil {
		return e
	}
	auth, e := pinnedBytes(m.Auth, 65536)
	if e != nil {
		return e
	}
	if e = writeSnapshot(inputs, "backend.json", backend); e != nil {
		return e
	}
	if e = writeSnapshot(inputs, "auth.json", auth); e != nil {
		return e
	}
	stage = "configuration"
	var c firecracker.Config
	if e = strictjson.Decode(backend, &c); e != nil {
		return e
	}
	stage = "backend_policy"
	if e = firecracker.ValidateAdmissionConfig(m.InputDir+"/backend.json", m.Admission()); e != nil {
		return e
	}
	if e = m.checkBackend(c); e != nil {
		return e
	}
	stage = "auth_policy"
	if _, e = access.Load(m.InputDir + "/auth.json"); e != nil {
		return e
	}
	stage = "state_volume"
	state, e := trustedDirectory(m.StateDir, true)
	if e != nil {
		return e
	}
	defer state.Close()
	runtimeDir, e := trustedDirectory(c.RuntimeRoot, true)
	if e != nil {
		return e
	}
	defer runtimeDir.Close()
	var stateFS, runtimeFS unix.Statfs_t
	var stateStat, runtimeStat unix.Stat_t
	if e = unix.Fstatfs(int(state.Fd()), &stateFS); e != nil {
		return e
	}
	if e = unix.Fstatfs(int(runtimeDir.Fd()), &runtimeFS); e != nil {
		return e
	}
	if e = unix.Fstat(int(state.Fd()), &stateStat); e != nil {
		return e
	}
	if e = unix.Fstat(int(runtimeDir.Fd()), &runtimeStat); e != nil {
		return e
	}
	if stateFS.Type != unix.EXT4_SUPER_MAGIC || runtimeFS.Type != unix.EXT4_SUPER_MAGIC || stateStat.Dev != runtimeStat.Dev {
		return errors.New("same ext4 state/runtime required")
	}
	state.Close()
	runtimeDir.Close()
	stage = "envelope"
	unit, e := openGroupPath(m.UnitRoot)
	if e != nil {
		return e
	}
	e = prepareGroups(unit, m, c, os.Getpid())
	unit.Close()
	if e != nil {
		return e
	}
	stage = "exec"
	if e = placement(m, "node/control"); e != nil {
		return e
	}
	if e = allThreadCapabilities(); e != nil {
		return e
	}
	inputs.Close()
	if e = rejectInheritedDescriptors(); e != nil {
		return e
	}
	// Resolve the already-verified ELF FD in execve before its CLOEXEC close.
	// Config/auth arguments name immutable per-unit snapshots, not raced source names.
	e = unix.Exec("/proc/self/fd/"+strconv.Itoa(int(executable.Fd())), m.Arguments(), []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C"})
	runtime.KeepAlive(executable)
	return e
}
