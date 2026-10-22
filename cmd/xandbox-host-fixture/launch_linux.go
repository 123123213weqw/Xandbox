//go:build linux && xandbox_host_fixture

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/hostclock"
	"github.com/123123213weqw/Xandbox/internal/lease"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

type launchPolicy struct {
	Version    int    `json:"version"`
	Root       string `json:"root"`
	Cgroup     string `json:"cgroup"`
	UID        uint32 `json:"uid"`
	KVMGroup   uint32 `json:"kvm_group"`
	Warden     string `json:"warden"`
	WardenSHA  string `json:"warden_sha256"`
	FixtureSHA string `json:"fixture_sha256"`
	QEMUSHA    string `json:"qemu_sha256"`
	KernelSHA  string `json:"kernel_sha256"`
	InitrdSHA  string `json:"initrd_sha256"`
}

var runtimePattern = regexp.MustCompile(`^/srv/nh-[0-9a-f]{6}$`)
var groupPattern = regexp.MustCompile(`^/sys/fs/cgroup/xandbox-nested-proof-([0-9a-f]{6})/[0-9a-f]{64}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (p launchPolicy) validate() error {
	m := groupPattern.FindStringSubmatch(p.Cgroup)
	if p.Version != 1 || !runtimePattern.MatchString(p.Root) || len(m) != 2 || p.Root != "/srv/nh-"+m[1] || p.UID < 850000 || p.UID >= 880000 || p.KVMGroup == 0 || p.KVMGroup > 65535 ||
		!filepath.IsAbs(p.Warden) || filepath.Clean(p.Warden) != p.Warden {
		return errors.New("invalid exclusive launch policy")
	}
	for _, h := range []string{p.WardenSHA, p.FixtureSHA, p.QEMUSHA, p.KernelSHA, p.InitrdSHA} {
		if !hashPattern.MatchString(h) {
			return errors.New("explicit artifact hashes required")
		}
	}
	return nil
}

func fileHash(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, 256<<20)); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func loadLaunch(path string) (launchPolicy, error) {
	var p launchPolicy
	info, e := os.Lstat(path)
	if e != nil {
		return p, e
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 8192 {
		return p, errors.New("fixture policy must be root private regular file")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return p, e
	}
	if e = strictjson.Decode(b, &p); e != nil {
		return p, e
	}
	return p, p.validate()
}

func (p launchPolicy) arguments() []string {
	return []string{"-no-user-config", "-nodefaults", "-machine", "pc-q35-6.2,accel=kvm,dump-guest-core=off,mem-merge=off",
		"-cpu", "host,vmx=on", "-smp", "4", "-m", "2048", "-display", "none", "-monitor", "none", "-nic", "none", "-no-reboot",
		"-serial", "file:" + p.Root + "/console.log",
		"-chardev", "socket,id=control,path=" + p.Root + "/control.sock,server=on,wait=off", "-device", "isa-serial,chardev=control,index=1",
		"-qmp", "unix:" + p.Root + "/qmp.sock,server=on,wait=off",
		"-kernel", p.Root + "/kernel", "-initrd", p.Root + "/initrd.cpio.gz",
		"-append", "console=ttyS0,115200 rdinit=/init panic=1 reboot=k loglevel=4",
		"-drive", "if=none,id=state,file=" + p.Root + "/disk.raw,format=raw,cache=none,aio=native,werror=report,rerror=report",
		"-device", "virtio-blk-pci,drive=state",
		"-object", "rng-random,id=rng0,filename=/dev/urandom", "-device", "virtio-rng-pci,rng=rng0",
		"-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"}
}

func launch(path string) error {
	if os.Geteuid() != 0 {
		return errors.New("root launcher required")
	}
	p, e := loadLaunch(path)
	if e != nil {
		return e
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	for file, want := range map[string]string{self: p.FixtureSHA, p.Warden: p.WardenSHA} {
		h, e := fileHash(file)
		if e != nil || h != want {
			return errors.New("launcher artifact mismatch")
		}
	}
	var life unix.Stat_t
	if e = unix.Fstat(0, &life); e != nil || life.Mode&unix.S_IFMT != unix.S_IFIFO {
		return errors.New("inherited parent lifetime pipe required")
	}
	unix.CloseOnExec(0)
	parent := os.NewFile(0, "parent-lifetime")
	defer parent.Close()
	cg, e := os.Open(p.Cgroup)
	if e != nil {
		return e
	}
	defer cg.Close()
	var fs unix.Statfs_t
	if e = unix.Fstatfs(int(cg.Fd()), &fs); e != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return errors.New("cgroup2 FD required")
	}
	procs, e := os.ReadFile(p.Cgroup + "/cgroup.procs")
	if e != nil || strings.TrimSpace(string(procs)) != "" {
		return errors.New("exclusive empty generation required")
	}
	kill, e := os.OpenFile(p.Cgroup+"/cgroup.kill", os.O_WRONLY, 0)
	if e != nil {
		return e
	}
	defer kill.Close()
	read, write, e := os.Pipe()
	if e != nil {
		return e
	}
	defer read.Close()
	defer write.Close()
	if e = unix.SetNonblock(int(write.Fd()), true); e != nil {
		return e
	}
	now, e := hostclock.NowNS()
	if e != nil {
		return e
	}
	hard := now + int64(15*time.Minute)
	binding, e := lease.ParseBinding(filepath.Base(p.Cgroup))
	if e != nil {
		return e
	}
	sequence := uint64(1)
	send := func() error {
		now, e := hostclock.NowNS()
		if e != nil {
			return e
		}
		f := lease.Encode(binding, sequence, lease.Deadline(now, hard))
		sequence++
		n, e := unix.Write(int(write.Fd()), f[:])
		if e != nil {
			return e
		}
		if n != len(f) {
			return io.ErrShortWrite
		}
		return nil
	}
	if e = send(); e != nil {
		return e
	}
	cmd := exec.Command(p.Warden, "-cgroup", strings.TrimPrefix(p.Cgroup, "/sys/fs/cgroup/"), "-hard-deadline-ns", fmt.Sprint(hard), "--", self, "-mode", "qemu-child", "-config", path)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{read, kill}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd()), Cloneflags: unix.CLONE_NEWNET, Setsid: true}
	if e = cmd.Start(); e != nil {
		return e
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	eof := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, parent); close(eof) }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case e = <-done:
			return e
		case <-eof:
			_ = write.Close()
			return <-done
		case <-ticker.C:
			if e = send(); e != nil {
				_ = write.Close()
				return <-done
			}
		}
	}
}

func qemuChild(path string) error {
	if os.Geteuid() != 0 {
		return errors.New("root fixture child required")
	}
	p, e := loadLaunch(path)
	if e != nil {
		return e
	}
	membership, e := os.ReadFile("/proc/self/cgroup")
	if e != nil || strings.TrimSpace(string(membership)) != "0::"+strings.TrimPrefix(p.Cgroup, "/sys/fs/cgroup") {
		return errors.New("fixture child not in exact owned group")
	}
	for file, want := range map[string]string{"/usr/bin/qemu-system-x86_64": p.QEMUSHA, p.Root + "/kernel": p.KernelSHA, p.Root + "/initrd.cpio.gz": p.InitrdSHA} {
		h, e := fileHash(file)
		if e != nil || h != want {
			return errors.New("QEMU input mismatch")
		}
	}
	info, e := os.Lstat(p.Root + "/disk.raw")
	if e != nil || !info.Mode().IsRegular() || info.Size() != 2<<30 {
		return errors.New("exclusive bounded raw disk required")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 || st.Uid != p.UID || info.Mode().Perm() != 0600 {
		return errors.New("raw disk ownership mismatch")
	}
	// Per-process limits inherited by QEMU, never host-wide settings.
	if e = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); e != nil {
		return e
	}
	if e = unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: 2 << 30, Max: 2 << 30}); e != nil {
		return e
	}
	cmd := exec.Command("/usr/bin/qemu-system-x86_64", p.arguments()...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent"}
	cmd.Dir = p.Root
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: p.UID, Gid: p.UID, Groups: []uint32{p.KVMGroup}}}
	return cmd.Run()
}
