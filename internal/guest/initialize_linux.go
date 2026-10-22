//go:build linux

package guest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/123123213weqw/Xandbox/internal/guestinit"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"
)

const initDir = "/run/xandbox-init"

func guardedBoot() (sandbox.Ref, bool, error) {
	var zero sandbox.Ref
	stamp, e := os.ReadFile("/etc/xandbox-guest")
	if e != nil || string(stamp) != "Xandbox guest image v1\n" || os.Geteuid() != 0 {
		return zero, false, errors.New("not an Xandbox guest image")
	}
	b, e := os.ReadFile("/proc/cmdline")
	if e != nil {
		return zero, false, e
	}
	ref, pristine, e := parseBoot(string(b))
	if e != nil {
		return zero, false, e
	}
	cid, e := vsock.ContextID()
	if e != nil || cid <= 2 {
		return zero, false, errors.New("guest vsock identity unavailable")
	}
	return ref, pristine, nil
}

// PristineBoot is checked before opening any bootstrap listener. A consumed or
// partially failed initialization permanently prevents reopening on respawn.
func PristineBoot() (bool, error) {
	_, pristine, e := guardedBoot()
	if e != nil || !pristine {
		return pristine, e
	}
	if _, e := os.Lstat(filepath.Join(initDir, "claimed")); !os.IsNotExist(e) {
		return true, errors.New("pristine initialization already consumed")
	}
	return true, nil
}

// InitializeAndExec runs ONLY inside an unassigned pristine guest. It is never
// called by a normal execution server, and has no arbitrary program/argv input.
func InitializeAndExec(req guestinit.Request) (retErr error) {
	defer func() {
		if retErr != nil {
			fmt.Fprintln(os.Stderr, "pristine guest initialization failed:", retErr)
		}
	}()
	if req.Operation != "initialize" || !req.Valid() {
		return errors.New("invalid guest initialization")
	}
	defer req.WipeEntropy()
	if pristine, e := PristineBoot(); e != nil || !pristine {
		return errors.New("guest is not an unassigned pristine template")
	}
	if _, e := privatefile.EnsureDirectory(initDir); e != nil {
		return e
	}
	claim, e := os.OpenFile(filepath.Join(initDir, "claimed"), os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return errors.New("guest initialization already consumed")
	}
	// The marker is a guest RAM/process-respawn latch, NOT durable host ownership.
	if _, e = claim.WriteString(req.Digest() + "\n"); e != nil {
		claim.Close()
		return e
	}
	if e = claim.Close(); e != nil {
		return e
	}
	if e = mixEntropy(req.Entropy); e != nil {
		return e
	}
	if e = unix.ClockSettime(unix.CLOCK_REALTIME, &unix.Timespec{Sec: req.RealtimeNS / 1e9, Nsec: req.RealtimeNS % 1e9}); e != nil {
		return e
	}
	bootPath := filepath.Join(initDir, "boot-id")
	// boot_id is public diagnostic identity, not the root-only receipt. Preserve
	// the normal proc file's read access for unprivileged guest processes.
	if e = os.WriteFile(bootPath, []byte(req.BootID+"\n"), 0444); e != nil {
		return e
	}
	if e = unix.Mount(bootPath, "/proc/sys/kernel/random/boot_id", "", unix.MS_BIND, ""); e != nil {
		return e
	}
	if e = unix.Mount("", "/proc/sys/kernel/random/boot_id", "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); e != nil {
		return e
	}
	machine, e := os.OpenFile("/etc/machine-id", os.O_WRONLY|os.O_CREATE|os.O_TRUNC|unix.O_NOFOLLOW, 0644)
	if e != nil {
		return e
	}
	_, e = machine.WriteString(strings.ReplaceAll(req.BootID, "-", "") + "\n")
	closeErr := machine.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	receipt := guestinit.Receipt{Version: guestinit.Version, Ref: req.Ref, BootID: req.BootID, Digest: req.Digest()}
	b, e := json.Marshal(receipt)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(filepath.Join(initDir, "receipt.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	closeErr = f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	// Replace all pre-snapshot userspace RNG/runtime caches. The bootstrap
	// listener and accepted sockets are CLOEXEC; no reset RPC survives handoff.
	req.WipeEntropy()
	return syscall.Exec("/usr/bin/xandbox-agent", []string{"xandbox-agent", "--initialized"}, []string{"PATH=/bin:/usr/bin"})
}

func mixEntropy(seed []byte) error {
	if len(seed) != 64 {
		return errors.New("invalid seed size")
	}
	f, e := os.OpenFile("/dev/urandom", os.O_RDWR, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	var payload struct {
		EntropyCount, BufferSize int32
		Bytes                    [64]byte
	}
	payload.EntropyCount, payload.BufferSize = 512, 64
	copy(payload.Bytes[:], seed)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), uintptr(unix.RNDADDENTROPY), uintptr(unsafe.Pointer(&payload)))
	runtime.KeepAlive(&payload)
	for i := range payload.Bytes {
		payload.Bytes[i] = 0
	}
	if errno != 0 {
		return errors.New("guest entropy injection failed")
	}
	if e = unix.IoctlSetInt(int(f.Fd()), unix.RNDRESEEDCRNG, 0); e != nil {
		return errors.New("guest entropy reseed barrier failed")
	}
	return nil
}

func initializedReceipt() (guestinit.Receipt, error) {
	var r guestinit.Receipt
	_, pristine, e := guardedBoot()
	if e != nil || !pristine {
		return r, errors.New("initialized mode requires pristine guest boot")
	}
	claim, e := privatefile.Read(filepath.Join(initDir, "claimed"), 128)
	if e != nil {
		return r, e
	}
	b, e := privatefile.Read(filepath.Join(initDir, "receipt.json"), 2048)
	if e != nil {
		return r, e
	}
	if e = strictjson.Decode(b, &r); e != nil || !r.Valid() || string(claim) != r.Digest+"\n" {
		return guestinit.Receipt{}, errors.New("invalid sealed guest receipt")
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil || string(boot) != r.BootID+"\n" {
		return guestinit.Receipt{}, errors.New("guest boot identity not rebound")
	}
	return r, nil
}

func NewInitializedExecutor() (*Executor, sandbox.Ref, string, string, error) {
	r, e := initializedReceipt()
	if e != nil {
		return nil, sandbox.Ref{}, "", "", e
	}
	if e = bootstrap(); e != nil {
		return nil, sandbox.Ref{}, "", "", e
	}
	return &Executor{guard: &guestGuard{}, root: "/sys/fs/cgroup/xandbox", slots: make(chan struct{}, 2)}, r.Ref, r.BootID, r.Digest, nil
}
