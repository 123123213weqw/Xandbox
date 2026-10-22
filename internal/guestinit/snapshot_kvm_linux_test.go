//go:build linux

package guestinit_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/fixturewire"
	"github.com/123123213weqw/Xandbox/internal/guestbridge"
	"github.com/123123213weqw/Xandbox/internal/guestinit"
	"github.com/123123213weqw/Xandbox/internal/guestwire"
	"github.com/123123213weqw/Xandbox/internal/hostclock"
	"github.com/123123213weqw/Xandbox/internal/lease"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

type fixture struct {
	Root, Cgroup, Firecracker, Jailer, Warden, Kernel, Initrd, Report, SourceRevision string
	ExportDirectory                                                                   string
	FaultMode                                                                         string
	UIDStart                                                                          int
	SHA256                                                                            map[string]string
}
type vm struct {
	ref         sandbox.Ref
	root, group string
	cmd         *exec.Cmd
	done        chan struct{}
	life        *os.File
	cancel      context.CancelFunc
	once        sync.Once
	leaseMu     sync.Mutex
	closed      bool
	leaseFD     int
}

func hash(path string) string {
	f, e := os.Open(path)
	if e != nil {
		panic(e)
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		panic(e)
	}
	return hex.EncodeToString(h.Sum(nil))
}
func randomID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func copyFile(from, to string, mode os.FileMode) error {
	a, e := os.Open(from)
	if e != nil {
		return e
	}
	defer a.Close()
	b, e := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if e != nil {
		return e
	}
	_, e = io.Copy(b, a)
	if e == nil {
		e = b.Chmod(mode)
	}
	if e == nil {
		e = b.Sync()
	}
	c := b.Close()
	if e != nil {
		return e
	}
	return c
}

// This explicit-root component test never invokes a tenant command on the host.
// It is NOT sandboxd integration, a snapshot catalog, or a production benchmark.
func TestKVMPristineBootstrapSnapshot(t *testing.T) { runSnapshotFixture(t, false) }

// Separate opt-in export for explicitly fault-instrumented TEST images. It is
// never counted as the ordinary two-clone positive component acceptance.
func TestKVMFaultFixtureSnapshotExport(t *testing.T) { runSnapshotFixture(t, true) }

func runSnapshotFixture(t *testing.T, faultOnly bool) {
	if os.Getenv("XANDBOX_KVM_PRISTINE") != "1" {
		t.Skip("explicit isolated root fixture required; skip is not KVM acceptance")
	}
	if os.Geteuid() != 0 || runtime.GOARCH != "amd64" || runtime.Version() != "go1.27.3" {
		t.Fatal("requires root linux/amd64 patched Go1.27.3")
	}
	raw, e := privatefile.Read(os.Getenv("XANDBOX_KVM_PRISTINE_FIXTURE"), 16384)
	if e != nil {
		t.Fatal(e)
	}
	var f fixture
	if e = strictjson.Decode(raw, &f); e != nil {
		t.Fatal(e)
	}
	if faultOnly {
		if f.ExportDirectory == "" || (f.FaultMode != "machine-id-directory" && f.FaultMode != "crash-before-marker") {
			t.Fatal("explicit private test-image export required")
		}
	} else if f.FaultMode != "" {
		t.Fatal("fault image cannot count as positive component acceptance")
	}
	revision, revisionErr := hex.DecodeString(f.SourceRevision)
	if revisionErr != nil || len(revision) != 20 || f.UIDStart < 300000 || f.UIDStart > 4_000_000_000 || !filepath.IsAbs(f.Root) || filepath.Clean(f.Root) != f.Root || !filepath.IsAbs(f.Report) || filepath.Dir(f.Cgroup) != "/sys/fs/cgroup" || !strings.HasPrefix(f.Cgroup, "/sys/fs/cgroup/xandbox-pristine-proof-") {
		t.Fatal("invalid private fixture")
	}
	if rel, e := filepath.Rel(f.Root, f.Report); e != nil || (rel != ".." && !strings.HasPrefix(rel, "../")) {
		t.Fatal("report must be outside the removable runtime")
	}
	for name, path := range map[string]string{"firecracker": f.Firecracker, "jailer": f.Jailer, "warden": f.Warden, "kernel": f.Kernel, "initrd": f.Initrd} {
		if !filepath.IsAbs(path) || len(f.SHA256[name]) != 64 || hash(path) != f.SHA256[name] {
			t.Fatal("asset mismatch", name)
		}
	}
	if _, e = os.Lstat(f.Report); !os.IsNotExist(e) {
		t.Fatal("refuse report overwrite")
	}
	// Refuse even an empty existing directory: test cleanup must never consume
	// an operator's pre-existing runtime tree.
	if e = os.Mkdir(f.Root, 0700); e != nil {
		t.Fatal(e)
	}
	root, e := privatefile.EnsureDirectory(f.Root)
	if e != nil {
		t.Fatal(e)
	}
	var fs unix.Statfs_t
	if e = unix.Statfs(root, &fs); e != nil || fs.Flags&unix.ST_NOEXEC != 0 {
		t.Fatal("requires executable private runtime; no remount fallback")
	}
	if e = os.Mkdir(f.Cgroup, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(f.Cgroup, "cgroup.subtree_control"), []byte("+memory +pids +cpu"), 0); e != nil {
		t.Fatal(e)
	}
	vms := []*vm{}
	groups := []string{}
	empty := func(group string) bool {
		b, e := os.ReadFile(filepath.Join(group, "cgroup.events"))
		return os.IsNotExist(e) || (e == nil && strings.Contains(string(b), "populated 0"))
	}
	wait := func(label string, p func() bool) {
		t.Helper()
		end := time.Now().Add(12 * time.Second)
		for time.Now().Before(end) {
			if p() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("timeout", label)
	}
	stop := func(v *vm) error {
		t.Helper()
		v.once.Do(func() {
			v.cancel()
			v.leaseMu.Lock()
			if !v.closed {
				v.closed = true
				v.life.Close()
			}
			v.leaseMu.Unlock()
			_ = os.WriteFile(filepath.Join(v.group, "cgroup.kill"), []byte("1"), 0)
		})
		end := time.Now().Add(12 * time.Second)
		for !empty(v.group) {
			if time.Now().After(end) {
				return fmt.Errorf("owned VM cgroup not empty; retain files")
			}
			time.Sleep(10 * time.Millisecond)
		}
		select {
		case <-v.done:
		case <-time.After(5 * time.Second):
			return fmt.Errorf("warden not exited; retain files")
		}
		return nil
	}
	defer func() {
		allStopped := true
		for _, v := range vms {
			if e := stop(v); e != nil {
				t.Error(e)
				allStopped = false
			}
		}
		// Attempt every owned stop even if one fails; never remove backing files
		// while a VMM may still be alive. Partial launch groups are tracked too.
		for _, group := range groups {
			if !empty(group) {
				allStopped = false
			}
		}
		if !allStopped {
			t.Error("retaining private runtime for failed owned-resource cleanup")
			return
		}
		for _, group := range groups {
			if e := os.Remove(group); e != nil && !os.IsNotExist(e) {
				t.Error(e)
			}
		}
		if e := os.Remove(f.Cgroup); e != nil {
			t.Error(e)
		}
		if e := os.RemoveAll(root); e != nil {
			t.Error(e)
		}
	}()
	disk := filepath.Join(root, "blank.ext4")
	df, e := os.OpenFile(disk, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	e = df.Truncate(128 << 20)
	df.Close()
	if e != nil {
		t.Fatal(e)
	}
	if out, e := exec.Command("/usr/sbin/mkfs.ext4", "-q", "-F", disk).CombinedOutput(); e != nil {
		t.Fatal("trusted host mkfs", e, string(out))
	}
	start := func(index int, mem, state, workspace string) *vm {
		t.Helper()
		ref := sandbox.Ref{ID: randomID(), Generation: randomID()}
		key := ref.ID + ref.Generation
		jailRoot := filepath.Join(root, "j")
		vr := filepath.Join(jailRoot, "firecracker", key, "root")
		if e := os.MkdirAll(vr, 0700); e != nil {
			t.Fatal(e)
		}
		if e := copyFile(workspace, filepath.Join(vr, "workspace.ext4"), 0600); e != nil {
			t.Fatal(e)
		}
		uid := f.UIDStart + index
		if e := os.Chown(filepath.Join(vr, "workspace.ext4"), uid, uid); e != nil {
			t.Fatal(e)
		}
		if mem == "" {
			for from, to := range map[string]string{f.Kernel: "kernel", f.Initrd: "initrd"} {
				if e := copyFile(from, filepath.Join(vr, to), 0444); e != nil {
					t.Fatal(e)
				}
			}
		} else {
			if e := os.Link(mem, filepath.Join(vr, "template.mem")); e != nil {
				t.Fatal(e)
			}
			if e := copyFile(state, filepath.Join(vr, "template.state"), 0444); e != nil {
				t.Fatal(e)
			}
		}
		group := filepath.Join(f.Cgroup, key)
		if e := os.Mkdir(group, 0700); e != nil {
			t.Fatal(e)
		}
		groups = append(groups, group)
		for k, value := range map[string]string{"memory.max": "805306368", "memory.swap.max": "0", "pids.max": "64", "cpu.max": "200000 100000"} {
			if e := os.WriteFile(filepath.Join(group, k), []byte(value), 0); e != nil {
				t.Fatal(e)
			}
		}
		cg, e := os.Open(group)
		if e != nil {
			t.Fatal(e)
		}
		defer cg.Close()
		lr, lw, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		defer lr.Close()
		registered := false
		defer func() {
			if !registered {
				lw.Close()
			}
		}()
		kill, e := os.OpenFile(filepath.Join(group, "cgroup.kill"), os.O_WRONLY, 0)
		if e != nil {
			t.Fatal(e)
		}
		defer kill.Close()
		now, e := hostclock.NowNS()
		if e != nil {
			t.Fatal(e)
		}
		hard := now + int64(120*time.Second)
		rel := strings.TrimPrefix(group, "/sys/fs/cgroup/")
		sizeLimit := "134217728"
		if mem == "" {
			sizeLimit = "536870912"
		} // Trusted builder only; restored VMMs keep128MiB write bound.
		cmd := exec.Command(f.Warden, "-cgroup", rel, "-hard-deadline-ns", fmt.Sprint(hard), "--", f.Jailer, "--id", key, "--exec-file", f.Firecracker, "--uid", fmt.Sprint(uid), "--gid", fmt.Sprint(uid), "--chroot-base-dir", jailRoot, "--cgroup-version", "2", "--parent-cgroup", rel, "--resource-limit", "no-file=256", "--resource-limit", "fsize="+sizeLimit, "--", "--api-sock", "/api.sock")
		cmd.ExtraFiles = []*os.File{lr, kill}
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd()), Cloneflags: unix.CLONE_NEWNET, Setsid: true}
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
		logFile, e := os.OpenFile(filepath.Join(filepath.Dir(f.Report), fmt.Sprintf("pristine-vm-%d.log", index)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		defer logFile.Close()
		cmd.Stdout, cmd.Stderr = logFile, logFile
		ctx, cancel := context.WithCancel(context.Background())
		fd := int(lw.Fd())
		if e = unix.SetNonblock(fd, true); e != nil {
			t.Fatal(e)
		}
		v := &vm{ref: ref, root: vr, group: group, cmd: cmd, done: make(chan struct{}), life: lw, cancel: cancel, leaseFD: fd}
		vms = append(vms, v)
		registered = true
		binding, e := lease.ParseBinding(key)
		if e != nil {
			t.Fatal(e)
		}
		renew := func(seq uint64) bool {
			v.leaseMu.Lock()
			defer v.leaseMu.Unlock()
			if v.closed {
				return false
			}
			now, e := hostclock.NowNS()
			if e != nil {
				return false
			}
			frame := lease.Encode(binding, seq, lease.Deadline(now, hard))
			n, e := unix.Write(v.leaseFD, frame[:])
			return e == nil && n == len(frame)
		}
		if !renew(1) {
			close(v.done)
			t.Fatal("first guardian lease")
		}
		if e = cmd.Start(); e != nil {
			close(v.done)
			t.Fatal(e)
		}
		go func() { _ = cmd.Wait(); close(v.done) }()
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for seq := uint64(2); ; seq++ {
				select {
				case <-ctx.Done():
					return
				case <-v.done:
					return
				case <-ticker.C:
					if !renew(seq) {
						return
					}
				}
			}
		}()
		wait("owned jail API", func() bool {
			select {
			case <-v.done:
				t.Fatal("VMM launch failed; inspect private log")
			default:
			}
			c, e := net.DialTimeout("unix", filepath.Join(v.root, "api.sock"), 50*time.Millisecond)
			if e == nil {
				c.Close()
			}
			return e == nil
		})
		return v
	}
	api := func(v *vm, method, path string, body any) {
		t.Helper()
		tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(v.root, "api.sock"))
		}}
		defer tr.CloseIdleConnections()
		b, e := json.Marshal(body)
		if e != nil {
			t.Fatal(e)
		}
		req, _ := http.NewRequest(method, "http://localhost"+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		resp, e := (&http.Client{Transport: tr, Timeout: 20 * time.Second}).Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode != 204 {
			t.Fatalf("trusted API %s %s status%d %s", method, path, resp.StatusCode, out)
		}
	}
	guestCall := func(v *vm, r guestwire.Request) (guestwire.Response, error) {
		ctx, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		return guestbridge.Call(ctx, filepath.Join(v.root, "v.sock"), r)
	}
	execute := func(v *vm, argv ...string) guestwire.Response {
		t.Helper()
		out, e := guestCall(v, guestwire.Request{Version: guestwire.Version, Operation: "exec", Ref: v.ref, ExecutionID: randomID(), Argv: argv, TimeoutMS: 1000, MaxOutputBytes: 4096})
		if e != nil || out.Status != "EXITED" || out.Output.ExitCode != 0 {
			t.Fatal("guest execution failed", e, out.Status, out.Output.ExitCode)
		}
		return out
	}
	checks := []string{}
	creator := start(0, "", "", disk)
	api(creator, "PUT", "/machine-config", map[string]any{"vcpu_count": 2, "mem_size_mib": 512, "smt": false})
	api(creator, "PUT", "/boot-source", map[string]any{"kernel_image_path": "/kernel", "initrd_path": "/initrd", "boot_args": "console=ttyS0 reboot=k panic=1 pci=off rdinit=/sbin/init xandbox.guest=1 xandbox.pristine=1"})
	api(creator, "PUT", "/drives/workspace", map[string]any{"drive_id": "workspace", "path_on_host": "/workspace.ext4", "is_root_device": false, "is_read_only": false})
	api(creator, "PUT", "/vsock", map[string]any{"guest_cid": 3, "uds_path": "/v.sock"})
	api(creator, "PUT", "/actions", map[string]any{"action_type": "InstanceStart"})
	wait("pristine bootstrap WAITING", func() bool {
		ctx, c := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer c()
		r, e := guestbridge.Bootstrap(ctx, filepath.Join(creator.root, "v.sock"), guestinit.Request{Version: 1, Operation: "state"})
		return e == nil && r.Phase == guestinit.Waiting
	})
	if _, e := guestCall(creator, guestwire.Request{Version: 1, Operation: "health", Ref: creator.ref}); e == nil {
		t.Fatal("pristine template exposed normal execution service")
	}
	if faultOnly {
		wait("fixture-only diagnostic ready", func() bool {
			ctx, c := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer c()
			v, e := fixturewire.Inspect(ctx, filepath.Join(creator.root, "v.sock"), "")
			return e == nil && v.AgentGenerations >= 1 && !v.Claimed && !v.Receipt
		})
	}
	checks = append(checks, "unassigned pristine template exposes only one-shot bootstrap, never normal health/exec")
	api(creator, "PATCH", "/vm", map[string]any{"state": "Paused"})
	api(creator, "PUT", "/snapshot/create", map[string]any{"snapshot_type": "Full", "snapshot_path": "/template.state", "mem_file_path": "/template.mem"})
	mem, state, backing := filepath.Join(creator.root, "template.mem"), filepath.Join(creator.root, "template.state"), filepath.Join(creator.root, "workspace.ext4")
	if info, e := os.Stat(mem); e != nil || info.Size() != 512<<20 {
		t.Fatal("wrong snapshot memory size")
	}
	memHash, diskHash := hash(mem), hash(backing)
	for _, p := range []string{mem, state} {
		if e := os.Chown(p, 0, 0); e != nil {
			t.Fatal(e)
		}
		if e := os.Chmod(p, 0444); e != nil {
			t.Fatal(e)
		}
	}
	if e = stop(creator); e != nil { // Never resume a builder after snapshotting.
		t.Fatal(e)
	}
	checks = append(checks, "full snapshot created only before assignment; creator terminated without tenant execution or resume")
	samples := []map[string]float64{}
	if !faultOnly {
		clones := []*vm{}
		epochs := []guestinit.Request{}
		for index := 1; index <= 2; index++ {
			began := time.Now()
			v := start(index, mem, state, backing)
			clones = append(clones, v)
			staged := time.Since(began)
			api(v, "PUT", "/snapshot/load", map[string]any{"snapshot_path": "/template.state", "mem_backend": map[string]any{"backend_path": "/template.mem", "backend_type": "File"}, "resume_vm": false})
			api(v, "PATCH", "/vm", map[string]any{"state": "Resumed"})
			wait("restored pristine WAITING", func() bool {
				ctx, c := context.WithTimeout(context.Background(), 300*time.Millisecond)
				defer c()
				r, e := guestbridge.Bootstrap(ctx, filepath.Join(v.root, "v.sock"), guestinit.Request{Version: 1, Operation: "state"})
				return e == nil && r.Phase == guestinit.Waiting
			})
			if _, e := guestCall(v, guestwire.Request{Version: 1, Operation: "health", Ref: v.ref}); e == nil {
				t.Fatal("restored clone admitted before initialization")
			}
			req, e := guestinit.NewRequest(v.ref)
			if e != nil {
				t.Fatal(e)
			}
			req.RealtimeNS = 1_609_459_200_000_000_000 // Guest-only2021 clock; never change the host clock.
			want := req.Digest()
			ctx, c := context.WithTimeout(context.Background(), 8*time.Second)
			health, e := guestbridge.Initialize(ctx, filepath.Join(v.root, "v.sock"), req)
			c()
			if e != nil || health.InitializationHash != want || health.BootID != req.BootID {
				t.Fatal("sealed handoff failed; inspect private log", e)
			}
			ctx, c = context.WithTimeout(context.Background(), time.Second)
			_, stillOpen := guestbridge.Bootstrap(ctx, filepath.Join(v.root, "v.sock"), guestinit.Request{Version: 1, Operation: "state"})
			c()
			if stillOpen == nil {
				t.Fatal("bootstrap port survived sealed exec")
			}
			if got := execute(v, "id", "-u").Output.Stdout; strings.TrimSpace(got) != "65534" {
				t.Fatal("wrong guest task UID")
			}
			if got := execute(v, "cat", "/proc/sys/kernel/random/boot_id").Output.Stdout; strings.TrimSpace(got) != req.BootID {
				t.Fatal("boot ID not rebound")
			}
			if got := execute(v, "cat", "/etc/machine-id").Output.Stdout; strings.TrimSpace(got) != strings.ReplaceAll(req.BootID, "-", "") {
				t.Fatal("machine ID not rebound")
			}
			if got := execute(v, "date", "-u", "+%Y").Output.Stdout; strings.TrimSpace(got) != "2021" {
				t.Fatal("guest clock not rebound")
			}
			if time.Now().Year() < 2025 {
				t.Fatal("host clock altered instead of guest clock")
			}
			execute(v, "sh", "-c", "test ! -e other-clone; echo private > other-clone; test ! -r /run/xandbox-init/receipt.json")
			epochs = append(epochs, req)
			req.WipeEntropy()
			samples = append(samples, map[string]float64{"private_staging_and_jailer_api_ms": float64(staged) / 1e6, "staging_to_initialized_guest_commands_ms": float64(time.Since(began)) / 1e6})
		}
		if epochs[0].BootID == epochs[1].BootID || epochs[0].Nonce == epochs[1].Nonce || epochs[0].Ref == epochs[1].Ref {
			t.Fatal("clone initialization identity reused")
		}
		checks = append(checks, "two actual restored KVM guests require new Ref/nonce/entropy and exact sealed normal-health hash before execution", "entropy-add and explicit reseed ioctls succeeded before fresh agent exec replaces agent userspace RNG caches", "per-clone proc boot ID, machine ID and guest-only clock rebound; host clock unchanged", "bootstrap listener removed after handoff; no post-admission reset RPC", "unprivileged tasks cannot read sealed initialization receipt; workspace markers isolated")
		same, e := os.Stat(mem)
		if e != nil {
			t.Fatal(e)
		}
		link, e := os.Stat(filepath.Join(clones[1].root, "template.mem"))
		if e != nil || !os.SameFile(same, link) {
			t.Fatal("memory template not shared immutably")
		}
		if hash(mem) != memHash || hash(backing) != diskHash {
			t.Fatal("shared pristine template changed")
		}
		if e = stop(clones[0]); e != nil {
			t.Fatal(e)
		}
		if e := os.RemoveAll(filepath.Dir(clones[0].root)); e != nil {
			t.Fatal(e)
		}
		execute(clones[1], "true")
		stale := guestwire.Request{Version: 1, Operation: "health", Ref: clones[0].ref}
		if _, e := guestCall(clones[1], stale); e == nil {
			t.Fatal("cross-clone stale Ref accepted")
		}
		if e = stop(clones[1]); e != nil {
			t.Fatal(e)
		}
		checks = append(checks, "read-only shared memory inode unchanged; removing one stopped clone cannot break another live clone", "cross-clone Ref rejected; host cgroup execution stopped before private file removal")

	}
	// Optional PRIVATE export is only for the next real-service fixture. Never
	// export an assigned clone: these sources belong to the stopped, unassigned
	// creator and hashes were checked after both clones finished independently.
	if f.ExportDirectory != "" {
		seedDigest, decodeErr := hex.DecodeString(f.SHA256["agent"])
		if !filepath.IsAbs(f.ExportDirectory) || filepath.Clean(f.ExportDirectory) != f.ExportDirectory || decodeErr != nil || len(seedDigest) != 32 {
			t.Fatal("invalid private export fixture")
		}
		rel, err := filepath.Rel(root, f.ExportDirectory)
		if err != nil || (rel != ".." && !strings.HasPrefix(rel, "../")) {
			t.Fatal("export must be outside removable runtime")
		}
		if err = os.Mkdir(f.ExportDirectory, 0700); err != nil {
			t.Fatal(err)
		}
		if _, err = privatefile.EnsureDirectory(f.ExportDirectory); err != nil {
			t.Fatal(err)
		}
		for source, name := range map[string]string{mem: "memory", state: "state", backing: "workspace.ext4"} {
			if err = copyFile(source, filepath.Join(f.ExportDirectory, name), 0444); err != nil {
				t.Fatal(err)
			}
		}
		abi, err := firecracker.SnapshotHostABI()
		if err != nil {
			t.Fatal(err)
		}
		stateInfo, err := os.Stat(state)
		if err != nil {
			t.Fatal(err)
		}
		manifest := firecracker.SnapshotManifest{Version: 1, Format: "firecracker-v1.17.0-full", SourceRevision: f.SourceRevision, CreatedAt: time.Now().UTC(), Assignment: "UNASSIGNED", BootArgs: "console=ttyS0 reboot=k panic=1 pci=off rdinit=/sbin/init xandbox.guest=1 xandbox.pristine=1", BootstrapProtocol: guestinit.Version, AgentSHA256: f.SHA256["agent"], FirecrackerSHA256: f.SHA256["firecracker"], JailerSHA256: f.SHA256["jailer"], KernelSHA256: f.SHA256["kernel"], InitrdSHA256: f.SHA256["initrd"], WorkspaceSHA256: diskHash, HostABI: abi, MemoryMiB: 512, VCPUs: 2, MemorySHA256: memHash, StateSHA256: hash(state), StateBytes: stateInfo.Size()}
		raw, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		out, err := os.OpenFile(filepath.Join(f.ExportDirectory, "manifest.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = out.Write(append(raw, '\n')); err != nil {
			out.Close()
			t.Fatal(err)
		}
		if err = out.Sync(); err != nil {
			out.Close()
			t.Fatal(err)
		}
		if err = out.Close(); err != nil {
			t.Fatal(err)
		}
		directory, err := os.Open(f.ExportDirectory)
		if err != nil {
			t.Fatal(err)
		}
		err = directory.Sync()
		directory.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	report := map[string]any{"test": "experimental_pristine_bootstrap_snapshot_component", "source_revision": f.SourceRevision, "production_ready": false, "sandboxd_driver_integrated": false, "snapshot_catalog_implemented": false, "snapshot_performance_benchmark": false, "toolchain": runtime.Version(), "architecture": runtime.GOARCH, "guest_memory_mib": 512, "vcpus": 2, "workspace_bytes": 128 << 20, "guest_network_interfaces": 0, "artifacts_sha256": f.SHA256, "snapshot_memory_sha256": memHash, "pristine_disk_sha256": diskHash, "checks": checks, "samples": samples, "notes": "Two same-host restores of an unassigned template; private workspace copies and read-only memory hardlinks. Not a production catalog, shared-reference crash recovery, prewarm pool, load test or SLO. Samples include unoptimized staging/diagnostic commands; no latency claim."}
	if faultOnly {
		report["test"] = "fault_image_unassigned_export_only"
		report["fault_mode"] = f.FaultMode
		report["normal_positive_clone_acceptance"] = false
		report["notes"] = "Private fixture-image builder only: no assigned clone exported and no successful initialization claimed. Real negative service tests are separate."
	}
	out, e := json.MarshalIndent(report, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(f.Report, append(out, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
}
