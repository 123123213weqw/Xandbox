//go:build linux

package gateway

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestGatewayFixedWireAndDescriptorCaps(t *testing.T) {
	good := frame{op: opConnect, request: 1}
	parsed, e := decodeFrame(good.encode())
	if e != nil || parsed != good {
		t.Fatal("wire")
	}
	for _, i := range []int{0, 4, 6, 7} {
		b := good.encode()
		b[i] ^= 1
		if _, e := decodeFrame(b); e == nil {
			t.Fatal("header/reserved field widened")
		}
	}
	for _, b := range [][]byte{nil, good.encode()[:23], append(good.encode(), 0)} {
		if _, e := decodeFrame(b); e == nil {
			t.Fatal("packet framing unbounded")
		}
	}
	p, c, e := packetPair()
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	defer c.Close()
	if e = writeFrame(p, good, -1); e != nil {
		t.Fatal(e)
	}
	f, fd, e := readFrame(c)
	if e != nil || f != good || fd != -1 {
		t.Fatal("packet")
	}
	file, e := os.CreateTemp(t.TempDir(), "fd")
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	file.Write([]byte("test"))
	if e = writeFrame(p, frame{op: opPolicy, request: 1}, int(file.Fd())); e != nil {
		t.Fatal(e)
	}
	f, fd, e = readFrame(c)
	if e != nil || f.op != opPolicy || fd < 0 {
		t.Fatal("descriptor transfer")
	}
	flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if e != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("received descriptor survives exec")
	}
	unix.Close(fd)
}
func TestGatewayTruncatedAndMultipleDescriptorsAreRejectedAndClosed(t *testing.T) {
	p, c, e := packetPair()
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	defer c.Close()
	a, e := unix.Eventfd(0, unix.EFD_CLOEXEC)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(a)
	for _, row := range []struct{ data, oob []byte }{{append(frame{op: opConnect, request: 1}.encode(), bytes.Repeat([]byte{0}, 100)...), nil}, {frame{op: opConnect, request: 1}.encode(), unix.UnixRights(a, a)}} {
		if _, _, e = p.WriteMsgUnix(row.data, row.oob, nil); e != nil {
			t.Fatal(e)
		}
		if _, fd, e := readFrame(c); e == nil || fd != -1 {
			t.Fatal("truncated/excess rights accepted")
		}
	}
}
func TestGatewaySealedSnapshotCannotGrowShrinkWriteOrLoseSeals(t *testing.T) {
	s, _ := testSnapshot(t)
	f, e := sealedSnapshot(s)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	flags, e := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if e != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatal("snapshot is writable")
	}
	if _, e = f.WriteAt([]byte("x"), 0); e == nil {
		t.Fatal("read-only descriptor wrote")
	}
	seals, e := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	if e != nil || seals != snapshotSeals {
		t.Fatal("missing seals")
	}
	if e = unix.Ftruncate(int(f.Fd()), 0); e == nil {
		t.Fatal("sealed descriptor truncated")
	}
	if os.Geteuid() == 0 {
		out, e := readSnapshot(f)
		if e != nil || out.Epoch != s.Epoch {
			t.Fatal("root sealed policy rejected")
		}
	} else {
		if _, e = readSnapshot(f); e == nil {
			t.Fatal("non-root policy producer accepted")
		}
	}
	ordinary, e := os.CreateTemp(t.TempDir(), "not-sealed")
	if e != nil {
		t.Fatal(e)
	}
	defer ordinary.Close()
	ordinary.Write([]byte(`{}`))
	if _, e = readSnapshot(ordinary); e == nil {
		t.Fatal("ordinary file used as policy capability")
	}
}
func TestGatewayChildAndRootNoImplicitHostFallback(t *testing.T) {
	if RunRoot("") == nil {
		t.Fatal("root supervisor accepts unspecified config")
	}
	if RunChild() == nil {
		t.Fatal("child starts without inherited capabilities")
	}
	if childPrivileges(Snapshot{}) == nil {
		t.Fatal("invalid identity accepted")
	}
	for _, path := range []string{"", "api.sock", "/srv/state/operator.sock", "/srv/state/metrics.sock", "/srv/state/../other/api.sock"} {
		if _, e := socketParent(path); e == nil {
			t.Fatal("arbitrary connector target")
		}
	}
	c := &controlClient{}
	if _, e := c.Dial(context.Background(), "tcp", "attacker.test:80"); e == nil {
		t.Fatal("fallback dial")
	}
	if decode := func() error { _, e := decodeFrame(frame{op: 255}.encode()); return e }(); decode == nil {
		t.Fatal("generic operation")
	}
}
func TestGatewayCapabilityEOFClosesClientAndRejectsPendingDial(t *testing.T) {
	p, c, e := packetPair()
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	client := &controlClient{conn: c, store: &Store{}, done: make(chan struct{}), closeIdle: func() {}}
	go client.read()
	p.Close()
	select {
	case <-client.done:
	case <-time.After(time.Second):
		t.Fatal("broker loss not observed")
	}
	if _, e = client.Dial(context.Background(), "tcp", "tenant.local:80"); e == nil {
		t.Fatal("broker loss fell back to network")
	}
	_ = c.Close()
}

func TestGatewayCallerCancelDrainsLateFDWithoutTakingDownOtherTenants(t *testing.T) {
	p, c, e := packetPair()
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	client := &controlClient{conn: c, store: &Store{}, done: make(chan struct{}), closeIdle: func() {}}
	defer client.fail()
	go client.read()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, e := client.Dial(ctx, "tcp", "tenant.local:80"); finished <- e }()
	q, fd, e := readFrame(p)
	if e != nil || fd != -1 || q.op != opConnect {
		t.Fatal("connect request")
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
	file, e := os.CreateTemp(t.TempDir(), "late-capability")
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	if e = writeFrame(p, frame{op: opConnected, request: q.request, lease: 123}, int(file.Fd())); e != nil {
		t.Fatal(e)
	}
	release, fd, e := readFrame(p)
	if e != nil || fd != -1 || release.op != opRelease || release.lease != 123 {
		t.Fatal("cancelled FD not released")
	}
	if e = <-finished; e != context.Canceled {
		t.Fatal("cancellation lost")
	}
	select {
	case <-client.done:
		t.Fatal("caller cancellation killed ingress")
	default:
	}
	go func() { _, e := client.Dial(context.Background(), "tcp", "tenant.local:80"); finished <- e }()
	next, fd, e := readFrame(p)
	if e != nil || fd != -1 || next.op != opConnect || next.request <= q.request {
		t.Fatal("next caller lost protocol sequence")
	}
	writeFrame(p, frame{op: opUnavailable, request: next.request}, -1)
	if e = <-finished; e == nil {
		t.Fatal("unavailable broker response accepted")
	}
	select {
	case <-client.done:
		t.Fatal("normal capacity response killed ingress")
	default:
	}
}

func TestGatewayInvalidHeartbeatEpochFailsClosed(t *testing.T) {
	p, c, e := packetPair()
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	s, a := testSnapshot(t)
	policy, e := NewPolicy(s, a, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	store := &Store{}
	store.Publish(policy)
	client := &controlClient{conn: c, store: store, done: make(chan struct{}), closeIdle: func() {}}
	defer client.fail()
	go client.read()
	writeFrame(p, frame{op: opHeartbeat, request: 2}, -1)
	select {
	case <-client.done:
	case <-time.After(time.Second):
		t.Fatal("wrong policy heartbeat survived")
	}
}

func TestGatewayChildExecMustChdirIntoNewRootAndPassOnlyCapabilities(t *testing.T) {
	cfg := Config{UID: 60001, GID: 60001, EmptyRoot: "/operator/private/root"}
	cmd := childCommand(cfg, nil, nil)
	if cmd.Path != "/gateway" || cmd.Dir != "/" || cmd.SysProcAttr.Chroot != cfg.EmptyRoot || cmd.SysProcAttr.Credential == nil || cmd.SysProcAttr.Credential.Uid != 60001 || cmd.SysProcAttr.Credential.Gid != 60001 || len(cmd.SysProcAttr.Credential.Groups) != 0 || len(cmd.ExtraFiles) != 2 || cmd.Stdin != nil || cmd.Stdout != nil || cmd.Stderr != nil {
		t.Fatal("outside cwd/privileged exec or descriptor capability contract widened")
	}
	for _, arg := range cmd.Args {
		if arg == cfg.EmptyRoot || arg == testBackend {
			t.Fatal("parent-only path or secret in child argv")
		}
	}
}

func TestGatewayExternalLauncherDirectoryFDDoesNotReachNextExec(t *testing.T) {
	const env = "XANDBOX_TEST_GATEWAY_INHERITED_FD"
	switch os.Getenv(env) {
	case "check":
		var st unix.Stat_t
		if e := unix.Fstat(10, &st); e == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR {
			t.Fatal("outside directory survived exec")
		}
		return
	case "sanitize":
		var st unix.Stat_t
		if e := unix.Fstat(10, &st); e != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
			t.Fatal("fixture did not supply actual inherited dir FD")
		}
		if e := sanitizeInheritedFDs(); e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestGatewayExternalLauncherDirectoryFDDoesNotReachNextExec$")
		cmd.Env = append(os.Environ(), env+"=check")
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("sanitized exec failed: %v %s", e, out)
		}
		return
	}
	dir, e := os.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestGatewayExternalLauncherDirectoryFDDoesNotReachNextExec$")
	cmd.Env = append(os.Environ(), env+"=sanitize")
	cmd.ExtraFiles = make([]*os.File, 8)
	cmd.ExtraFiles[7] = dir
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("descriptor inheritance check failed: %v %s", e, out)
	}
}
