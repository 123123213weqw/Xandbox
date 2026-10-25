//go:build linux

package policycontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

func operatorDirectory(t *testing.T) string {
	t.Helper()
	// Short path stays below sockaddr_un.sun_path even for long test names.
	d, e := os.MkdirTemp("", "xbo-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}
func operatorTestPair(t *testing.T) (*net.UnixConn, *net.UnixConn, error) {
	t.Helper()
	fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return nil, nil, e
	}
	a, b := os.NewFile(uintptr(fds[0]), "test-operator-a"), os.NewFile(uintptr(fds[1]), "test-operator-b")
	defer a.Close()
	defer b.Close()
	p, e := net.FileConn(a)
	if e != nil {
		return nil, nil, e
	}
	c, e := net.FileConn(b)
	if e != nil {
		p.Close()
		return nil, nil, e
	}
	return p.(*net.UnixConn), c.(*net.UnixConn), nil
}
func testOperator(t *testing.T) *Server {
	t.Helper()
	s, e := startPolicyOperator(filepath.Join(operatorDirectory(t), "operator.sock"), operatorTestStatus(1, 0, "waiting"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	return s
}
func operatorRequest(t *testing.T, s *Server, c PolicyCommand) (PolicyStatus, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return requestPolicyAt(ctx, s.path, uint32(os.Geteuid()), os.Getpid(), c)
}
func operatorRaw(t *testing.T, s *Server, data, oob []byte) policyReply {
	t.Helper()
	c, e := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: s.path, Net: "unixpacket"})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, _, e = c.WriteMsgUnix(data, oob, nil); e != nil {
		t.Fatal(e)
	}
	b, e := operatorPacket(c)
	if e != nil {
		t.Fatal(e)
	}
	var r policyReply
	if strictjson.Decode(b, &r) != nil || r.Version != 1 {
		t.Fatal("invalid response framing")
	}
	return r
}

func TestOperatorActualUnixPeerPinsAndClosedPackets(t *testing.T) {
	s := testOperator(t)
	status := PolicyCommand{Version: 1, Operation: "status"}
	if got, e := operatorRequest(t, s, status); e != nil || got != s.Status() {
		t.Fatal("named seqpacket status rejected")
	}
	for _, row := range []struct {
		uid uint32
		pid int
	}{{uint32(os.Geteuid()) + 1, os.Getpid()}, {uint32(os.Geteuid()), os.Getpid() + 1}, {uint32(os.Geteuid()), 0}} {
		if _, e := requestPolicyAt(context.Background(), s.path, row.uid, row.pid, status); e == nil {
			t.Fatal("unbound endpoint accepted")
		}
	}
	p, c, e := operatorTestPair(t)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	defer c.Close()
	if operatorPeer(p, uint32(os.Geteuid()), os.Getpid()) != nil || operatorPeer(p, uint32(os.Geteuid())+1, os.Getpid()) == nil || operatorPeer(p, uint32(os.Geteuid()), os.Getpid()+1) == nil {
		t.Fatal("kernel peer credentials not enforced")
	}
	if _, e := RequestPolicy(context.Background(), 1, status); e == nil {
		t.Fatal("unbound public client")
	}
	if os.Getuid() != 0 {
		if _, e := RequestPolicy(context.Background(), os.Getpid(), status); e == nil {
			t.Fatal("nonroot public client")
		}
	}
	for _, b := range [][]byte{
		[]byte(`null`), []byte(`[]`), []byte(`{} {}`), []byte(`{"version":1,"operation":"status","extra":true}`),
		[]byte(`{"version":1,"VERSION":1,"operation":"status"}`), []byte(`{"version":1,"operation":"status","expected_epoch":1}`),
		[]byte(`{"version":2,"operation":"status"}`), []byte(`{"version":1,"operation":"reload"}`),
		bytes.Repeat([]byte("x"), OperatorPacketLimit+1), bytes.Repeat([]byte("x"), OperatorPacketLimit*4),
	} {
		if r := operatorRaw(t, s, b, nil); r.Code != "INVALID" || r.Status != (PolicyStatus{}) {
			t.Fatal("malformed packet produced an observation")
		}
		if len(s.requests) != 0 || s.Status() != operatorTestStatus(1, 0, "waiting") {
			t.Fatal("invalid packet mutated supervisor input")
		}
	}
	if _, e := operatorRequest(t, s, status); e != nil {
		t.Fatal("invalid caller took down listener")
	}
}

func sameFileDescriptors(t *testing.T, original os.FileInfo) int {
	t.Helper()
	entries, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, entry := range entries {
		if st, e := os.Stat(filepath.Join("/proc/self/fd", entry.Name())); e == nil && os.SameFile(original, st) {
			count++
		}
	}
	return count
}
func TestOperatorAncillaryRightsAndTruncationCloseEveryReceivedFD(t *testing.T) {
	p, c, e := operatorTestPair(t)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	defer c.Close()
	f, e := os.CreateTemp(operatorDirectory(t), "rights")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		t.Fatal(e)
	}
	good := []byte(`{"version":1,"operation":"status"}`)
	for _, count := range []int{1, 2, 4, 32} {
		fds := make([]int, count)
		for i := range fds {
			fds[i] = int(f.Fd())
		}
		if _, _, e := p.WriteMsgUnix(good, unix.UnixRights(fds...), nil); e != nil {
			t.Fatal(e)
		}
		if _, e := operatorPacket(c); e == nil {
			t.Fatal("operator delegated a file capability")
		}
		if got := sameFileDescriptors(t, st); got != 1 {
			t.Fatalf("received rights leaked: %d copies", got)
		}
	}
	s := testOperator(t)
	if r := operatorRaw(t, s, good, unix.UnixRights(int(f.Fd()))); r.Code != "INVALID" {
		t.Fatal("named operator accepted rights")
	}
	if got := sameFileDescriptors(t, st); got != 1 {
		t.Fatal("named operator leaked right")
	}
}

func TestOperatorLostResponseRetryWithSyntheticSupervisorAndACK(t *testing.T) {
	// This is a transport/model test, NOT a real policy-store commit, RunRoot,
	// frontend ACK, installation transaction, VM continuity or root CLI acceptance.
	s := testOperator(t)
	d1 := s.Status().SnapshotSHA256
	active := s.Status()
	active.ActiveEpoch = 1
	active.ActiveSHA256 = d1
	active.Phase = "active"
	if s.Publish(active) != nil {
		t.Fatal("initial synthetic ACK")
	}
	d2 := strings.Repeat("b", 64)
	command := PolicyCommand{Version: 1, Operation: "activate", ExpectedEpoch: 1, TargetEpoch: 2, SnapshotSHA256: d2}
	b, _ := json.Marshal(command)
	c, e := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: s.path, Net: "unixpacket"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Write(b); e != nil {
		t.Fatal(e)
	}
	var first Activation
	select {
	case first = <-s.requests:
	case <-time.After(2 * time.Second):
		t.Fatal("activation not delivered")
	}
	_ = c.Close() // Caller loses the response BEFORE durable commit.
	if duplicate, e := Classify(first.Command, s.Status()); e != nil || duplicate {
		t.Fatal("first classification")
	}
	committing := active
	committing.Phase = "committing"
	if s.Publish(committing) != nil {
		t.Fatal("commit start")
	}
	waiting := active
	waiting.DurableEpoch = 2
	waiting.SnapshotSHA256 = d2
	waiting.Phase = "waiting"
	if s.Publish(waiting) != nil {
		t.Fatal("commit finish")
	}
	first.reply <- policyReply{Version: 1, Status: waiting}
	mutations := 1
	exchange := func(command PolicyCommand, conflict bool) PolicyStatus {
		t.Helper()
		done := make(chan struct {
			status PolicyStatus
			err    error
		}, 1)
		go func() {
			got, e := operatorRequest(t, s, command)
			done <- struct {
				status PolicyStatus
				err    error
			}{got, e}
		}()
		var request Activation
		select {
		case request = <-s.requests:
		case <-time.After(2 * time.Second):
			t.Fatal("retry not delivered")
		}
		duplicate, e := Classify(request.Command, s.Status())
		if conflict {
			if e == nil {
				t.Fatal("conflict became mutation")
			}
			request.reply <- policyReply{Version: 1, Code: "CONFLICT"}
		} else {
			if e != nil || !duplicate {
				mutations++
				t.Fatal("retry would redispatch policy transfer")
			}
			request.reply <- policyReply{Version: 1, Status: s.Status()}
		}
		select {
		case result := <-done:
			if (result.err != nil) != conflict {
				t.Fatal("retry result")
			}
			return result.status
		case <-time.After(3 * time.Second):
			t.Fatal("retry response timeout")
			return PolicyStatus{}
		}
	}
	if got := exchange(command, false); got != waiting {
		t.Fatal("unacknowledged child reported active")
	}
	if got, e := operatorRequest(t, s, PolicyCommand{Version: 1, Operation: "status"}); e != nil || got != waiting {
		t.Fatal("lost response not observationally recoverable")
	}
	bad := command
	bad.SnapshotSHA256 = strings.Repeat("c", 64)
	exchange(bad, true)
	bad = command
	bad.ExpectedEpoch = 2
	bad.TargetEpoch = 3
	exchange(bad, true) // Still waiting for previous synthetic ACK.
	active = waiting
	active.ActiveEpoch = 2
	active.ActiveSHA256 = d2
	active.Phase = "active"
	if s.Publish(active) != nil {
		t.Fatal("synthetic next ACK")
	}
	if got := exchange(command, false); got != active || mutations != 1 {
		t.Fatal("exact retry redispatched the synthetic supervisor")
	}
	for _, next := range []PolicyStatus{waiting, committing} {
		if s.Publish(next) == nil || s.Status() != active {
			t.Fatal("progress rolled back")
		}
	}
}

func TestOperatorSupervisorResponseIsSingleAndCannotCarryArbitraryError(t *testing.T) {
	s := testOperator(t)
	command := PolicyCommand{Version: 1, Operation: "activate", TargetEpoch: 1, SnapshotSHA256: s.Status().SnapshotSHA256}
	done := make(chan error, 1)
	go func() { _, e := operatorRequest(t, s, command); done <- e }()
	var r Activation
	select {
	case r = <-s.Requests():
	case <-time.After(2 * time.Second):
		t.Fatal("request not delivered")
	}
	if r.Respond(PolicyStatus{}, "PRIVATE_TEST_SENTINEL") == nil {
		t.Fatal("unbounded error accepted")
	}
	if r.Respond(s.Status(), "") != nil || r.Respond(s.Status(), "") == nil {
		t.Fatal("response not single-shot")
	}
	select {
	case e := <-done:
		if e != nil {
			t.Fatal("valid pending observation rejected")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("unbounded response")
	}
	if (Activation{}).Respond(PolicyStatus{}, "BUSY") == nil {
		t.Fatal("fabricated activation response")
	}
}

func TestOperatorStatusBypassesFullActivationQueueAndNoImplicitActivation(t *testing.T) {
	s := testOperator(t)
	for i := 0; i < cap(s.requests); i++ {
		s.requests <- Activation{}
	}
	if got, e := operatorRequest(t, s, PolicyCommand{Version: 1, Operation: "status"}); e != nil || got != s.Status() {
		t.Fatal("status depended on writable activation queue")
	}
	command := PolicyCommand{Version: 1, Operation: "activate", TargetEpoch: 1, SnapshotSHA256: s.Status().SnapshotSHA256}
	if _, e := operatorRequest(t, s, command); e == nil || len(s.requests) != cap(s.requests) {
		t.Fatal("activation queue unbounded")
	}
	s2 := testOperator(t)
	done := make(chan error, 1)
	go func() { _, e := operatorRequest(t, s2, command); done <- e }()
	select {
	case <-s2.requests:
	case <-time.After(2 * time.Second):
		t.Fatal("activation not queued")
	}
	// Without a supervisor reply, the transport must not invent activation.
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("timeout reported success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("unbounded missing reply")
	}
	if s2.Status() != operatorTestStatus(1, 0, "waiting") {
		t.Fatal("transport invented a policy ACK")
	}
}

func TestOperatorClientRejectsWrongTargetAndServerClosesReplyVocabulary(t *testing.T) {
	s := testOperator(t)
	command := PolicyCommand{Version: 1, Operation: "activate", ExpectedEpoch: 1, TargetEpoch: 2, SnapshotSHA256: strings.Repeat("b", 64)}
	for _, status := range []PolicyStatus{operatorTestStatus(1, 1, "active"), operatorTestStatus(2, 2, "active"), {Version: 1, DurableEpoch: 2, SnapshotSHA256: command.SnapshotSHA256, Phase: "fenced"}} {
		done := make(chan error, 1)
		go func() { _, e := operatorRequest(t, s, command); done <- e }()
		select {
		case request := <-s.requests:
			request.reply <- policyReply{Version: 1, Status: status}
		case <-time.After(2 * time.Second):
			t.Fatal("command not delivered")
		}
		select {
		case e := <-done:
			if e == nil {
				t.Fatal("unrelated/fenced target reported success")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("unbounded response")
		}
	}
	c, e := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: s.path, Net: "unixpacket"})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	b, _ := json.Marshal(command)
	if _, e := c.Write(b); e != nil {
		t.Fatal(e)
	}
	select {
	case request := <-s.requests:
		request.reply <- policyReply{Version: 1, Code: "PRIVATE_TEST_SENTINEL"}
	case <-time.After(2 * time.Second):
		t.Fatal("command not delivered")
	}
	b, e = operatorPacket(c)
	if e != nil {
		t.Fatal(e)
	}
	var reply policyReply
	if strictjson.Decode(b, &reply) != nil || !reply.valid() || reply.Code != "UNAVAILABLE" || bytes.Contains(b, []byte("PRIVATE_TEST_SENTINEL")) {
		t.Fatal("unbounded/private supervisor error escaped")
	}
}

func TestOperatorEndpointOwnershipStaleRecoveryAndIdentitySafeClose(t *testing.T) {
	dir := operatorDirectory(t)
	path := filepath.Join(dir, "operator.sock")
	initial := operatorTestStatus(1, 0, "waiting")
	if e := os.WriteFile(path, []byte("not owned by operator"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := startPolicyOperator(path, initial); e == nil {
		t.Fatal("unknown file adopted")
	}
	if b, e := os.ReadFile(path); e != nil || string(b) != "not owned by operator" {
		t.Fatal("unknown file removed")
	}
	os.Remove(path)
	if e := os.Symlink("missing", path); e != nil {
		t.Fatal(e)
	}
	if _, e := startPolicyOperator(path, initial); e == nil {
		t.Fatal("socket symlink adopted")
	}
	os.Remove(path)
	l, e := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if e != nil {
		t.Fatal(e)
	}
	l.SetUnlinkOnClose(false)
	os.Chmod(path, 0600)
	l.Close()
	s, e := startPolicyOperator(path, initial)
	if e != nil {
		t.Fatal("private stale socket not recovered")
	}
	defer s.Close()
	if _, e := startPolicyOperator(path, initial); e == nil {
		t.Fatal("live operator replaced")
	}
	if _, e := operatorRequest(t, s, PolicyCommand{Version: 1, Operation: "status"}); e != nil {
		t.Fatal("live endpoint lost after rejected competitor")
	}
	if e := os.Rename(path, path+".old"); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte("replacement"), 0600); e != nil {
		t.Fatal(e)
	}
	s.Close()
	if b, e := os.ReadFile(path); e != nil || string(b) != "replacement" {
		t.Fatal("close unlinked unrelated replacement")
	}
	if s.Publish(initial) == nil {
		t.Fatal("closed operator accepted progress")
	}
	for _, mode := range []os.FileMode{0711, 0755, 0777} {
		d := operatorDirectory(t)
		if os.Chmod(d, mode) != nil {
			t.Fatal("chmod")
		}
		if _, e := startPolicyOperator(filepath.Join(d, "operator.sock"), initial); e == nil {
			t.Fatal("nonprivate parent accepted")
		}
	}
}

func TestOperatorCloseReapsIdleConnectionsAndBoundsHandlers(t *testing.T) {
	s := testOperator(t)
	var connections []*net.UnixConn
	defer func() {
		for _, c := range connections {
			c.Close()
		}
	}()
	for i := 0; i < 4; i++ {
		c, e := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: s.path, Net: "unixpacket"})
		if e != nil {
			t.Fatal(e)
		}
		connections = append(connections, c)
	}
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		n := len(s.connections)
		s.mu.Unlock()
		if n == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("idle handlers not admitted")
		}
		time.Sleep(time.Millisecond)
	}
	c, e := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: s.path, Net: "unixpacket"})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := operatorPacket(c); e == nil {
		t.Fatal("excess connection admitted")
	}
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close left blocked handlers")
	}
	if _, e := os.Lstat(s.path); !os.IsNotExist(e) {
		t.Fatal("owned socket survived close")
	}
	s.mu.Lock()
	n := len(s.connections)
	s.mu.Unlock()
	if n != 0 {
		t.Fatal("owned connection survived close")
	}
}

func TestOperatorSocketSpecialModesAndMultipleLinksRejected(t *testing.T) {
	s := testOperator(t)
	info, e := os.Lstat(s.path)
	if e != nil {
		t.Fatal(e)
	}
	st := *info.Sys().(*syscall.Stat_t)
	if !privateOperatorSocket(info, uint32(os.Geteuid())) {
		t.Fatal("normal socket rejected")
	}
	for _, mutate := range []func(*syscall.Stat_t){func(st *syscall.Stat_t) { st.Nlink = 2 }, func(st *syscall.Stat_t) { st.Mode |= 04000 }, func(st *syscall.Stat_t) { st.Uid++ }} {
		copy := st
		mutate(&copy)
		if privateOperatorSocket(operatorFileInfo{FileInfo: info, stat: &copy}, uint32(os.Geteuid())) {
			t.Fatal("special or aliased socket accepted")
		}
	}
}

type operatorFileInfo struct {
	os.FileInfo
	stat *syscall.Stat_t
}

func (s operatorFileInfo) Sys() any { return s.stat }
