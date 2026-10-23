//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: the fixed schema3 no-snapshot L1 admission/operator protocol.
// No host command, path, UID, target mode or resource budget comes from RPC.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const operatorReceiptPath = "/srv/fixture/node-operator-receipt.json"
const operatorSocket = "/srv/state/operator.sock"
const operatorForeignUID = 400003

type operatorForeignReport struct {
	Connected   bool   `json:"connected"`
	NoHTTPBytes bool   `json:"no_http_bytes"`
	PeerPID     int32  `json:"peer_pid"`
	PeerUID     uint32 `json:"peer_uid"`
}

// Only a fixed unprivileged direct child of this L1 PID1 can reach this helper.
// It connects AFTER setuid; passing an already-connected root FD would not test
// SO_PEERCRED. Failure at pathname DAC is NOT accepted as a peer-filter result.
func runOperatorForeignChild() error {
	if os.Getuid() != operatorForeignUID || os.Geteuid() != operatorForeignUID || os.Getgid() != operatorForeignUID || os.Getegid() != operatorForeignUID || os.Getppid() != 1 || os.Getpid() == 1 {
		return errors.New("fixed isolated L1 foreign child required")
	}
	// The image marker is root0600. PID1 passes ONLY its read-only marker FD,
	// never a connected operator FD or tenant credential. Socket connect below
	// still occurs after setuid, so SO_PEERCRED observes the foreign UID.
	marker := os.NewFile(3, "fixed-l1-marker")
	if marker == nil {
		return errors.New("read-only L1 marker descriptor required")
	}
	defer marker.Close()
	if e := operatorMarkerDescriptor(marker); e != nil {
		return e
	}
	groups, e := os.Getgroups()
	if e != nil || len(groups) != 0 {
		return errors.New("foreign child must have no supplemental groups")
	}
	parent, e := os.ReadFile("/proc/1/cmdline")
	if e != nil || string(parent) != "/usr/bin/xandbox-host-fixture\x00-mode\x00node-budget\x00" {
		return errors.New("fixed budget PID1 required")
	}
	status, e := os.ReadFile("/proc/self/status")
	if e != nil {
		return e
	}
	if e = operatorForeignCapabilities(string(status)); e != nil {
		return e
	}
	data, e := io.ReadAll(io.LimitReader(os.Stdin, nodecontrol.MaxCommandBytes+1))
	if e != nil || len(data) > nodecontrol.MaxCommandBytes {
		return errors.New("bounded fixed command required")
	}
	var command nodecontrol.Command
	if strictjson.Decode(data, &command) != nil || !command.Valid() {
		return errors.New("fixed valid resume command required")
	}
	c, e := net.DialTimeout("unix", operatorSocket, time.Second)
	if e != nil {
		return errors.New("foreign child did not connect: DAC refusal is not peer proof")
	}
	defer c.Close()
	u, ok := c.(*net.UnixConn)
	if !ok {
		return errors.New("Unix connection required")
	}
	raw, e := u.SyscallConn()
	if e != nil {
		return e
	}
	var peer *unix.Ucred
	var inner error
	if e = raw.Control(func(fd uintptr) { peer, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); e != nil || inner != nil || peer == nil || peer.Uid != 0 || peer.Pid <= 1 {
		return errors.New("connected peer was not L1 daemon")
	}
	if e = c.SetDeadline(time.Now().Add(2 * time.Second)); e != nil {
		return e
	}
	request, e := http.NewRequest("POST", "http://operator.local/v1/node/resume", bytes.NewReader(data))
	if e != nil {
		return e
	}
	request.Header.Set("Content-Type", "application/json")
	// A quick peer close may race Write; still demand actual connected peer and
	// EOF/reset without even one HTTP byte, never a read timeout or403 response.
	writeErr := request.Write(c)
	var first [1]byte
	n, readErr := c.Read(first[:])
	if n != 0 || !(errors.Is(readErr, io.EOF) || errors.Is(readErr, unix.ECONNRESET)) {
		return errors.New("foreign peer not closed before HTTP")
	}
	if writeErr != nil && !errors.Is(writeErr, unix.EPIPE) && !errors.Is(writeErr, unix.ECONNRESET) {
		return errors.New("unexpected foreign write failure")
	}
	return json.NewEncoder(os.Stdout).Encode(operatorForeignReport{Connected: true, NoHTTPBytes: true, PeerPID: peer.Pid, PeerUID: peer.Uid})
}

func operatorMarkerDescriptor(marker *os.File) error {
	info, e := marker.Stat()
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	flags, e := unix.FcntlInt(marker.Fd(), unix.F_GETFL, 0)
	if e != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != 0 || st.Nlink != 1 || info.Size() != int64(len(fixtureMarker)) || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return errors.New("invalid read-only root L1 marker descriptor")
	}
	data, e := io.ReadAll(io.LimitReader(marker, 64))
	if e != nil || string(data) != fixtureMarker {
		return errors.New("invalid inherited L1 marker contents")
	}
	return nil
}

func operatorForeignCapabilities(status string) error {
	for _, field := range []string{"CapPrm", "CapEff", "CapAmb"} {
		count := 0
		for _, line := range strings.Split(status, "\n") {
			parts := strings.Fields(line)
			if len(parts) == 2 && parts[0] == field+":" {
				count++
				v, e := strconv.ParseUint(parts[1], 16, 64)
				if e != nil || v != 0 {
					return errors.New("foreign child capability retained or invalid")
				}
			}
		}
		if count != 1 {
			return errors.New("foreign child capability field missing/duplicate")
		}
	}
	return nil
}

func operatorCommand(s nodecontrol.State) (nodecontrol.Command, error) {
	id, e := nodecontrol.NewRequestID()
	return nodecontrol.Command{Version: 1, Epoch: s.Epoch, ExpectedRevision: s.Revision, RequestID: id}, e
}
func operatorConflict(ctx context.Context, c *nodecontrol.Client, command nodecontrol.Command) error {
	if _, e := c.Change(ctx, nodecontrol.ModeOpen, command); e == nil || !strings.Contains(e.Error(), "CONFLICT") {
		return errors.New("stale/unauthorized resume did not conflict")
	}
	return nil
}
func operatorDenied(ctx context.Context, api *switchAPI, path, key string, body any) error {
	var out struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if e := api.call(ctx, "POST", path, key, body, &out, 503); e != nil {
		return e
	}
	if out.Error.Code != "NODE_DRAINING" {
		return errors.New("new reservation rejected for wrong reason")
	}
	return nil
}
func operatorState() (nodecontrol.State, error) {
	var s nodecontrol.State
	b, e := privatefile.Read("/srv/state/admission/state.json", 4096)
	if e == nil {
		e = strictjson.Decode(b, &s)
	}
	return s, e
}
func operatorFileNames(dir string) ([]string, error) {
	entries, e := os.ReadDir(dir)
	if e != nil {
		return nil, e
	}
	if len(entries) > 32 {
		return nil, errors.New("operator fixture inventory bound")
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil, errors.New("unexpected fixture journal entry")
		}
		out = append(out, entry.Name())
	}
	sort.Strings(out)
	return out, nil
}
func operatorSessionBytes(id string) ([]byte, error) {
	if !hex32Pattern(id) {
		return nil, errors.New("invalid fixed session ref")
	}
	return privatefile.Read("/srv/state/sessions/"+id+".json", 1<<20)
}
func (n *node) operatorForeign(ctx context.Context, c *nodecontrol.Client, drained nodecontrol.State) (err error) {
	if e := requireNode(); e != nil {
		return e
	}
	if n.process == nil {
		return errors.New("ordinary operator daemon required")
	}
	if e := operatorEmptyInstances(nodeBudgetInstances); e != nil {
		return e
	}
	view, e := c.Status(ctx)
	if e != nil || view.Control.Committed != drained || view.Control.AdmissionOpen || view.ResourceObservation.Active != 0 || view.ResourceObservation.Records != 0 {
		return errors.New("foreign UID test requires fresh drained node")
	}
	// Deliberate DAC bypass ONLY for this isolated L1 and before ANY guest.
	// Capture and restore exact inode modes even when child/positive control fails.
	paths := []string{"/srv", "/srv/state", operatorSocket}
	infos := make([]os.FileInfo, len(paths))
	for i, p := range paths {
		infos[i], e = os.Lstat(p)
		if e != nil {
			return e
		}
		st, ok := infos[i].Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || infos[i].Mode()&os.ModeSymlink != 0 {
			return errors.New("untrusted own operator path")
		}
		if i < 2 && (!infos[i].IsDir() || infos[i].Mode().Perm()&0022 != 0) {
			return errors.New("untrusted own operator directory")
		}
		if i == 2 && (infos[i].Mode()&os.ModeSocket == 0 || infos[i].Mode().Perm() != 0600 || st.Nlink != 1) {
			return errors.New("private own operator socket required")
		}
	}
	defer func() {
		for i := len(paths) - 1; i >= 0; i-- {
			now, e := os.Lstat(paths[i])
			if e != nil || !os.SameFile(now, infos[i]) {
				err = errors.Join(err, errors.New("operator path replaced during foreign probe"))
				continue
			}
			err = errors.Join(err, os.Chmod(paths[i], infos[i].Mode().Perm()))
		}
	}()
	for i, p := range paths {
		mode := os.FileMode(0755)
		if i == 2 {
			mode = 0666
		}
		if e = os.Chmod(p, mode); e != nil {
			return e
		}
	}
	positive := newSwitchAPI(operatorSocket, "")
	defer positive.close()
	var observed nodecontrol.Reply
	if e = positive.call(ctx, "GET", "/v1/node", "", nil, &observed, 200); e != nil || observed.Control.Committed != drained || observed.Control.AdmissionOpen {
		return errors.New("same-UID wide-DAC positive control failed")
	}
	command, e := operatorCommand(drained)
	if e != nil {
		return e
	}
	data, e := json.Marshal(command)
	if e != nil {
		return e
	}
	childCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	child := exec.CommandContext(childCtx, "/usr/bin/xandbox-host-fixture", "-mode", "node-operator-foreign")
	marker, e := os.Open("/etc/xandbox-host-fixture")
	if e != nil {
		return e
	}
	defer marker.Close()
	if e = operatorMarkerDescriptor(marker); e != nil {
		return e
	}
	if _, e = marker.Seek(0, io.SeekStart); e != nil {
		return e
	}
	child.ExtraFiles = []*os.File{marker}
	child.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	child.Stdin = bytes.NewReader(data)
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: operatorForeignUID, Gid: operatorForeignUID, Groups: []uint32{}}}
	var output, diagnostic bytes.Buffer
	child.Stdout = &output
	child.Stderr = &diagnostic
	if e = child.Run(); e != nil {
		fmt.Fprintln(os.Stderr, "private foreign operator child:", diagnostic.String())
		return errors.New("fixed foreign operator child failed/reaped")
	}
	if output.Len() > 1024 || diagnostic.Len() != 0 {
		return errors.New("unbounded foreign operator reply")
	}
	var result operatorForeignReport
	if e = strictjson.Decode(output.Bytes(), &result); e != nil || !result.Connected || !result.NoHTTPBytes || result.PeerUID != 0 || int(result.PeerPID) != n.process.Process.Pid {
		return errors.New("foreign UID kernel peer witness invalid")
	}
	return nil
}

func operatorEmptyInstances(root string) error {
	entries, e := os.ReadDir(root)
	if e != nil {
		return e
	}
	// Empty cgroup2 directories still contain their kernel control FILES.
	// Only descendant directories represent possible execution domains.
	for _, entry := range entries {
		if entry.IsDir() {
			return errors.New("foreign UID test requires zero descendant execution domains")
		}
	}
	procs, e := os.ReadFile(root + "/cgroup.procs")
	if e != nil || len(bytes.TrimSpace(procs)) != 0 {
		return errors.New("foreign UID test requires empty instance parent")
	}
	return nil
}

type operatorCheckpoint struct {
	Version                                                int
	Phase, L1Boot, Config                                  string
	Committed                                              nodecontrol.State
	LastDrain, StaleResume                                 nodecontrol.Command
	Session                                                session.Result
	SessionKey, RawKey, RejectedRawKey, RejectedSessionKey string
	AllRefs                                                []sandbox.Ref
	Owner                                                  []byte
	Quota                                                  driverQuotaReceipt
	L2Boot                                                 string
	L2Boots                                                []string
}

func (n *node) operatorProfile() error {
	if e := requireNode(); e != nil {
		return e
	}
	if !n.nodeBudget || n.nodeSnapshot || n.quotaSnapshot || n.quotaSwitch || n.mapper != nil || !n.quotaDriver || n.process != nil {
		return errors.New("fresh fixed no-snapshot node-budget operator profile required")
	}
	_, e := fixedBudgetConfig()
	return e
}
func operatorGuest(ctx context.Context, n *node, api *switchAPI, ref sandbox.Ref, marker string, binding *session.Result) (string, error) {
	if e := budgetVM(ref); e != nil {
		return "", e
	}
	cfg, e := fixedBudgetConfig()
	if e != nil {
		return "", e
	}
	if e = syscallGuestBoundaryWithObserver(cfg, ref, n.process.Process.Pid, false); e != nil {
		return "", e
	}
	// Marker is a fixed compile-time label, not RPC/tenant input.
	if marker != "raw" && marker != "session" && marker != "switched" && marker != "cold" {
		return "", errors.New("unknown guest marker")
	}
	argv := []string{"sh", "-c", "set -e; test ! -e operator-marker; printf '" + marker + "' > operator-marker; sync; id -u; cat /proc/sys/kernel/random/boot_id"}
	var output sandbox.Output
	if binding == nil {
		output, e = api.executeVM(ctx, ref, argv)
	} else {
		if binding.Current != ref {
			return "", errors.New("operator session guest route mismatch")
		}
		output, e = api.sessionExec(ctx, *binding, argv)
	}

	if e != nil {
		return "", e
	}
	return switchGuestIdentity(output)
}
func operatorIdle(ctx context.Context, c *nodecontrol.Client, active, records int) error {
	return waitNode(ctx, func() (bool, error) {
		r, e := c.Status(ctx)
		s := r.ResourceObservation
		return e == nil && s.Active == active && s.Records == records && s.StopQueued == 0 && s.StopRunning == 0 && s.CleanupQueued == 0 && s.CleanupRunning == 0 && r.Control.PendingSessionReservations == 0, e
	})
}
func (n *node) nodeOperatorCheckpoint(ctx context.Context) (map[string]any, error) {
	if e := n.operatorProfile(); e != nil {
		return nil, e
	}
	if e := n.start(ctx); e != nil {
		return nil, e
	}
	c, e := nodecontrol.NewClient("/srv/state")
	if e != nil {
		return nil, e
	}
	defer c.Close()
	initial, e := c.Status(ctx)
	if e != nil || initial.Control.Phase != "ready" || !initial.Control.AdmissionOpen || initial.Control.Committed.Revision != 1 {
		return nil, errors.New("fresh open operator epoch required")
	}
	firstDrain, e := operatorCommand(initial.Control.Committed)
	if e != nil {
		return nil, e
	}
	foreignState, e := c.Change(ctx, nodecontrol.ModeDrained, firstDrain)
	if e != nil {
		return nil, e
	}
	if e = n.operatorForeign(ctx, c, foreignState.Control.Committed); e != nil {
		return nil, e
	}
	after, e := c.Status(ctx)
	if e != nil || after.Control.Committed != foreignState.Control.Committed || after.Control.AdmissionOpen {
		return nil, errors.New("foreign UID changed durable operator state")
	}
	reopen, e := operatorCommand(after.Control.Committed)
	if e != nil {
		return nil, e
	}
	opened, e := c.Change(ctx, nodecontrol.ModeOpen, reopen)
	if e != nil || !opened.Control.AdmissionOpen {
		return nil, errors.New("authorized same-UID resume failed")
	}
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	defer api.close()
	rawKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	raw, e := api.create(ctx, rawKey)
	if e != nil {
		return nil, e
	}
	rawBoot, e := operatorGuest(ctx, n, api, raw.Ref, "raw", nil)
	if e != nil {
		return nil, e
	}
	sessionKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	bound, e := api.openSession(ctx, sessionKey)
	if e != nil {
		return nil, e
	}
	sessionBoot, e := operatorGuest(ctx, n, api, bound.Current, "session", &bound)
	if e != nil {
		return nil, fmt.Errorf("operator session guest validation: %w", e)
	}
	if rawBoot == sessionBoot {
		return nil, errors.New("independent real raw/session guest boots required")
	}
	busy, e := n.submit(ctx, raw.Ref, []string{"sh", "-c", "i=0; while :; do i=$((i+1)); printf '%s\\n' \"$i\" > operator-progress.tmp; mv operator-progress.tmp operator-progress; sleep 0.05; done"})
	if e != nil {
		return nil, e
	}
	progress := func() (int, error) {
		out, e := api.executeVM(ctx, raw.Ref, []string{"sh", "-c", "cat operator-progress 2>/dev/null || echo 0"})
		if e != nil {
			return 0, e
		}
		return strconv.Atoi(strings.TrimSpace(out.Stdout))
	}
	before := 0
	if e = waitNode(ctx, func() (bool, error) { var e error; before, e = progress(); return before > 0, e }); e != nil {
		return nil, e
	}
	names, e := operatorFileNames("/srv/state/ledger")
	if e != nil || len(names) != 2 {
		return nil, errors.New("unexpected initial operator ledger")
	}
	savedSession, e := operatorSessionBytes(bound.ID)
	if e != nil {
		return nil, e
	}
	drainCommand, e := operatorCommand(opened.Control.Committed)
	if e != nil {
		return nil, e
	}
	drained, e := c.Change(ctx, nodecontrol.ModeDrained, drainCommand)
	if e != nil || drained.Control.AdmissionOpen {
		return nil, errors.New("live drain failed")
	}
	replay, e := c.Change(ctx, nodecontrol.ModeDrained, drainCommand)
	if e != nil || replay.Control.Committed != drained.Control.Committed {
		return nil, errors.New("exact drain replay failed")
	}
	rejectedRaw, e := randomKey()
	if e != nil {
		return nil, e
	}
	rejectedSession, e := randomKey()
	if e != nil {
		return nil, e
	}
	switchKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	switchRequest := session.SwitchRequest{ExpectedRevision: bound.Revision, Create: nodeSpec()}
	for _, attempt := range []struct {
		path, key string
		body      any
	}{{"/v1/sandboxes", rejectedRaw, nodeSpec()}, {"/v1/sessions", rejectedSession, nodeSpec()}, {"/v1/sessions/" + bound.ID + "/switch", switchKey, switchRequest}} {
		if e = operatorDenied(ctx, api, attempt.path, attempt.key, attempt.body); e != nil {
			return nil, e
		}
	}
	now, e := operatorFileNames("/srv/state/ledger")
	if e != nil || strings.Join(now, ",") != strings.Join(names, ",") {
		return nil, errors.New("drained creation consumed ledger metadata")
	}
	sessions, e := operatorFileNames("/srv/state/sessions")
	if e != nil || len(sessions) != 1 {
		return nil, errors.New("drained open consumed session record")
	}
	currentSession, e := operatorSessionBytes(bound.ID)
	if e != nil || !bytes.Equal(currentSession, savedSession) {
		return nil, errors.New("drained switch changed durable history")
	}
	var rawReplay sandbox.Record
	if e = api.call(ctx, "POST", "/v1/sandboxes", rawKey, nodeSpec(), &rawReplay, 201); e != nil || rawReplay.Ref != raw.Ref {
		return nil, errors.New("raw accepted replay lost during drain")
	}
	boundReplay, e := api.openSession(ctx, sessionKey)
	if e != nil || boundReplay.Current != bound.Current || boundReplay.Revision != bound.Revision {
		return nil, errors.New("session accepted replay lost during drain")
	}
	if e = api.call(ctx, "GET", "/readyz", "", nil, nil, 503); e != nil {
		return nil, e
	}
	var health struct {
		Open bool `json:"admission_open"`
	}
	if e = api.call(ctx, "GET", "/healthz", "", nil, &health, 200); e != nil || health.Open {
		return nil, errors.New("drained health/readiness incorrect")
	}
	if e = api.call(ctx, "POST", "/v1/node/resume", "", nil, nil, 404); e != nil {
		return nil, e
	}
	if e = waitNode(ctx, func() (bool, error) { v, e := progress(); return v > before, e }); e != nil {
		return nil, e
	}
	job, e := n.job(ctx, raw.Ref, busy)
	if e != nil || job.Status != "RUNNING" {
		return nil, errors.New("pre-drain task did not remain running")
	}
	out, e := api.sessionExec(ctx, bound, []string{"cat", "operator-marker"})
	if e != nil || out.Stdout != "session" {
		return nil, errors.New("old session execution lost during drain")
	}
	rawOwner, _, e := budgetOwner(raw.Ref)
	if e != nil {
		return nil, e
	}
	began := time.Now()
	if e = api.call(ctx, "DELETE", switchPath(raw.Ref), "", generationBody(raw.Ref), nil, 202); e != nil {
		return nil, e
	}
	if e = waitNode(ctx, func() (bool, error) {
		b, e := os.ReadFile(nodeBudgetInstances + "/" + raw.ID + raw.Generation + "/cgroup.procs")
		return os.IsNotExist(e) || (e == nil && len(bytes.TrimSpace(b)) == 0), func() error {
			if os.IsNotExist(e) {
				return nil
			}
			return e
		}()
	}); e != nil {
		return nil, e
	}
	stopMS := switchMS(began)
	if e = budgetDestroyed(ctx, api, raw.Ref); e != nil {
		return nil, e
	}
	rawQuota, e := driverQuotaRead(rawOwner.ProjectID)
	if e != nil || !quotaEmpty(rawQuota) {
		return nil, errors.New("drained raw private quota not zero")
	}
	reclaimMS := switchMS(began)
	stale, e := operatorCommand(initial.Control.Committed)
	if e != nil {
		return nil, e
	}
	if e = operatorConflict(ctx, c, stale); e != nil {
		return nil, e
	}
	resume, e := operatorCommand(drained.Control.Committed)
	if e != nil {
		return nil, e
	}
	resumed, e := c.Change(ctx, nodecontrol.ModeOpen, resume)
	if e != nil || !resumed.Control.AdmissionOpen {
		return nil, errors.New("live resume failed")
	}
	newRaw, e := api.create(ctx, rejectedRaw)
	if e != nil {
		return nil, e
	}
	newRawBoot, e := operatorGuest(ctx, n, api, newRaw.Ref, "raw", nil)
	if e != nil {
		return nil, e
	}
	newSession, e := api.openSession(ctx, rejectedSession)
	if e != nil {
		return nil, e
	}
	newSessionBoot, e := operatorGuest(ctx, n, api, newSession.Current, "session", &newSession)
	if e != nil {
		return nil, e
	}
	var switched session.Result
	if e = api.call(ctx, "POST", "/v1/sessions/"+bound.ID+"/switch", switchKey, switchRequest, &switched, 200); e != nil || switched.Revision != 2 || switched.Previous != bound.Current || switched.Current == bound.Current {
		return nil, errors.New("previously rejected switch key not reusable")
	}
	liveBoot, e := operatorGuest(ctx, n, api, switched.Current, "switched", &switched)
	if e != nil || liveBoot == sessionBoot {
		return nil, errors.New("new switch guest not independent")
	}
	boots := []string{rawBoot, sessionBoot, newRawBoot, newSessionBoot, liveBoot}
	seenBoot := map[string]bool{}
	for _, boot := range boots {
		if !switchUUID(boot) || seenBoot[boot] {
			return nil, errors.New("five independent real guest boots required")
		}
		seenBoot[boot] = true
	}
	if e = budgetDestroyed(ctx, api, bound.Current); e != nil {
		return nil, e
	}
	if e = api.revoke(ctx, newSession); e != nil {
		return nil, e
	}
	if e = budgetDestroyed(ctx, api, newSession.Current); e != nil {
		return nil, e
	}
	if e = api.call(ctx, "DELETE", switchPath(newRaw.Ref), "", generationBody(newRaw.Ref), nil, 202); e != nil {
		return nil, e
	}
	if e = budgetDestroyed(ctx, api, newRaw.Ref); e != nil {
		return nil, e
	}
	if e = operatorIdle(ctx, c, 1, 5); e != nil {
		return nil, e
	}
	owner, ownerBytes, e := budgetOwner(switched.Current)
	if e != nil {
		return nil, e
	}
	fs, e := openQuotaFS(false)
	if e != nil {
		return nil, e
	}
	defer fs.file.Close()
	if e = fs.sync(); e != nil {
		return nil, e
	}
	if e = unix.Syncfs(int(fs.file.Fd())); e != nil {
		return nil, e
	}
	for project := driverProjectFirst; project < driverProjectFirst+4; project++ {
		if project == owner.ProjectID {
			continue
		}
		q, e := driverQuotaRead(project)
		if e != nil || !quotaEmpty(q) {
			return nil, errors.New("non-live operator project retained")
		}
	}
	qr, e := driverQuotaRead(owner.ProjectID)
	if e != nil {
		return nil, e
	}
	jail := "/srv/r/j/firecracker/" + switched.Current.ID + switched.Current.Generation
	blocks, inodes, entries, e := driverQuotaTree(jail, false)
	if e != nil {
		return nil, e
	}
	lastDrain, e := operatorCommand(resumed.Control.Committed)
	if e != nil {
		return nil, e
	}
	expected := nodecontrol.State{Version: 1, Epoch: lastDrain.Epoch, Revision: lastDrain.ExpectedRevision + 1, Mode: nodecontrol.ModeDrained, LastRequestID: lastDrain.RequestID, LastExpectedRevision: lastDrain.ExpectedRevision}
	saved := operatorCheckpoint{Version: 1, Phase: "node-operator-ack-drained", L1Boot: n.boot, Committed: expected, LastDrain: lastDrain, StaleResume: resume, Session: switched, SessionKey: sessionKey, RawKey: rawKey, RejectedRawKey: rejectedRaw, RejectedSessionKey: rejectedSession, AllRefs: []sandbox.Ref{raw.Ref, bound.Current, newRaw.Ref, newSession.Current, switched.Current}, Owner: ownerBytes, Quota: driverQuotaReceipt{Phase: "running", Jail: jail, Project: owner.ProjectID, Record: qr, NamespaceBlocks: blocks, NamespaceInodes: inodes, Entries: entries}, L2Boot: liveBoot, L2Boots: boots}
	if e = validateDriverQuotaAccounting(saved.Quota, qr, blocks, inodes, entries); e != nil {
		return nil, e
	}
	saved.Config, e = fileHash("/srv/config/backend.json")
	if e != nil {
		return nil, e
	}
	// Commit the receipt BEFORE the final operator ACK; no observer Syncfs, quota
	// sync, receipt write or catalog operation follows that ACK before outer cut.
	if e = privateWrite(operatorReceiptPath, saved); e != nil {
		return nil, e
	}
	final, e := c.Change(ctx, nodecontrol.ModeDrained, lastDrain)
	if e != nil || final.Control.Committed != expected || final.Control.AdmissionOpen {
		return nil, errors.New("final acknowledged drain missing")
	}
	onDisk, e := operatorState()
	if e != nil || onDisk != expected {
		return nil, errors.New("final committed state mismatch")
	}
	return map[string]any{"real_nested_kvm": true, "schema3_exact_node_policy": true, "same_uid_operator_roundtrip_and_foreign_uid_kernel_refused_after_actual_connect": true, "foreign_probe_before_any_guest_dac_restored_child_reaped": true, "raw_and_session_independent_kvm_uid_boot_workspace_checked": true, "new_raw_session_switch503_no_ledger_or_session_history": true, "exact_accepted_replays_continue_while_drained": true, "accepted_busy_raw_progress_and_existing_session_exec_continue": true, "stop_and_private_reclaim_continue_while_drained": true, "stale_resume_conflict_and_rejected_keys_reusable_after_resume": true, "five_real_generations_one_live_before_acknowledged_drained_cut": true, "receipt_fsynced_before_final_ack_no_observer_sync_after": true, "stop_execution_domain_observed_ms": stopMS, "private_reclaim_observed_ms": reclaimMS, "operator_filesystem_fault_or_physical_media_failure_claim": false, "production_slo_claim": false}, nil
}

func validateOperatorCheckpoint(s operatorCheckpoint, boot string) error {
	if s.Version != 1 || s.Phase != "node-operator-ack-drained" || !switchUUID(s.L1Boot) || s.L1Boot == boot || !switchUUID(s.L2Boot) || !hashPattern.MatchString(s.Config) || !hex32Pattern(s.Session.ID) || s.Session.Revision != 2 || !switchRefValid(s.Session.Current) || !switchRefValid(s.Session.Previous) || len(s.AllRefs) != 5 || len(s.L2Boots) != 5 {
		return errors.New("operator cold receipt identity invalid")
	}
	seenBoot := map[string]bool{}
	for _, boot := range s.L2Boots {
		if !switchUUID(boot) || seenBoot[boot] {
			return errors.New("duplicate/invalid operator guest boot")
		}
		seenBoot[boot] = true
	}
	if s.L2Boot != s.L2Boots[4] {
		return errors.New("operator live guest boot mismatch")
	}
	seen := map[sandbox.Ref]bool{}
	for _, ref := range s.AllRefs {
		if !switchRefValid(ref) || seen[ref] {
			return errors.New("operator receipt generations invalid")
		}
		seen[ref] = true
	}
	if s.AllRefs[4] != s.Session.Current || s.AllRefs[1] != s.Session.Previous {
		return errors.New("operator receipt route mismatch")
	}
	for _, key := range []string{s.SessionKey, s.RawKey, s.RejectedRawKey, s.RejectedSessionKey} {
		if !hashPattern.MatchString(key) {
			return errors.New("invalid private replay key")
		}
	}
	expected := nodecontrol.State{Version: 1, Epoch: s.LastDrain.Epoch, Revision: 6, Mode: nodecontrol.ModeDrained, LastRequestID: s.LastDrain.RequestID, LastExpectedRevision: 5}
	if !s.LastDrain.Valid() || s.LastDrain.ExpectedRevision != 5 || s.Committed != expected || !s.StaleResume.Valid() || s.StaleResume.Epoch != expected.Epoch || s.StaleResume.ExpectedRevision != 4 || s.StaleResume.RequestID == s.LastDrain.RequestID {
		return errors.New("operator cold committed command mismatch")
	}
	return nil
}
func (n *node) nodeOperatorRecover(ctx context.Context) (map[string]any, error) {
	if e := n.operatorProfile(); e != nil {
		return nil, e
	}
	b, e := privatefile.Read(operatorReceiptPath, 32768)
	if e != nil {
		return nil, e
	}
	var saved operatorCheckpoint
	if e = strictjson.Decode(b, &saved); e != nil {
		return nil, e
	}
	if e = validateOperatorCheckpoint(saved, n.boot); e != nil {
		return nil, e
	}
	h, e := fileHash("/srv/config/backend.json")
	if e != nil || h != saved.Config {
		return nil, errors.New("operator node policy retargeted")
	}
	onDisk, e := operatorState()
	if e != nil || onDisk != saved.Committed {
		return nil, errors.New("acknowledged drain not durable before daemon")
	}
	owner, raw, e := budgetOwner(saved.Session.Current)
	if e != nil || !bytes.Equal(raw, saved.Owner) || saved.Quota.Project != owner.ProjectID || saved.Quota.Phase != "running" || saved.Quota.Snapshot || saved.Quota.Jail != "/srv/r/j/firecracker/"+saved.Session.Current.ID+saved.Session.Current.Generation {
		return nil, errors.New("operator live owner/quota binding changed")
	}
	for _, ref := range saved.AllRefs {
		if _, e = os.Lstat(nodeBudgetInstances + "/" + ref.ID + ref.Generation); !os.IsNotExist(e) {
			return nil, errors.New("old execution survived own L1 cut")
		}
	}
	qr, e := driverQuotaRead(owner.ProjectID)
	if e != nil {
		return nil, e
	}
	blocks, inodes, entries, e := driverQuotaTree(saved.Quota.Jail, false)
	if e != nil {
		return nil, e
	}
	if e = validateDriverQuotaAccounting(saved.Quota, qr, blocks, inodes, entries); e != nil {
		return nil, e
	}
	if e = n.start(ctx); e != nil {
		return nil, e
	}
	c, e := nodecontrol.NewClient("/srv/state")
	if e != nil {
		return nil, e
	}
	defer c.Close()
	view, e := c.Status(ctx)
	if e != nil || view.Control.Committed != saved.Committed || view.Control.AdmissionOpen || view.Control.Phase != "ready" {
		return nil, errors.New("cold daemon reopened drained node")
	}
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	defer api.close()
	if e = api.call(ctx, "GET", "/readyz", "", nil, nil, 503); e != nil {
		return nil, e
	}
	for _, ref := range saved.AllRefs {
		if e = budgetDestroyed(ctx, api, ref); e != nil {
			return nil, e
		}
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	if e = operatorIdle(ctx, c, 0, 5); e != nil {
		return nil, e
	}
	for _, key := range []string{saved.RawKey, saved.RejectedRawKey} {
		if e = api.call(ctx, "POST", "/v1/sandboxes", key, nodeSpec(), nil, 410); e != nil {
			return nil, e
		}
	}
	for _, key := range []string{saved.SessionKey, saved.RejectedSessionKey} {
		if e = api.call(ctx, "POST", "/v1/sessions", key, nodeSpec(), nil, 410); e != nil {
			return nil, e
		}
	}
	var route struct {
		Has   bool   `json:"has_binding"`
		Phase string `json:"phase"`
	}
	if e = api.call(ctx, "GET", "/v1/sessions/"+saved.Session.ID, "", nil, &route, 200); e != nil || route.Has || route.Phase != "CLOSED" {
		return nil, errors.New("old session route resurrected")
	}
	freshKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	if e = operatorDenied(ctx, api, "/v1/sandboxes", freshKey, nodeSpec()); e != nil {
		return nil, e
	}
	exact, e := c.Change(ctx, nodecontrol.ModeDrained, saved.LastDrain)
	if e != nil || exact.Control.Committed != saved.Committed || exact.Control.AdmissionOpen {
		return nil, errors.New("cold last-command replay failed")
	}
	if e = operatorConflict(ctx, c, saved.StaleResume); e != nil {
		return nil, e
	}
	resume, e := operatorCommand(saved.Committed)
	if e != nil {
		return nil, e
	}
	resumed, e := c.Change(ctx, nodecontrol.ModeOpen, resume)
	if e != nil || !resumed.Control.AdmissionOpen {
		return nil, errors.New("cold explicit resume failed")
	}
	fresh, e := api.create(ctx, freshKey)
	if e != nil {
		return nil, e
	}
	boot, e := operatorGuest(ctx, n, api, fresh.Ref, "cold", nil)
	if e != nil {
		return nil, e
	}
	for _, oldBoot := range saved.L2Boots {
		if boot == oldBoot {
			return nil, errors.New("fresh cold guest reused assigned boot")
		}
	}
	if e = api.call(ctx, "DELETE", switchPath(fresh.Ref), "", generationBody(fresh.Ref), nil, 202); e != nil {
		return nil, e
	}
	if e = budgetDestroyed(ctx, api, fresh.Ref); e != nil {
		return nil, e
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	if e = operatorIdle(ctx, c, 0, 6); e != nil {
		return nil, e
	}
	if e = n.process.Process.Signal(os.Interrupt); e != nil {
		return nil, e
	}
	select {
	case e = <-n.exited:
		if e != nil {
			return nil, e
		}
		n.process = nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	for _, p := range []string{nodeBudgetInstances, nodeGroup + "/control", nodeGroup} {
		if e = os.Remove(p); e != nil {
			return nil, e
		}
	}
	return map[string]any{"l1_boot_changed_same_disk_ack_drained_state_checked_before_daemon": true, "exact_node_policy_live_owner_quota_namespace_before_recovery": true, "ordinary_recovery_keeps_admission_closed_and_destroys_all_old_generations": true, "old_raw_session_keys410_old_session_route_closed": true, "cold_new_create503_last_command_replay_stale_resume_conflict": true, "explicit_resume_fresh_real_guest_uid_boot_clean_workspace": true, "all_four_projects_zero_pools_idle_controller_reaped_node_subtree_removed": true, "no_assigned_guest_restore_or_metadata_repair": true}, nil
}
