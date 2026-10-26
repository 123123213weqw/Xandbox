//go:build linux && xandbox_host_fixture

package main

// TEST ONLY. Pressure is confined to one existing owned L1 VM cgroup, with
// unchanged production limits. This is not a guest-origin or whole-node OOM.
import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

const nodeOOMAllocation = 1 << 30
const nodeOOMGuestBytes = 96 << 20

type nodeOOMEvents struct {
	Max, OOM, Kills, Groups uint64
}

// Private failure diagnostics only; no embedding/promoted io.Copy fast path.
type nodeOOMCapture struct{ data []byte }

func (b *nodeOOMCapture) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := 4096 - len(b.data); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}

// All kernel reads have a bound and reject truncation, duplicate keys, signed
// values and overflow. Counters are observations, never defaults on read error.
func nodeOOMRows(b []byte) (map[string]uint64, error) {
	if len(b) == 0 || len(b) > 16384 || b[len(b)-1] != '\n' {
		return nil, errors.New("incomplete bounded kernel counters")
	}
	out := map[string]uint64{}
	for _, line := range strings.Split(string(b[:len(b)-1]), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || len(f[0]) > 64 || len(f[1]) > 20 {
			return nil, errors.New("invalid kernel counter row")
		}
		if _, exists := out[f[0]]; exists {
			return nil, errors.New("duplicate kernel counter")
		}
		v, e := strconv.ParseUint(f[1], 10, 64)
		if e != nil || strconv.FormatUint(v, 10) != f[1] {
			return nil, errors.New("noncanonical kernel counter")
		}
		out[f[0]] = v
	}
	return out, nil
}

func nodeOOMRead(f *os.File) ([]byte, error) {
	b := make([]byte, 16385)
	n, e := f.ReadAt(b, 0)
	if e != nil && !errors.Is(e, io.EOF) {
		return nil, e
	}
	if n == 0 || n > 16384 {
		return nil, errors.New("kernel read outside bound")
	}
	return b[:n], nil
}

func nodeOOMReadRows(f *os.File) (map[string]uint64, error) {
	b, e := nodeOOMRead(f)
	if e != nil {
		return nil, e
	}
	return nodeOOMRows(b)
}

func nodeOOMReadEvents(f *os.File) (nodeOOMEvents, error) {
	m, e := nodeOOMReadRows(f)
	if e != nil {
		return nodeOOMEvents{}, e
	}
	for _, k := range []string{"low", "high", "max", "oom", "oom_kill", "oom_group_kill"} {
		if _, ok := m[k]; !ok {
			return nodeOOMEvents{}, errors.New("missing actual memory event")
		}
	}
	return nodeOOMEvents{m["max"], m["oom"], m["oom_kill"], m["oom_group_kill"]}, nil
}

func (a nodeOOMEvents) delta(b nodeOOMEvents) (nodeOOMEvents, error) {
	if a.Max < b.Max || a.OOM < b.OOM || a.Kills < b.Kills || a.Groups < b.Groups {
		return nodeOOMEvents{}, errors.New("kernel OOM counter decreased")
	}
	return nodeOOMEvents{a.Max - b.Max, a.OOM - b.OOM, a.Kills - b.Kills, a.Groups - b.Groups}, nil
}

func nodeOOMMember(b []byte) (string, error) {
	const prefix = "0::/xandbox/instances/"
	s := string(b)
	if !strings.HasPrefix(s, prefix) || !strings.HasSuffix(s, "\n") {
		return "", errors.New("pressure child outside fixed VM subtree")
	}
	id := strings.TrimSuffix(strings.TrimPrefix(s, prefix), "\n")
	if !hashPattern.MatchString(id) {
		return "", errors.New("pressure requires exact existing generation")
	}
	return nodeBudgetInstances + "/" + id, nil
}

func nodeOOMStatus(b []byte, uid uint32) error {
	if uid < 400000 || uid >= 400004 || len(b) > 16384 {
		return errors.New("fixed pressure UID required")
	}
	seen := map[string]bool{}
	want := strconv.FormatUint(uint64(uid), 10)
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "Uid:", "Gid:":
			if seen[f[0]] || len(f) != 5 || strings.Join(f[1:], " ") != strings.Join([]string{want, want, want, want}, " ") {
				return errors.New("pressure credential mismatch")
			}
		case "Groups:":
			if seen[f[0]] || len(f) != 1 {
				return errors.New("pressure supplemental groups")
			}
		case "CapEff:", "CapPrm:", "CapInh:", "CapAmb:", "CapBnd:":
			if seen[f[0]] || len(f) != 2 || f[1] != "0000000000000000" {
				return errors.New("pressure capabilities retained")
			}
		case "NoNewPrivs:":
			if seen[f[0]] || len(f) != 2 || f[1] != "1" {
				return errors.New("pressure NNP missing")
			}
		default:
			continue
		}
		seen[f[0]] = true
	}
	if len(seen) != 9 {
		return errors.New("missing pressure privilege observation")
	}
	return nil
}

func nodeOOMChildStatus(pid int, uid uint32, group string) error {
	tasks, e := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if e != nil || len(tasks) == 0 || len(tasks) > 64 {
		return errors.New("bounded actual pressure threads required")
	}
	for _, task := range tasks {
		base := fmt.Sprintf("/proc/%d/task/%s/", pid, task.Name())
		b, e := os.ReadFile(base + "status")
		if os.IsNotExist(e) { // A completed runtime thread cannot consume memory.
			continue
		}
		if e != nil || nodeOOMStatus(b, uid) != nil {
			return errors.New("actual pressure thread privilege mismatch")
		}
		b, e = os.ReadFile(base + "cgroup")
		g, parseErr := nodeOOMMember(b)
		if e != nil || parseErr != nil || g != group {
			return errors.New("actual pressure thread cgroup mismatch")
		}
	}
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/oom_score_adj", pid))
	if e != nil || string(b) != "0\n" {
		return errors.New("pressure worker OOM immunity changed")
	}
	return nil
}

func nodeOOMLimits(group string) error {
	for name, want := range map[string]string{"memory.max": "805306368\n", "memory.swap.max": "0\n", "memory.oom.group": "1\n"} {
		b, e := os.ReadFile(group + "/" + name)
		if e != nil || string(b) != want {
			return errors.New("existing per-VM memory policy changed")
		}
	}
	return nil
}

// No user-chosen path/PID/UID/size. Fixed FDs are provided only by our L1 PID1.
// All L0/root/marker checks occur before privilege changes or any large mapping.
func runNodeOOMPressure() error {
	if e := requireQuotaChild(); e != nil {
		return e
	}
	b, e := os.ReadFile("/proc/self/cgroup")
	group, parseErr := nodeOOMMember(b)
	if e != nil || parseErr != nil {
		return errors.New("pressure must be born into existing owned VM cgroup")
	}
	var marker, actual, cg, actualCG unix.Stat_t
	if unix.Fstat(3, &marker) != nil || unix.Lstat("/etc/xandbox-host-fixture", &actual) != nil || marker.Dev != actual.Dev || marker.Ino != actual.Ino || marker.Mode != unix.S_IFREG|0600 || marker.Uid != 0 || marker.Gid != 0 || marker.Nlink != 1 {
		return errors.New("fixed held fixture marker required")
	}
	if unix.Fstat(4, &cg) != nil || unix.Lstat(group, &actualCG) != nil || cg.Dev != actualCG.Dev || cg.Ino != actualCG.Ino || cg.Mode != unix.S_IFDIR|0700 || cg.Uid != 0 || cg.Gid != 0 {
		return errors.New("same held owned cgroup inode required")
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(4, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return errors.New("pressure requires real cgroup2")
	}
	if e = nodeOOMLimits(group); e != nil {
		return e
	}
	name := filepath.Base(group)
	owner, _, e := budgetOwnerChild(sandbox.Ref{ID: name[:32], Generation: name[32:]})
	if e != nil {
		return e
	}
	for _, fd := range []int{5, 6} {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
			return errors.New("fixed pressure handshake pipes required")
		}
	}
	last, e := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	n, parseErr := strconv.Atoi(strings.TrimSpace(string(last)))
	if e != nil || parseErr != nil || n < 40 || n > 63 {
		return errors.New("bounded kernel capability set required")
	}
	for cap := 0; cap <= n; cap++ {
		if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, uintptr(cap), 0); errno != 0 {
			return errno
		}
	}
	if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return errno
	}
	if e = syscall.Setgroups([]int{}); e != nil {
		return e
	}
	uid := int(owner.UID)
	if e = syscall.Setresgid(uid, uid, uid); e != nil {
		return e
	}
	if e = syscall.Setresuid(uid, uid, uid); e != nil {
		return e
	}
	if e = nodeOOMChildStatus(os.Getpid(), uint32(uid), group); e != nil {
		return e
	}
	unix.Close(3)
	unix.Close(4)
	ready, release := os.NewFile(5, "pressure-ready"), os.NewFile(6, "pressure-release")
	if _, e = io.WriteString(ready, "pressure-ready-v1\n"); e != nil {
		return e
	}
	ready.Close()
	b, e = io.ReadAll(io.LimitReader(release, 9))
	release.Close()
	if e != nil || string(b) != "start-v1" {
		return errors.New("fixed pressure release required")
	}
	mem, e := unix.Mmap(-1, 0, nodeOOMAllocation, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if e != nil {
		return e // ENOMEM is NOT a successful kernel OOM-kill observation.
	}
	defer unix.Munmap(mem)
	if e = unix.Madvise(mem, unix.MADV_NOHUGEPAGE); e != nil {
		return e
	}
	for i := 0; i < len(mem); i += 4096 {
		mem[i] = 0xa5
	}
	runtime.KeepAlive(mem)
	return errors.New("pressure unexpectedly survived resident allocation above unchanged limit")
}

// Child guard differs only in PID; it cannot use budgetOwner's PID1 guard.
func budgetOwnerChild(ref sandbox.Ref) (clearWindowOwner, []byte, error) {
	if e := requireQuotaChild(); e != nil {
		return clearWindowOwner{}, nil, e
	}
	return readBudgetOwner(ref)
}

func nodeOOMOpen(path string) (*os.File, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	return os.Open(path)
}

// Includes absence/ENODEV only when this exact previously bound group is gone.
func nodeOOMEmpty(group string) (bool, error) {
	if e := requireNode(); e != nil {
		return false, e
	}
	f, e := os.Open(group + "/cgroup.events")
	if os.IsNotExist(e) {
		return true, nil
	}
	if e != nil {
		return false, e
	}
	defer f.Close()
	m, e := nodeOOMReadRows(f)
	if errors.Is(e, unix.ENODEV) {
		if _, statErr := os.Stat(group); os.IsNotExist(statErr) {
			return true, nil
		}
	}
	if e != nil {
		return false, e
	}
	v, ok := m["populated"]
	if !ok || v > 1 {
		return false, errors.New("actual populated counter required")
	}
	return v == 0, nil
}

func nodeOOMStop(ctx context.Context, api *switchAPI, ref sandbox.Ref) error {
	if !switchRefValid(ref) {
		return errors.New("exact neighbor generation required for Stop")
	}
	var stopped sandbox.Record
	// Ordinary Stop is synchronous HTTP200; only DELETE is acceptance-only202.
	// The subsequent kernel-domain observation is still separately required.
	if e := api.call(ctx, "POST", switchPath(ref)+"/stop", "", generationBody(ref), &stopped, 200); e != nil {
		return e
	}
	if stopped.Ref != ref || stopped.State != sandbox.Stopped || stopped.StoppedAt.IsZero() || !stopped.DestroyedAt.IsZero() {
		return errors.New("ordinary Stop lacks exact durable STOPPED reply")
	}
	return nil
}

func (n *node) nodeOOMCheckpoint(ctx context.Context) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.nodeBudget || n.nodeSnapshot || !n.quotaDriver || n.process != nil {
		return nil, errors.New("fresh fixed no-snapshot node budget required")
	}
	if _, e := fixedBudgetConfig(); e != nil {
		return nil, e
	}
	if e := n.start(ctx); e != nil {
		return nil, e
	}
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	defer api.close()
	var refs []sandbox.Ref
	var owners []clearWindowOwner
	var keys, boots []string
	var groups []string
	var beforeAnon []uint64
	var eventFiles []*os.File
	defer func() {
		for _, f := range eventFiles {
			f.Close()
		}
	}()
	readAnon := func(group string) (uint64, error) {
		f, e := nodeOOMOpen(group + "/memory.stat")
		if e != nil {
			return 0, e
		}
		defer f.Close()
		m, e := nodeOOMReadRows(f)
		v, ok := m["anon"]
		if e != nil || !ok {
			return 0, errors.New("actual anonymous resident counter required")
		}
		return v, nil
	}
	for i := 0; i < 4; i++ {
		key, e := randomKey()
		if e != nil {
			return nil, e
		}
		r, e := api.create(ctx, key)
		if e != nil {
			return nil, e
		}
		if e = budgetVM(r.Ref); e != nil {
			return nil, e
		}
		out, e := api.executeVM(ctx, r.Ref, []string{"sh", "-c", "set -e; test ! -e budget-marker; printf oom > budget-marker; id -u; cat /proc/sys/kernel/random/boot_id"})
		if e != nil {
			return nil, e
		}
		boot, e := switchGuestIdentity(out)
		if e != nil {
			return nil, e
		}
		o, _, e := budgetOwner(r.Ref)
		if e != nil {
			return nil, e
		}
		for j, old := range owners {
			if old.UID == o.UID || boots[j] == boot || refs[j] == r.Ref {
				return nil, errors.New("independent live guest UID/ref/boot required")
			}
		}
		group := nodeBudgetInstances + "/" + r.ID + r.Generation
		if e = nodeOOMLimits(group); e != nil {
			return nil, e
		}
		anon, e := readAnon(group)
		if e != nil {
			return nil, e
		}
		f, e := nodeOOMOpen(group + "/memory.events")
		if e != nil {
			return nil, e
		}
		refs, owners, keys, boots, groups = append(refs, r.Ref), append(owners, o), append(keys, key), append(boots, boot), append(groups, group)
		beforeAnon, eventFiles = append(beforeAnon, anon), append(eventFiles, f)
	}
	key, e := randomKey()
	if e != nil {
		return nil, e
	}
	if e = api.call(ctx, "POST", "/v1/sandboxes", key, nodeSpec(), nil, 503); e != nil {
		return nil, e
	}
	var jobs []sandbox.Job
	var deadlines []time.Time
	var anonDeltas []uint64
	for i, ref := range refs {
		deadline := time.Now().Add(60 * time.Second)
		var j sandbox.Job
		// Distinct 1KiB values prevent a string alias-only allocation. This is a
		// fixed ordinary guest workload, not a host shell or pressure hook.
		argv := []string{"awk", "BEGIN { for (i=0;i<98304;i++) a[i]=sprintf(\"%01024d\",i); system(\"printf ready > oom-ready\"); while (1) { k++; if (k==1000000) k=0 } }"}
		if e = api.call(ctx, "POST", switchPath(ref)+"/exec", "", sandbox.ExecRequest{Generation: ref.Generation, Argv: argv, TimeoutMS: 60000}, &j, 202); e != nil {
			return nil, e
		}
		j.Ref = ref
		if _, e = api.executeVM(ctx, ref, []string{"sh", "-c", "set -e; i=0; while [ ! -s oom-ready ]; do i=$((i+1)); test $i -le 200; sleep 0.05; done"}); e != nil {
			return nil, e
		}
		if j, e = api.job(ctx, ref, j); e != nil || j.Status != "RUNNING" || !time.Now().Before(deadline) {
			return nil, errors.New("resident guest workload not running before timeout")
		}
		var current uint64
		if e = waitNode(ctx, func() (bool, error) {
			var err error
			current, err = readAnon(groups[i])
			return err == nil && current >= beforeAnon[i] && current-beforeAnon[i] >= 64<<20, err
		}); e != nil {
			return nil, e
		}
		jobs, deadlines, anonDeltas = append(jobs, j), append(deadlines, deadline), append(anonDeltas, current-beforeAnon[i])
	}
	baseline := make([]nodeOOMEvents, 4)
	for i, f := range eventFiles {
		if baseline[i], e = nodeOOMReadEvents(f); e != nil {
			return nil, e
		}
	}
	// Hierarchical totals bind all kills to the target. Local ancestor counters
	// reject an ancestor OOM even if it happens to select our target as victim.
	scopePaths := []string{nodeGroup + "/memory.events", nodeGroup + "/memory.events.local", nodeBudgetInstances + "/memory.events.local", nodeGroup + "/control/memory.events"}
	var scopeFiles []*os.File
	defer func() {
		for _, f := range scopeFiles {
			f.Close()
		}
	}()
	var scopeBefore []nodeOOMEvents
	for _, path := range scopePaths {
		f, err := nodeOOMOpen(path)
		if err != nil {
			return nil, err
		}
		scopeFiles = append(scopeFiles, f)
		v, err := nodeOOMReadEvents(f)
		if err != nil {
			return nil, err
		}
		scopeBefore = append(scopeBefore, v)
	}
	vmstat, e := nodeOOMOpen("/proc/vmstat")
	if e != nil {
		return nil, e
	}
	defer vmstat.Close()
	vmBefore, e := nodeOOMReadRows(vmstat)
	if _, ok := vmBefore["oom_kill"]; e != nil || !ok {
		return nil, errors.New("actual L1 global OOM counter required")
	}
	marker, e := nodeOOMOpen("/etc/xandbox-host-fixture")
	if e != nil {
		return nil, e
	}
	defer marker.Close()
	cg, e := nodeOOMOpen(groups[0])
	if e != nil {
		return nil, e
	}
	defer cg.Close()
	readyR, readyW, e := os.Pipe()
	if e != nil {
		return nil, e
	}
	defer readyR.Close()
	defer readyW.Close()
	releaseR, releaseW, e := os.Pipe()
	if e != nil {
		return nil, e
	}
	defer releaseR.Close()
	defer releaseW.Close()
	guard, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(guard, "/usr/bin/xandbox-host-fixture", "-mode", "node-oom-pressure")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.ExtraFiles = []*os.File{marker, cg, readyW, releaseR}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd()), Pdeathsig: syscall.SIGKILL}
	var privateDiagnostic nodeOOMCapture
	cmd.Stdout, cmd.Stderr = io.Discard, &privateDiagnostic
	if e = cmd.Start(); e != nil {
		return nil, e
	}
	waited := false
	defer func() {
		if !waited {
			cancel()
			cmd.Wait()
		}
		if len(privateDiagnostic.data) != 0 {
			fmt.Fprintln(os.Stderr, "private bounded OOM helper diagnostic:", string(privateDiagnostic.data))
		}
	}() // failure cleanup never counts as OOM.
	readyW.Close()
	releaseR.Close()
	if e = readyR.SetReadDeadline(time.Now().Add(5 * time.Second)); e != nil {
		return nil, e
	}
	b, e := io.ReadAll(io.LimitReader(readyR, 19))
	if e != nil || string(b) != "pressure-ready-v1\n" {
		return nil, errors.New("pressure child never reached verified ready state")
	}
	if e = nodeOOMChildStatus(cmd.Process.Pid, uint32(owners[0].UID), groups[0]); e != nil {
		return nil, e
	}
	if e = nodeOOMLimits(groups[0]); e != nil {
		return nil, e
	}
	targetObserved := make(chan nodeOOMEvents, 1)
	observeCtx, stopObserve := context.WithCancel(guard)
	defer stopObserve()
	observeErr := make(chan error, 1)
	observeDone := make(chan struct{})
	defer func() { stopObserve(); <-observeDone }()
	go func() {
		defer close(observeDone)
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		for {
			now, err := nodeOOMReadEvents(eventFiles[0])
			if err != nil {
				observeErr <- err
				return
			}
			delta, err := now.delta(baseline[0])
			if err != nil {
				observeErr <- err
				return
			}
			if delta.Max > 0 && delta.OOM > 0 && delta.Kills > 0 && delta.Groups > 0 {
				targetObserved <- delta
				return
			}
			select {
			case <-observeCtx.Done():
				observeErr <- observeCtx.Err()
				return
			case <-tick.C:
			}
		}
	}()
	for i, ref := range refs {
		j, err := api.job(ctx, ref, jobs[i])
		if err != nil || j.Status != "RUNNING" || !time.Now().Before(deadlines[i]) {
			return nil, errors.New("all four guest tasks must still be busy at pressure release")
		}
	}
	started := time.Now()
	if _, e = io.WriteString(releaseW, "start-v1"); e != nil {
		return nil, e
	}
	releaseW.Close()
	e = cmd.Wait()
	waited = true
	exit, ok := e.(*exec.ExitError)
	if !ok || guard.Err() != nil || !exit.ProcessState.Sys().(syscall.WaitStatus).Signaled() || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		return nil, errors.New("actual kernel-killed pressure child required before fixed guard")
	}
	var target nodeOOMEvents
	select {
	case target = <-targetObserved:
	case err := <-observeErr:
		return nil, fmt.Errorf("actual target OOM evidence missing: %w", err)
	case <-guard.Done():
		return nil, errors.New("OOM event observation timed out")
	}
	if e = waitNode(guard, func() (bool, error) { return nodeOOMEmpty(groups[0]) }); e != nil {
		return nil, e
	}
	if e = waitNode(guard, func() (bool, error) {
		j, err := api.job(guard, refs[0], jobs[0])
		if err != nil {
			return false, err
		}
		if j.Status == "RUNNING" {
			return false, nil
		}
		if (j.Status != "FAILED" && j.Status != "CANCELLED") || j.FinishedAt.IsZero() {
			return false, errors.New("OOM job falsely succeeded or naturally timed out")
		}
		return true, nil
	}); e != nil {
		return nil, e
	}
	if !time.Now().Before(deadlines[0]) {
		return nil, errors.New("OOM target stopped after original guest timeout")
	}
	oomStopMS := float64(time.Since(started)) / float64(time.Millisecond)
	for _, group := range groups[1:] {
		if e = nodeOOMLimits(group); e != nil {
			return nil, e
		}
	}
	for i := 1; i < 4; i++ {
		now, err := nodeOOMReadEvents(eventFiles[i])
		if err != nil {
			return nil, err
		}
		d, err := now.delta(baseline[i])
		if err != nil || d.OOM != 0 || d.Kills != 0 || d.Groups != 0 {
			return nil, errors.New("neighbor OOM observed")
		}
		if _, e = api.executeVM(ctx, refs[i], []string{"true"}); e != nil {
			return nil, e
		}
		j, err := api.job(ctx, refs[i], jobs[i])
		if err != nil || j.Status != "RUNNING" || !time.Now().Before(deadlines[i]) {
			return nil, errors.New("neighbor did not survive target OOM while still busy")
		}
	}
	var hierarchy nodeOOMEvents
	for i, f := range scopeFiles {
		now, err := nodeOOMReadEvents(f)
		if err != nil {
			return nil, err
		}
		d, err := now.delta(scopeBefore[i])
		if err != nil {
			return nil, err
		}
		if i == 0 {
			hierarchy = d
			if d.OOM < target.OOM || d.Kills < target.Kills || d.Groups != target.Groups {
				return nil, errors.New("target/hierarchical OOM scope mismatch")
			}
		} else if d.OOM != 0 || d.Kills != 0 || d.Groups != 0 {
			return nil, errors.New("ancestor or controller OOM observed")
		}
	}
	vmAfter, e := nodeOOMReadRows(vmstat)
	if _, ok := vmAfter["oom_kill"]; e != nil || !ok || vmAfter["oom_kill"] < vmBefore["oom_kill"] || vmAfter["oom_kill"]-vmBefore["oom_kill"] != hierarchy.Kills {
		return nil, errors.New("global L1 OOM kill outside observed node subtree")
	}
	for path, want := range map[string]string{nodeGroup + "/memory.max": "7516192768\n", nodeGroup + "/control/memory.max": "1073741824\n"} {
		b, err := os.ReadFile(path)
		if err != nil || string(b) != want {
			return nil, errors.New("node/control memory policy changed during OOM")
		}
	}
	// Physical Stop and durable Destroyed/ownership/quota release are separate.
	stopStarted := time.Now()
	for i := 1; i < 4; i++ {
		if e = nodeOOMStop(ctx, api, refs[i]); e != nil {
			return nil, e
		}
	}
	for i := 1; i < 4; i++ {
		if e = waitNode(ctx, func() (bool, error) { return nodeOOMEmpty(groups[i]) }); e != nil {
			return nil, e
		}
		if !time.Now().Before(deadlines[i]) {
			return nil, errors.New("neighbor Stop fell past original guest timeout")
		}
	}
	stopMS := float64(time.Since(stopStarted)) / float64(time.Millisecond)
	for i, ref := range refs {
		if e = api.call(ctx, "DELETE", switchPath(ref), "", generationBody(ref), nil, 202); e != nil {
			return nil, e
		}
		if e = budgetDestroyed(ctx, api, ref); e != nil {
			return nil, e
		}
		q, err := driverQuotaRead(owners[i].ProjectID)
		if err != nil || !quotaEmpty(q) {
			return nil, errors.New("OOM/neighbor project not fully reclaimed")
		}
		if e = api.call(ctx, "POST", "/v1/sandboxes", keys[i], nodeSpec(), nil, 410); e != nil {
			return nil, e
		}
	}
	reclaimMS := float64(time.Since(stopStarted)) / float64(time.Millisecond)
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	if e = n.budgetFreshCheckpoint(ctx, api, boots, nodeOOMCheckpointPhase); e != nil {
		return nil, e
	}
	return map[string]any{
		"real_nested_kvm": true, "checkpoint_receipt_fsynced": true, "four_busy_guest_resident_anon_deltas_checked": true, "fifth_create503_before_pressure": true,
		"helper_born_in_exact_vm_group_privileges_dropped_and_parent_verified": true, "actual_target_kernel_oom_group_kill_and_sigkill_reap_before_guard": true,
		"target_domain_empty_independently_observed": true, "target_job_failed_without_natural_timeout": true, "ancestor_control_and_neighbor_oom_counters_unchanged": true, "three_neighbors_still_running_and_new_exec_succeeds_after_oom": true,
		"ordinary_stop_before_original_job_timeout": true, "all_four_destroyed_resources_absent_projects_zero_keys410": true, "fresh_capacity_clean_workspace_new_boot_and_synced_cold_checkpoint": true,
		"host_cgroup_test_pressure_not_guest_origin": true, "global_l1_oom_kills_equal_node_hierarchical_count": true, "production_slo_claim": false, "whole_node_saturation_claim": false,
		"fixed_helper_allocation_request_bytes": nodeOOMAllocation, "guest_workload_bytes_each": nodeOOMGuestBytes, "guest_host_anon_delta_bytes_each": anonDeltas,
		"target_observed_oom_events": target.OOM, "target_observed_oom_kills": target.Kills, "target_observed_oom_group_kills": target.Groups, "node_hierarchical_oom_kills": hierarchy.Kills, "l1_global_oom_kills": vmAfter["oom_kill"] - vmBefore["oom_kill"],
		"fixed_helper_guard_ms": 20000, "oom_release_to_target_empty_observed_ms": oomStopMS, "neighbor_stop_to_empty_observed_ms": stopMS, "neighbor_stop_to_all_private_reclaimed_observed_ms": reclaimMS,
	}, nil
}
