//go:build linux && xandbox_host_fixture

package main

// TEST ONLY. This census does not wait/reap, signal, trace, or move any task.
// In particular it must not consume an os/exec.Cmd.Wait child's exit status.
import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const nodeLoadProcLimit = 4096

// Only aggregate, closed fields enter the private diagnostic capsule. PID,
// PPID, comm, UID, cgroup path and start ticks are never serialized.
type nodeLoadCensus struct {
	Available             bool    `json:"available"`
	Complete              bool    `json:"complete"`
	Truncated             bool    `json:"truncated"`
	CaptureMS             float64 `json:"capture_ms"`
	Candidates            int     `json:"candidates"`
	Scanned               int     `json:"scanned"`
	Vanished              int     `json:"vanished"`
	ReadErrors            int     `json:"read_errors"`
	AdoptedZombies        int     `json:"adopted_zombies"`
	ManagedControllerDead bool    `json:"managed_controller_zombie"`
	VMM                   int     `json:"vmm_zombies"`
	Warden                int     `json:"warden_zombies"`
	Jailer                int     `json:"jailer_zombies"`
	Other                 int     `json:"other_zombies"`
	ReservedUID           int     `json:"reserved_uid_zombies"`
	NodeScoped            int     `json:"node_scoped_zombies"`
	DeletedScoped         int     `json:"deleted_scoped_zombies"`
	MembershipUnknown     int     `json:"membership_unknown_zombies"`
	NodePIDs              uint64  `json:"node_pids"`
	ControlPIDs           uint64  `json:"control_pids"`
}

type nodeLoadProcIdentity struct {
	comm   string
	state  byte
	parent int
	start  uint64
}

func nodeLoadParseProcStat(pid int, b []byte) (nodeLoadProcIdentity, error) {
	var zero nodeLoadProcIdentity
	prefix := strconv.Itoa(pid) + " ("
	s := strings.TrimSpace(string(b))
	end := strings.LastIndex(s, ") ")
	if pid <= 0 || len(b) > 8192 || !strings.HasPrefix(s, prefix) || end < len(prefix) {
		return zero, errors.New("bounded exact proc identity required")
	}
	f := strings.Fields(s[end+2:])
	// Fields3..22 must exist. A comm containing spaces or ')' is not a field
	// separator; neither its raw bytes nor arbitrary names leave this parser.
	if len(f) < 20 || len(f[0]) != 1 || !strings.ContainsRune("RSDZTtXxKWPIN", rune(f[0][0])) {
		return zero, errors.New("invalid proc state")
	}
	parent, e := strconv.Atoi(f[1])
	if e != nil || parent < 0 {
		return zero, errors.New("invalid proc parent")
	}
	start, e := strconv.ParseUint(f[19], 10, 64)
	if e != nil {
		return zero, errors.New("invalid proc start ticks")
	}
	return nodeLoadProcIdentity{s[len(prefix):end], f[0][0], parent, start}, nil
}

func nodeLoadProcEUID(b []byte) (uint64, error) {
	if len(b) > 8192 {
		return 0, errors.New("bounded proc status required")
	}
	var uid uint64
	found := false
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "Uid:" {
			continue
		}
		if found || len(f) != 5 {
			return 0, errors.New("ambiguous proc UID")
		}
		for i, field := range f[1:] {
			v, e := strconv.ParseUint(field, 10, 32)
			if e != nil {
				return 0, errors.New("invalid proc UID")
			}
			if i == 1 {
				uid = v
			}
		}
		found = true
	}
	if !found {
		return 0, errors.New("missing proc UID")
	}
	return uid, nil
}

func nodeLoadProcMembership(b []byte) (scoped, deleted, unknown bool) {
	if len(b) > 8192 || len(strings.Fields(string(b))) == 0 {
		return false, false, true
	}
	s := strings.TrimSpace(string(b))
	prefix := "0::" + strings.TrimPrefix(nodeBudgetInstances, "/sys/fs/cgroup") + "/"
	if strings.HasPrefix(s, prefix) {
		name := strings.TrimPrefix(s, prefix)
		deleted = strings.HasSuffix(name, " (deleted)")
		if deleted {
			name = strings.TrimSuffix(name, " (deleted)")
		}
		if hashPattern.MatchString(name) {
			return true, deleted, false
		}
	}
	// Empty/deleted proc membership need not retain a resolvable cgroup path.
	// A recognized foreign/root membership is not silently called our scope.
	return false, false, true
}

func nodeLoadProcRead(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 8193))
	if e == nil && len(b) > 8192 {
		e = errors.New("bounded proc file exceeded")
	}
	return b, e
}

func (n *node) nodeLoadPID1Census(ctx context.Context, identity string) (out nodeLoadCensus) {
	began := time.Now()
	defer func() { out.CaptureMS = switchMS(began) }()
	if requireNode() != nil || !n.nodeLoad || n.process == nil || n.process.Process == nil || ctx.Err() != nil {
		return out
	}
	controller := n.process.Process.Pid
	got, e := processStart(controller)
	if e != nil || got != identity {
		return out
	}
	cfg, e := fixedNodeLoadConfig()
	if e != nil {
		return out
	}
	out.Available = true
	dir, e := os.Open("/proc")
	if e != nil {
		out.ReadErrors++
		return out
	}
	names, e := dir.Readdirnames(nodeLoadProcLimit + 1)
	dir.Close()
	if (e != nil && e != io.EOF) || len(names) > nodeLoadProcLimit {
		out.Truncated = len(names) > nodeLoadProcLimit
		out.ReadErrors++
		return out
	}
	for _, name := range names {
		pid, e := strconv.Atoi(name)
		if e != nil || pid <= 0 || strconv.Itoa(pid) != name {
			continue
		}
		out.Candidates++
		if ctx.Err() != nil {
			return out
		}
		b, e := nodeLoadProcRead("/proc/" + name + "/stat")
		if os.IsNotExist(e) {
			out.Vanished++
			continue
		}
		p, parseErr := nodeLoadParseProcStat(pid, b)
		if e != nil || parseErr != nil {
			out.ReadErrors++
			continue
		}
		out.Scanned++
		if p.state != 'Z' || p.parent != 1 {
			continue
		}
		if pid == controller {
			out.ManagedControllerDead = true
			continue // Owned by os/exec.Cmd.Wait, not classified as adopted.
		}
		out.AdoptedZombies++
		switch p.comm {
		case "firecracker":
			out.VMM++
		case "xandbox-warden":
			out.Warden++
		case "jailer":
			out.Jailer++
		default:
			out.Other++
		}
		b, e = nodeLoadProcRead("/proc/" + name + "/status")
		uid, parseErr := nodeLoadProcEUID(b)
		if e != nil || parseErr != nil {
			out.ReadErrors++
		} else if uid >= uint64(cfg.UIDStart) && uid < uint64(cfg.UIDStart+cfg.UIDCount) {
			out.ReservedUID++
		}
		b, e = nodeLoadProcRead("/proc/" + name + "/cgroup")
		scoped, deleted, unknown := nodeLoadProcMembership(b)
		if e != nil {
			out.ReadErrors++
			scoped, deleted, unknown = false, false, true
		}
		if scoped {
			out.NodeScoped++
		}
		if deleted {
			out.DeletedScoped++
		}
		if unknown || e != nil {
			out.MembershipUnknown++
		}
	}
	for path, target := range map[string]*uint64{nodeGroup + "/pids.current": &out.NodePIDs, nodeGroup + "/control/pids.current": &out.ControlPIDs} {
		b, e := nodeLoadProcRead(path)
		v, parseErr := switchUint(string(b))
		if e != nil || parseErr != nil {
			out.ReadErrors++
		} else {
			*target = v
		}
	}
	got, e = processStart(controller)
	if e != nil || got != identity {
		out.Available = false
	}
	b, readErr := nodeLoadProcRead("/proc/" + strconv.Itoa(controller) + "/stat")
	last, parseErr := nodeLoadParseProcStat(controller, b)
	if readErr != nil || parseErr != nil {
		out.ReadErrors++
	} else {
		if strconv.FormatUint(last.start, 10) != identity {
			out.Available = false
		}
		if last.state == 'Z' || last.state == 'X' || last.state == 'x' {
			out.ManagedControllerDead = true
		}
	}
	out.Complete = out.Available && !out.Truncated && out.ReadErrors == 0 && ctx.Err() == nil
	return out
}

func nodeLoadPreflightCensusValid(v nodeLoadCensus) error {
	if !v.Available || !v.Complete || v.Truncated || v.ReadErrors != 0 || v.ManagedControllerDead || v.Scanned == 0 || v.Candidates != v.Scanned+v.Vanished {
		return errors.New("complete live-controller PID1 census required before load")
	}
	if v.AdoptedZombies != 0 {
		return errors.New("adopted PID1 zombies retained after quiescent load preflight")
	}
	return nil
}
