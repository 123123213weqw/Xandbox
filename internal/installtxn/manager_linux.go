//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type command func(context.Context, []string) ([]byte, error)
type systemManager struct {
	fs      *filesystem
	command command
}
type observation struct {
	load, active, fragment, dropins, enabled string
	pid                                      int
}

func parseObservation(raw []byte) (observation, error) {
	var o observation
	values := map[string]string{}
	if len(raw) > 16384 {
		return o, ErrInventory
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		a, b, ok := strings.Cut(line, "=")
		if !ok || values[a] != "" || strings.ContainsAny(b, "\r\x00") {
			return o, ErrInventory
		}
		switch a {
		case "LoadState", "ActiveState", "FragmentPath", "DropInPaths", "UnitFileState", "MainPID":
		default:
			return o, ErrInventory
		}
		if _, ok := values[a]; ok {
			return o, ErrInventory
		}
		values[a] = b
	}
	if len(values) != 6 {
		return o, ErrInventory
	}
	pid, e := strconv.Atoi(values["MainPID"])
	if e != nil || pid < 0 || strconv.Itoa(pid) != values["MainPID"] {
		return o, ErrInventory
	}
	return observation{values["LoadState"], values["ActiveState"], values["FragmentPath"], values["DropInPaths"], values["UnitFileState"], pid}, nil
}
func (m systemManager) observe(ctx context.Context, unit string) (observation, error) {
	if unit != MainUnit && unit != IngressUnit {
		return observation{}, ErrPolicy
	}
	raw, e := m.command(ctx, []string{"show", "--property=LoadState", "--property=ActiveState", "--property=FragmentPath", "--property=DropInPaths", "--property=UnitFileState", "--property=MainPID", unit})
	if e != nil {
		return observation{}, e
	}
	return parseObservation(raw)
}
func (m systemManager) fresh(ctx context.Context) error {
	for _, unit := range []string{MainUnit, IngressUnit} {
		o, e := m.observe(ctx, unit)
		if e != nil {
			return e
		}
		if o.load != "not-found" || o.active != "inactive" || o.pid != 0 || o.fragment != "" || o.dropins != "" || o.enabled != "" {
			return ErrInventory
		}
	}
	for _, p := range []string{UnitDir + "/multi-user.target.wants/" + MainUnit, UnitDir + "/" + MainUnit + ".wants"} {
		yes, e := m.fs.exists(p)
		if e != nil {
			return e
		}
		if yes {
			return ErrInventory
		}
	}
	return nil
}
func (f *filesystem) link(path, unit string) error {
	dir, e := f.directory(strings.TrimSuffix(path, "/"+unit))
	if e != nil {
		return e
	}
	defer dir.Close()
	var s unix.Stat_t
	if unix.Fstatat(int(dir.Fd()), unit, &s, unix.AT_SYMLINK_NOFOLLOW) != nil || s.Mode&unix.S_IFMT != unix.S_IFLNK || s.Uid != uint32(os.Geteuid()) {
		return ErrInventory
	}
	b := make([]byte, 4096)
	n, e := unix.Readlinkat(int(dir.Fd()), unit, b)
	if e != nil {
		return e
	}
	value := string(b[:n])
	if value != UnitDir+"/"+unit && value != "../"+unit {
		return ErrInventory
	}
	return nil
}
func (m systemManager) current(ctx context.Context) (bool, error) {
	for _, unit := range []string{MainUnit, IngressUnit} {
		o, e := m.observe(ctx, unit)
		if e != nil {
			return false, e
		}
		if o.load != "loaded" || o.fragment != UnitDir+"/"+unit || o.dropins != "" {
			return false, ErrInventory
		}
		if o.active != "active" || o.enabled != "enabled" || o.pid <= 1 {
			return false, nil
		}
	}
	if e := m.fs.link(UnitDir+"/multi-user.target.wants/"+MainUnit, MainUnit); e != nil {
		return false, e
	}
	if e := m.fs.link(UnitDir+"/"+MainUnit+".wants/"+IngressUnit, IngressUnit); e != nil {
		return false, e
	}
	names, e := m.fs.names(UnitDir + "/" + MainUnit + ".wants")
	if e != nil || !sameNames(names, []string{IngressUnit}) {
		return false, ErrInventory
	}
	return true, nil
}
func (m systemManager) reconcile(ctx context.Context) error {
	return m.reconcileUnits(ctx, false)
}
func (m systemManager) reconcileManaged(ctx context.Context) error {
	return m.reconcileUnits(ctx, true)
}
func (m systemManager) reconcileUnits(ctx context.Context, explicitIngress bool) error {
	// These are idempotent manager operations, never restart/stop/reset-failed or
	// node resume. The transaction file lock is NOT held while ExecStartPre runs.
	if _, e := m.command(ctx, []string{"daemon-reload"}); e != nil {
		return e
	}
	for _, unit := range []string{MainUnit, IngressUnit} {
		o, e := m.observe(ctx, unit)
		if e != nil {
			return e
		}
		if o.load != "loaded" || o.fragment != UnitDir+"/"+unit || o.dropins != "" {
			return ErrInventory
		}
	}
	if _, e := m.command(ctx, []string{"enable", MainUnit, IngressUnit}); e != nil {
		return e
	}
	if _, e := m.command(ctx, []string{"start", MainUnit}); e != nil {
		return e
	}
	if explicitIngress {
		main, e := m.observe(ctx, MainUnit)
		if e != nil || main.active != "active" || main.pid <= 1 {
			return ErrInventory
		}
		ingress, e := m.observe(ctx, IngressUnit)
		if e != nil {
			return e
		}
		if ingress.active != "active" {
			if _, e = m.command(ctx, []string{"start", IngressUnit}); e != nil {
				return e
			}
		}
	}
	waitCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for {
		yes, e := m.current(waitCtx)
		if e != nil {
			return e
		}
		if yes {
			return nil
		}
		select {
		case <-waitCtx.Done():
			return waitCtx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("bounded manager output exceeded")
	}
	return b.Buffer.Write(p)
}
func (f *filesystem) managerCommand(ctx context.Context, args []string) ([]byte, error) {
	// Root-owned OS systemctl and its verified ancestry are a declared trust root;
	// no environment-selected binary, shell, unit, remote host or tenant input.
	in, e := f.open("/usr/bin/systemctl", unix.O_RDONLY, 0)
	if e != nil {
		return nil, e
	}
	st, e := in.Stat()
	in.Close()
	if e != nil || st.Mode().Perm()&0111 == 0 {
		return nil, ErrPlatform
	}
	// enable normally reports successful link creation on stderr. Quiet mode
	// suppresses that progress, not errors; unexpected stderr stays fail closed.
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", append([]string{"--no-ask-password", "--no-pager", "--quiet"}, args...)...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER="}
	cmd.Stdin = nil
	out, errout := &limitedBuffer{limit: 16384}, &limitedBuffer{limit: 4096}
	cmd.Stdout = out
	cmd.Stderr = errout
	if e = cmd.Run(); e != nil || errout.Len() != 0 {
		return nil, ErrPlatform
	}
	return out.Bytes(), nil
}

// Keep io imported in compile-time interface checks instead of trusting exec's
// writer selection to accidentally bypass the fixed bounds.
var _ io.Writer = (*limitedBuffer)(nil)
