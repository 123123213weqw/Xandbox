//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/policycontrol"
	"golang.org/x/sys/unix"
)

type managedServiceManager interface {
	reconcileManaged(context.Context) error
	policy(context.Context, uint64, string, string, bool) (bool, error)
}

func (m systemManager) prepareManagedIngress(ctx context.Context) (observation, int, error) {
	var zero observation
	main, e := m.observe(ctx, MainUnit)
	if e != nil {
		return zero, -1, e
	}
	if main.load != "loaded" || main.active != "active" || main.enabled != "enabled" || main.fragment != UnitDir+"/"+MainUnit || main.dropins != "" || main.pid <= 1 {
		return zero, -1, ErrInventory
	}
	fd, e := unix.PidfdOpen(main.pid, 0)
	if e != nil {
		return zero, -1, e
	}
	ok := false
	defer func() {
		if !ok {
			unix.Close(fd)
		}
	}()
	if e = livePolicyPID(fd); e != nil {
		return zero, -1, e
	}
	ingress, e := m.observe(ctx, IngressUnit)
	if e != nil {
		return zero, -1, e
	}
	if ingress.load != "loaded" || ingress.enabled != "enabled" || ingress.fragment != UnitDir+"/"+IngressUnit || ingress.dropins != "" {
		return zero, -1, ErrInventory
	}
	if ingress.active != "active" {
		// Ordinary start could pull in BindsTo's main after a concurrent stop.
		// v255 ignore-requirements omits requirement activation but keeps ordering:
		// https://github.com/systemd/systemd/blob/v255/man/systemctl.xml
		if _, e = m.command(ctx, []string{"--job-mode=ignore-requirements", "start", IngressUnit}); e != nil {
			return zero, -1, e
		}
	}
	after, e := m.observe(ctx, MainUnit)
	if e != nil {
		return zero, -1, e
	}
	if after != main {
		return zero, -1, ErrConflict
	}
	if e = livePolicyPID(fd); e != nil {
		return zero, -1, e
	}
	ok = true
	return main, fd, nil
}
func (m systemManager) activateManaged(ctx context.Context, epoch uint64, digest, sha string) (bool, error) {
	main, fd, e := m.prepareManagedIngress(ctx)
	if e != nil {
		return false, e
	}
	defer unix.Close(fd)
	yes, e := m.policy(ctx, epoch, digest, sha, true)
	if e != nil || !yes {
		return false, e
	}
	after, e := m.observe(ctx, MainUnit)
	if e != nil {
		return false, e
	}
	if after != main {
		return false, ErrConflict
	}
	if e = livePolicyPID(fd); e != nil {
		return false, e
	}
	return true, nil
}

func boundedProcessFile(path string, max int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > max {
		return nil, ErrInventory
	}
	return b, nil
}
func policyProcessProof(ctx context.Context, pid int, sha string) error {
	root := "/proc/" + strconv.Itoa(pid)
	placement, e := boundedProcessFile(root+"/cgroup", 4096)
	if e != nil {
		return e
	}
	if strings.TrimSpace(string(placement)) != "0::/system.slice/"+IngressUnit {
		return ErrInventory
	}
	argv, e := boundedProcessFile(root+"/cmdline", 16384)
	if e != nil {
		return e
	}
	if !bytes.Equal(argv, []byte(rolePath("gateway")+"\x00-config\x00"+Root+"/gateway.json\x00")) {
		return unix.EAGAIN
	}
	f, e := os.Open(root + "/exe")
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	if e = trustedStat(int(f.Fd()), false, 0555); e != nil {
		return e
	}
	if st.Size() <= 0 || st.Size() > 64<<20 {
		return ErrInventory
	}
	sum, e := hashFile(ctx, f, st.Size())
	if e != nil {
		return e
	}
	if sum != sha {
		return unix.EAGAIN
	}
	return nil
}
func livePolicyPID(fd int) error {
	n, e := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 0)
	if e != nil {
		return e
	}
	if n != 0 {
		return ErrInventory
	}
	return nil
}
func (m systemManager) policySample(ctx context.Context, epoch uint64, digest, sha string, activate bool) (policycontrol.PolicyStatus, error) {
	var zero policycontrol.PolicyStatus
	yes, e := m.current(ctx)
	if e != nil {
		return zero, e
	}
	if !yes {
		return zero, unix.EAGAIN
	}
	o, e := m.observe(ctx, IngressUnit)
	if e != nil {
		return zero, e
	}
	fd, e := unix.PidfdOpen(o.pid, 0)
	if e != nil {
		return zero, e
	}
	defer unix.Close(fd)
	if e = livePolicyPID(fd); e != nil {
		return zero, e
	}
	if e = policyProcessProof(ctx, o.pid, sha); e != nil {
		return zero, e
	}
	command := policycontrol.PolicyCommand{Version: 1, Operation: "status"}
	if activate {
		if epoch == 0 {
			return zero, ErrPolicy
		}
		command = policycontrol.PolicyCommand{Version: 1, Operation: "activate", ExpectedEpoch: epoch - 1, TargetEpoch: epoch, SnapshotSHA256: digest}
	}
	s, e := policycontrol.RequestPolicy(ctx, o.pid, command)
	if e != nil {
		return zero, e
	}
	if e = policyProcessProof(ctx, o.pid, sha); e != nil {
		return zero, e
	}
	if e = livePolicyPID(fd); e != nil {
		return zero, e
	}
	after, e := m.observe(ctx, IngressUnit)
	if e != nil {
		return zero, e
	}
	if after != o {
		return zero, ErrConflict
	}
	return s, nil
}
func (m systemManager) policy(ctx context.Context, epoch uint64, digest, sha string, reconcile bool) (bool, error) {
	if epoch == 0 || !digestPattern.MatchString(digest) || !digestPattern.MatchString(sha) {
		return false, ErrPolicy
	}
	if !reconcile {
		s, e := m.policySample(ctx, epoch, digest, sha, false)
		if e != nil {
			return false, e
		}
		return s.Phase == "active" && s.DurableEpoch == epoch && s.ActiveEpoch == epoch && s.SnapshotSHA256 == digest && s.ActiveSHA256 == digest, nil
	}
	wait, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	attempted := false
	for {
		s, e := m.policySample(wait, epoch, digest, sha, false)
		if e == nil {
			if s.Phase == "fenced" || s.DurableEpoch > epoch || s.DurableEpoch == epoch && s.SnapshotSHA256 != digest {
				return false, ErrConflict
			}
			if s.Phase == "active" && s.DurableEpoch == epoch && s.ActiveEpoch == epoch && s.SnapshotSHA256 == digest && s.ActiveSHA256 == digest {
				return true, nil
			}
			if !attempted && s.Phase == "active" && s.DurableEpoch != ^uint64(0) && s.DurableEpoch+1 == epoch {
				attempted = true
				// A lost response is unconfirmed: observe, do not blindly resend.
				_, _ = m.policySample(wait, epoch, digest, sha, true)
			}
		} else if errors.Is(e, ErrInventory) || errors.Is(e, ErrConflict) {
			return false, e
		}
		select {
		case <-wait.Done():
			return false, wait.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
func (f *filesystem) policyReceipt(ctx context.Context, t transaction, m serviceManager, reconcile bool) (bool, error) {
	managed, ok := m.(managedServiceManager)
	if !ok {
		return false, ErrPlatform
	}
	_, p, e := f.effectivePolicy(t, true)
	if e != nil {
		return false, e
	}
	digest, e := gateway.SnapshotDigest(p.Snapshot)
	if e != nil {
		return false, e
	}
	art, e := descriptor(t.Release)
	if e != nil {
		return false, e
	}
	return managed.policy(ctx, p.Revision, digest, art["gateway"].SHA256, reconcile)
}
