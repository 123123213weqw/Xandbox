//go:build linux

package installtxn

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
)

func validManagedUnit(o observation, unit string) bool {
	return o.load == "loaded" && o.enabled == "enabled" && o.fragment == UnitDir+"/"+unit && o.dropins == ""
}

// Explicit administrative maintenance, not the ordinary application start path.
// No file flock is held across this method. The caller's operation EX excludes
// competing installers until the callback's final ACK/receipt work finishes.
func (m systemManager) maintainIngress(ctx context.Context, work func() error) error {
	return m.maintainIngressProof(ctx, work, m.fs.ingressEmpty)
}

// The public manager always supplies the fixed read-only kernel proof. Tests
// model that observation, never by fabricating a cgroup on an ordinary FS.
func (m systemManager) maintainIngressProof(ctx context.Context, work func() error, empty func() error) error {
	if work == nil || empty == nil {
		return ErrPolicy
	}
	if e := m.enabledLinks(); e != nil {
		return e
	}
	main, e := m.observe(ctx, MainUnit)
	if e != nil {
		return e
	}
	if !validManagedUnit(main, MainUnit) || main.active != "active" || main.pid <= 1 {
		return ErrInventory
	}
	fd, e := unix.PidfdOpen(main.pid, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	sameMain := func() error {
		if e := livePolicyPID(fd); e != nil {
			return e
		}
		after, e := m.observe(ctx, MainUnit)
		if e != nil {
			return e
		}
		if after != main {
			return ErrConflict
		}
		return livePolicyPID(fd)
	}
	if e = sameMain(); e != nil {
		return e
	}
	ingress, e := m.observe(ctx, IngressUnit)
	if e != nil {
		return e
	}
	if !validManagedUnit(ingress, IngressUnit) {
		return ErrInventory
	}
	if ingress.active != "inactive" && ingress.active != "failed" || ingress.pid != 0 {
		// The fixed administrator recovery job must not propagate jobs to main or
		// other dependencies. v255 semantics: all requirement/ordering edges ignored.
		// https://github.com/systemd/systemd/blob/v255/man/systemctl.xml
		if _, e = m.command(ctx, []string{"--job-mode=ignore-dependencies", "stop", IngressUnit}); e != nil {
			return e
		}
	}
	stopped, e := m.observe(ctx, IngressUnit)
	if e != nil {
		return e
	}
	if !validManagedUnit(stopped, IngressUnit) || stopped.pid != 0 || stopped.active != "inactive" && stopped.active != "failed" {
		return ErrInventory
	}
	if e = sameMain(); e != nil {
		return e
	}
	if e = empty(); e != nil {
		return e
	}
	if e = sameMain(); e != nil {
		return e
	}
	// No restart on callback failure. A surviving supervisor is independently
	// excluded by the durable policy store's original exclusive lock.
	result := work()
	return errors.Join(result, sameMain())
}
