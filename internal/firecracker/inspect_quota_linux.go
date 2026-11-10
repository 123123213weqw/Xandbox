//go:build linux

package firecracker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

type InspectionProjects struct {
	Reserved, Empty, Owned int
	AllReleased            bool // Observation only, never full reclaim/work/activation authority.
}

// Separate closed READ-ONLY dispatcher: no SET, SYNC, quota-on/off, ioctl SET,
// driver constructor or mutation closure is reachable through this interface.
func inspectionQuotaCall(fd uintptr, cfg Config, command, id uint32, value unsafe.Pointer, call func(uintptr, uintptr, uintptr, uintptr, uintptr, uintptr) (uintptr, uintptr, unix.Errno)) error {
	if cfg.Quota == nil {
		return errors.New("project quota policy required")
	}
	switch command {
	case 0x800004:
		if id != 0 {
			return errors.New("invalid inspection format selector")
		}
	case 0x800007:
		if id < cfg.Quota.ProjectStart || uint64(id) >= uint64(cfg.Quota.ProjectStart)+uint64(cfg.UIDCount) {
			return errors.New("inspection project outside reserved range")
		}
	default:
		return errors.New("quota inspection is read-only")
	}
	if value == nil {
		return errors.New("quota inspection output required")
	}
	_, _, e := call(unix.SYS_QUOTACTL_FD, fd, uintptr(command<<8|2), uintptr(id), uintptr(value), 0)
	runtime.KeepAlive(value)
	if e != 0 {
		return e
	}
	return nil
}

func inspectProjectRecords(ctx context.Context, cfg Config, owners []InspectionOwnership, get func(uint32) (projectRecord, error)) (InspectionProjects, error) {
	var out InspectionProjects
	if e := ctx.Err(); e != nil {
		return out, e
	}
	if e := cfg.validate(); e != nil {
		return out, e
	}
	if cfg.Quota == nil || get == nil {
		return out, errors.New("project quota reader required")
	}
	known := map[uint32]ownership{}
	refs := map[string]bool{}
	for _, o := range owners {
		k, e := key(o.Ref)
		if e != nil || !validOwnership(o, cfg) || o.UID < cfg.UIDStart || o.UID >= cfg.UIDStart+cfg.UIDCount || refs[k] {
			return InspectionProjects{}, errors.New("invalid inspected quota owner")
		}
		if _, yes := known[o.ProjectID]; yes {
			return InspectionProjects{}, errors.New("duplicate inspected quota slot")
		}
		known[o.ProjectID], refs[k] = o, true
	}
	q := projectQuota{cfg: cfg}
	for n := 0; n < cfg.UIDCount; n++ {
		if e := ctx.Err(); e != nil {
			return InspectionProjects{}, e
		}
		id := cfg.Quota.ProjectStart + uint32(n)
		r, e := get(id)
		if e != nil {
			return InspectionProjects{}, e
		}
		// Linux Q_GETQUOTA fills all six QIF fields. Partial/unknown results
		// must never let zero-initialized output masquerade as released usage.
		// https://www.man7.org/linux/man-pages/man2/q_getquota.2const.html
		if r.Valid != 63 || r.Pad != 0 {
			return InspectionProjects{}, errors.New("incomplete kernel quota inspection")
		}
		o, owned := known[id]
		if (!owned || !o.QuotaAttempted) && !emptyProject(r) {
			return InspectionProjects{}, ErrQuotaOwnership
		}
		if owned && o.QuotaAttempted && !q.knownRecord(r) {
			return InspectionProjects{}, errors.New("inspected quota conflicts with immutable limits")
		}
		out.Reserved++
		if owned {
			out.Owned++
		}
		if emptyProject(r) {
			out.Empty++
		}
	}
	if e := ctx.Err(); e != nil {
		return InspectionProjects{}, e
	}
	out.AllReleased = out.Empty == out.Reserved && out.Owned == 0
	return out, nil
}

// InspectReservedProjects queries a caller-anchored runtime directory only.
// The caller must hold original state ownership and bind this FD to the fixed
// installed RuntimeRoot before/after inspection. No arbitrary path/CLI selector
// or transferable full-reclaim certificate is provided. This function never
// creates, repairs, sets or syncs quota state, and does not require constructing
// the effectful driver/project-quota lifecycle object.
func InspectReservedProjects(ctx context.Context, cfg Config, anchor *os.File, owners []InspectionOwnership) (InspectionProjects, error) {
	var out InspectionProjects
	if e := ctx.Err(); e != nil {
		return out, e
	}
	if e := cfg.validate(); e != nil {
		return out, e
	}
	if cfg.Quota == nil || anchor == nil {
		return out, errors.New("anchored project quota inspection required")
	}
	raw, e := anchor.SyscallConn()
	if e != nil {
		return out, e
	}
	fd := -1
	var cause error
	if e = raw.Control(func(n uintptr) { fd, cause = unix.FcntlInt(n, unix.F_DUPFD_CLOEXEC, 0) }); e != nil {
		return out, e
	}
	if cause != nil {
		return out, cause
	}
	f := os.NewFile(uintptr(fd), "readonly-quota-inspection-anchor")
	defer f.Close()
	if cfg.IO != nil {
		var st unix.Stat_t
		if e = unix.Fstat(fd, &st); e != nil {
			return out, e
		}
		if fmt.Sprintf("%d:%d", unix.Major(st.Dev), unix.Minor(st.Dev)) != cfg.IO.FilesystemDevice {
			return out, errors.New("inspection runtime filesystem device changed")
		}
	}
	mount, e := inspectQuotaMount(f, cfg.Quota.FilesystemUUID)
	if e != nil {
		return out, e
	}
	a, e := readProjectAttr(f)
	if e != nil {
		return out, e
	}
	if a.ID != 0 || a.Flags&projectInherit != 0 {
		return out, errors.New("inspected runtime root must be unassigned")
	}
	var format uint32
	// Wrapper preserves the syscall's six argument ABI while allowing only the
	// two getters above. A real typed result is required after successful return.
	call := func(trap, a, b, c, d, e uintptr) (uintptr, uintptr, unix.Errno) {
		return unix.Syscall6(trap, a, b, c, d, e, 0)
	}
	if e = inspectionQuotaCall(f.Fd(), cfg, 0x800004, 0, unsafe.Pointer(&format), call); e != nil {
		return out, e
	}
	if format != 4 {
		return out, errors.New("inspection requires v2 64-bit quota accounting")
	}
	out, e = inspectProjectRecords(ctx, cfg, owners, func(id uint32) (projectRecord, error) {
		var r projectRecord
		e := inspectionQuotaCall(f.Fd(), cfg, 0x800007, id, unsafe.Pointer(&r), call)
		return r, e
	})
	if e != nil {
		return InspectionProjects{}, e
	}
	after, e := inspectQuotaMount(f, cfg.Quota.FilesystemUUID)
	if e != nil {
		return InspectionProjects{}, e
	}
	if mount != after {
		return InspectionProjects{}, errors.New("inspected quota mount changed")
	}
	a, e = readProjectAttr(f)
	if e != nil {
		return InspectionProjects{}, e
	}
	if a.ID != 0 || a.Flags&projectInherit != 0 {
		return InspectionProjects{}, errors.New("inspected runtime project changed")
	}
	return out, ctx.Err()
}
