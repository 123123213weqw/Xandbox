//go:build linux

package firecracker

import (
	"context"
	"errors"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestInspectionQuotaDispatcherOnlyAllowsBoundedReadCommands(t *testing.T) {
	cfg := policy()
	cfg.Quota = quotaPolicy()
	var value projectRecord
	for _, kind := range []string{"format", "project", "set", "sync", "on", "off", "get-info", "foreign-project", "foreign-format", "nil-output", "errno"} {
		t.Run(kind, func(t *testing.T) {
			command, id := uint32(0x800007), cfg.Quota.ProjectStart
			ptr := unsafe.Pointer(&value)
			switch kind {
			case "format":
				command, id = 0x800004, 0
			case "set":
				command = 0x800008
			case "sync":
				command, id = 0x800001, 0
			case "on":
				command = 0x800002
			case "off":
				command = 0x800003
			case "get-info":
				command = 0x800005
			case "foreign-project":
				id--
			case "foreign-format":
				command = 0x800004
			case "nil-output":
				ptr = nil
			}
			calls := 0
			e := inspectionQuotaCall(99, cfg, command, id, ptr, func(trap, fd, op, project, output, zero uintptr) (uintptr, uintptr, unix.Errno) {
				calls++
				if trap != unix.SYS_QUOTACTL_FD || fd != 99 || op != uintptr(command<<8|2) || project != uintptr(id) || output != uintptr(ptr) || zero != 0 {
					t.Error("incorrect read ABI")
				}
				if kind == "errno" {
					return 0, 0, unix.EIO
				}
				return 0, 0, 0
			})
			allowed := kind == "format" || kind == "project" || kind == "errno"
			if (calls == 1) != allowed {
				t.Fatal("dispatcher reached forbidden operation", calls, e)
			}
			if (e == nil) != (kind == "format" || kind == "project") {
				t.Fatal(e)
			}
			if kind == "errno" && !errors.Is(e, unix.EIO) {
				t.Fatal(e)
			}
		})
	}
}

func TestInspectionQuotaCompleteReservedRangeNeverAdoptsUnknownOrPartial(t *testing.T) {
	for _, kind := range []string{"released", "owned-limits", "owned-empty", "unowned-usage", "unowned-limits", "unattempted", "partial-valid", "unknown-valid", "padding", "usage-overflow", "wrong-limits", "duplicate-owner", "foreign-owner", "get-error", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			cfg := policy()
			cfg.Quota = quotaPolicy()
			o := ownership{Version: 3, Ref: reference("1"), UID: cfg.UIDStart, ProjectID: cfg.Quota.ProjectStart, QuotaAttempted: true}
			var owners []InspectionOwnership
			q := projectQuota{cfg: cfg}
			r := projectRecord{Valid: 63}
			switch kind {
			case "owned-limits":
				owners = []InspectionOwnership{o}
				r = q.limits()
				r.Valid = 63
				r.Space = 4096
				r.Inodes = 1
			case "owned-empty":
				owners = []InspectionOwnership{o}
			case "unowned-usage":
				r.Space = 4096
			case "unowned-limits":
				r = q.limits()
				r.Valid = 63
			case "unattempted":
				o.QuotaAttempted = false
				owners = []InspectionOwnership{o}
				r = q.limits()
				r.Valid = 63
			case "partial-valid":
				r.Valid = 0
			case "unknown-valid":
				r.Valid = 127
			case "padding":
				r.Pad = 1
			case "usage-overflow":
				owners = []InspectionOwnership{o}
				r = q.limits()
				r.Valid = 63
				r.Space = cfg.Quota.MaxBytes + 1
			case "wrong-limits":
				owners = []InspectionOwnership{o}
				r = q.limits()
				r.Valid = 63
				r.BHard++
			case "duplicate-owner":
				owners = []InspectionOwnership{o, o}
			case "foreign-owner":
				o.ProjectID++
				owners = []InspectionOwnership{o}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancel" {
				cancel()
			}
			calls := 0
			out, e := inspectProjectRecords(ctx, cfg, owners, func(id uint32) (projectRecord, error) {
				calls++
				if id < cfg.Quota.ProjectStart || id >= cfg.Quota.ProjectStart+uint32(cfg.UIDCount) {
					t.Fatal("range escaped")
				}
				if kind == "get-error" {
					return projectRecord{}, unix.EIO
				}
				if id == cfg.Quota.ProjectStart {
					return r, nil
				}
				return projectRecord{Valid: 63}, nil
			})
			want := kind == "released" || kind == "owned-limits" || kind == "owned-empty"
			if (e == nil) != want {
				t.Fatal(out, e)
			}
			if !want && out != (InspectionProjects{}) {
				t.Fatal("partial read report escaped", out)
			}
			if want && (calls != cfg.UIDCount || out.Reserved != cfg.UIDCount || out.AllReleased != (kind == "released")) {
				t.Fatal(out, calls)
			}
		})
	}
}

func TestInspectionQuotaClosedAnchorRefusesBeforeAnyKernelQuotaOperation(t *testing.T) {
	cfg := policy()
	cfg.Quota = quotaPolicy()
	f, e := os.CreateTemp(t.TempDir(), "closed-anchor-")
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	for _, anchor := range []*os.File{nil, f} {
		if out, e := InspectReservedProjects(context.Background(), cfg, anchor, nil); e == nil || out != (InspectionProjects{}) {
			t.Fatal(out, e)
		}
	}
}
