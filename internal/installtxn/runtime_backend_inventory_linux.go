//go:build linux

package installtxn

import (
	"context"
	"errors"
	"io"
	"os"
	"sort"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

type runtimeBackendInventory struct {
	Core                                                        runtimeCoreInventory
	Owners, Jails, InstanceGroups                               int
	NodeEnvelopePresent                                         bool
	Projects                                                    firecracker.InspectionProjects
	BackendInventoryParsed, BackendResourcesAbsent              bool
	AcceptedWorkComplete, ResourcesReclaimed, ActivationAllowed bool
}
type backendInspectionProofs struct {
	empty    func(string) error
	cgroup   func(int) error
	projects func(context.Context, firecracker.Config, *os.File, []firecracker.InspectionOwnership) (firecracker.InspectionProjects, error)
}

// Retain exact opened directory/link identity and names around each traversal.
// This is not a writer-reconciliation operation; unknown/partial files refuse.
func stableBackendDirectory(ctx context.Context, f *filesystem, path string, max int, visit func(*os.File, []string) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	dir, e := f.directory(path)
	if e != nil {
		return e
	}
	defer dir.Close()
	if e = trustedStat(int(dir.Fd()), true, 0700); e != nil {
		return e
	}
	var before, after, current unix.Stat_t
	if e = unix.Fstat(int(dir.Fd()), &before); e != nil {
		return e
	}
	names, e := dir.Readdirnames(max + 1)
	if e != nil && e != io.EOF {
		return e
	}
	if len(names) > max {
		return ErrInventory
	}
	sort.Strings(names)
	if e = visit(dir, names); e != nil {
		return e
	}
	if e = unix.Fstat(int(dir.Fd()), &after); e != nil {
		return e
	}
	linked, e := f.directory(path)
	if e != nil {
		return e
	}
	defer linked.Close()
	if e = unix.Fstat(int(linked.Fd()), &current); e != nil {
		return e
	}
	if !sameCoreStat(before, after) || !sameCoreStat(after, current) {
		return ErrInventory
	}
	return ctx.Err()
}

// The installed composition has always forbidden snapshot bootstrap/migration.
// Do not change immutable backend policy just to make an inspection pass. A
// catalog (including empty) is UNKNOWN under this cold policy and must refuse.
func readBackendOwners(ctx context.Context, state *filesystem, cfg firecracker.Config, generations map[sandbox.Ref]coreGeneration) ([]firecracker.InspectionOwnership, error) {
	var out []firecracker.InspectionOwnership
	if cfg.Snapshot != nil {
		return nil, ErrPolicy
	}
	uids := map[int]bool{}
	refs := map[sandbox.Ref]bool{}
	e := stableBackendDirectory(ctx, state, "/firecracker", cfg.UIDCount+1, func(dir *os.File, names []string) error {
		seenConfig := false
		for _, name := range names {
			if name == "config.json" {
				b, e := readCoreRecord(ctx, dir, name, 16384)
				if e != nil {
					return e
				}
				bound, e := firecracker.DecodeInspectionConfig(b)
				if e != nil {
					return e
				}
				if !firecracker.InspectionConfigEqual(bound, cfg) {
					return ErrConflict
				}
				seenConfig = true
				continue
			}
			if len(name) != 69 || name[64:] != ".json" || !digestPattern.MatchString(name[:64]) {
				return ErrInventory
			}
			b, e := readCoreRecord(ctx, dir, name, 2048)
			if e != nil {
				return e
			}
			o, e := firecracker.DecodeInspectionOwnership(b, cfg)
			if e != nil {
				return e
			}
			g, ok := generations[o.Ref]
			if !ok || g.state == sandbox.Destroyed || name[:64] != o.Ref.ID+o.Ref.Generation || uids[o.UID] || refs[o.Ref] {
				return ErrInventory
			}
			uids[o.UID], refs[o.Ref] = true, true
			out = append(out, o)
		}
		if !seenConfig {
			return ErrInventory
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}

func inspectJailNamespaces(ctx context.Context, f *filesystem, cfg firecracker.Config, owners map[string]bool) (int, error) {
	count := 0
	for _, stage := range []struct {
		path  string
		names []string
	}{{runtimeDir, []string{"j"}}, {runtimeDir + "/j", []string{"firecracker"}}} {
		if e := stableBackendDirectory(ctx, f, stage.path, 1, func(_ *os.File, names []string) error {
			if !sameNames(names, stage.names) {
				return ErrInventory
			}
			return nil
		}); e != nil {
			return 0, e
		}
	}
	e := stableBackendDirectory(ctx, f, runtimeDir+"/j/firecracker", cfg.UIDCount, func(dir *os.File, names []string) error {
		for _, name := range names {
			if !digestPattern.MatchString(name) || !owners[name] {
				return ErrInventory
			}
			var st unix.Stat_t
			if e := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
				return e
			}
			if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0700 {
				return ErrInventory
			}
			// Never descend into guest-controlled jail contents or follow a link.
			count++
		}
		return nil
	})
	if e != nil {
		return 0, e
	}
	return count, nil
}

// Missing nodes count absent ONLY below a validated real cgroup2 ancestor.
// Walk the complete fixed unit/node layout, rejecting unknown child groups;
// observe exact generation dirs without removing/freezing/killing anything.
func inspectBackendGroups(ctx context.Context, f *filesystem, owners map[string]bool, checkFS func(int) error) (int, bool, error) {
	parent, e := f.directory(ingressCgroupParent)
	if e != nil {
		return 0, false, e
	}
	defer parent.Close()
	if e = checkFS(int(parent.Fd())); e != nil {
		return 0, false, e
	}
	count := 0
	nodePresent := false
	var walk func(*os.File, string) error
	walk = func(dir *os.File, level string) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := checkFS(int(dir.Fd())); e != nil {
			return e
		}
		if e := trustedStat(int(dir.Fd()), true, 0); e != nil {
			return e
		}
		if level == "generation" {
			return proveIngressSubtree(dir, checkFS)
		}
		if e := readIngressEvents(int(dir.Fd()), checkFS); e != nil {
			return e
		}
		names, e := ingressNames(int(dir.Fd()))
		if e != nil {
			return e
		}
		for _, name := range names {
			var st unix.Stat_t
			if e = unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
				return e
			}
			if st.Mode&unix.S_IFMT == unix.S_IFREG {
				continue
			} // Kernel interface, on proven cgroup2 only.
			if st.Mode&unix.S_IFMT != unix.S_IFDIR {
				return ErrInventory
			}
			switch level {
			case "unit":
				if name != "node" {
					return ErrInventory
				}
				nodePresent = true
			case "node":
				if name != "control" && name != "instances" {
					return ErrInventory
				}
			case "instances":
				if !digestPattern.MatchString(name) || !owners[name] {
					return ErrInventory
				}
				count++
			default:
				return ErrInventory
			}
			fd, e := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if e != nil {
				return e
			}
			child := os.NewFile(uintptr(fd), "backend-inspection-cgroup")
			var opened unix.Stat_t
			e = unix.Fstat(fd, &opened)
			if e == nil && (opened.Dev != st.Dev || opened.Ino != st.Ino) {
				e = ErrInventory
			}
			next := name
			if level == "instances" {
				next = "generation"
			}
			if e == nil {
				e = walk(child, next)
			}
			child.Close()
			if e != nil {
				return e
			}
			if e = sameIngressEntry(int(dir.Fd()), name, st, false); e != nil {
				return e
			}
		}
		after, e := ingressNames(int(dir.Fd()))
		if e != nil {
			return e
		}
		if !sameNames(names, after) {
			return ErrInventory
		}
		return readIngressEvents(int(dir.Fd()), checkFS)
	}
	fd, e := unix.Openat(int(parent.Fd()), MainUnit, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(e, unix.ENOENT) {
		return 0, false, nil
	}
	if e != nil {
		return 0, false, e
	}
	unit := os.NewFile(uintptr(fd), "backend-inspection-unit")
	defer unit.Close()
	var pinned unix.Stat_t
	if e = unix.Fstat(fd, &pinned); e != nil {
		return 0, false, e
	}
	if e = walk(unit, "unit"); e != nil {
		return 0, false, e
	}
	if e = sameIngressEntry(int(parent.Fd()), MainUnit, pinned, false); e != nil {
		return 0, false, e
	}
	return count, nodePresent, ctx.Err()
}

func (s *runtimeScope) inspectStoppedBackend(ctx context.Context, base, request string, m systemManager) (runtimeBackendInventory, error) {
	return s.inspectStoppedBackendWithProofs(ctx, base, request, m, backendInspectionProofs{m.fs.unitExecutionEmpty, cgroup2FD, firecracker.InspectReservedProjects})
}

// Private model seams apply ONLY to manager/real cgroup/mount/quota observations.
// Original leases, saved Stop/admission, installed policy, complete metadata and
// path/FD/record joins always run. No public selector or file permission token.
func (s *runtimeScope) inspectStoppedBackendWithProofs(ctx context.Context, base, request string, m systemManager, proof backendInspectionProofs) (runtimeBackendInventory, error) {
	var out runtimeBackendInventory
	if !digestPattern.MatchString(base) || !requestPattern.MatchString(request) || proof.empty == nil || proof.cgroup == nil || proof.projects == nil {
		return out, ErrPolicy
	}
	e := s.run(ctx, func(f *filesystem) error {
		if s.state == nil {
			return ErrConflict
		}
		p, e := s.stoppedStateProof(ctx, base, request, m, proof.empty)
		if e != nil {
			return e
		}
		if p.State == nil || s.state.id != *p.State {
			return ErrConflict
		}
		raw, e := f.read(Root+"/backend.json", 16384, 0600)
		if e != nil {
			return e
		}
		cfg, e := firecracker.DecodeInspectionConfig(raw)
		if e != nil {
			return e
		}
		if cfg.Snapshot != nil || cfg.Version != 3 || cfg.RuntimeRoot != runtimeDir || cfg.CgroupRoot != unitRoot+"/node/instances" || cfg.Node == nil || cfg.Quota == nil || cfg.IO == nil {
			return ErrInventory
		}
		drain, e := f.runtimeDrainReadIntent()
		if e != nil {
			return e
		}
		var generations map[sandbox.Ref]coreGeneration
		out.Core, generations, e = readCoreAuthority(ctx, s.state.root, drainedRuntimeState(drain))
		if e != nil {
			return e
		}
		state := &filesystem{root: s.state.root}
		owners, e := readBackendOwners(ctx, state, cfg, generations)
		if e != nil {
			return e
		}
		out.Owners = len(owners)
		if e = f.point("runtime-backend-after-registry"); e != nil {
			return e
		}
		keys := map[string]bool{}
		for _, o := range owners {
			keys[o.Ref.ID+o.Ref.Generation] = true
		}
		out.Jails, e = inspectJailNamespaces(ctx, f, cfg, keys)
		if e != nil {
			return e
		}
		if e = f.point("runtime-backend-after-jails"); e != nil {
			return e
		}
		out.InstanceGroups, out.NodeEnvelopePresent, e = inspectBackendGroups(ctx, f, keys, proof.cgroup)
		if e != nil {
			return e
		}
		if e = f.point("runtime-backend-after-groups"); e != nil {
			return e
		}
		runtimeRoot, e := f.directory(runtimeDir)
		if e != nil {
			return e
		}
		defer runtimeRoot.Close()
		var before, stateStat, after unix.Stat_t
		if e = unix.Fstat(int(runtimeRoot.Fd()), &before); e != nil {
			return e
		}
		if e = unix.Fstat(int(s.state.root.Fd()), &stateStat); e != nil {
			return e
		}
		if before.Dev != stateStat.Dev {
			return ErrInventory
		}
		out.Projects, e = proof.projects(ctx, cfg, runtimeRoot, owners)
		if e != nil {
			return e
		}
		if out.Projects.Reserved != cfg.UIDCount || out.Projects.Owned != len(owners) || out.Projects.Empty < 0 || out.Projects.Empty > cfg.UIDCount || out.Projects.AllReleased != (out.Projects.Empty == cfg.UIDCount && len(owners) == 0) {
			return ErrInventory
		}
		if e = f.point("runtime-backend-after-quota"); e != nil {
			return e
		}
		linked, e := f.directory(runtimeDir)
		if e != nil {
			return e
		}
		defer linked.Close()
		if e = unix.Fstat(int(linked.Fd()), &after); e != nil {
			return e
		}
		if !sameCoreStat(before, after) {
			return ErrInventory
		}
		// Recheck complete metadata and namespace membership, not a cached report.
		again, e := readBackendOwners(ctx, state, cfg, generations)
		if e != nil {
			return e
		}
		if !sameInspectionOwners(owners, again) {
			return ErrConflict
		}
		j, e := inspectJailNamespaces(ctx, f, cfg, keys)
		if e != nil {
			return e
		}
		g, n, e := inspectBackendGroups(ctx, f, keys, proof.cgroup)
		if e != nil {
			return e
		}
		if j != out.Jails || g != out.InstanceGroups || n != out.NodeEnvelopePresent {
			return ErrConflict
		}
		if e = readCoreAdmission(ctx, state, drainedRuntimeState(drain)); e != nil {
			return e
		}
		coreAfter, _, e := readCoreAuthority(ctx, s.state.root, drainedRuntimeState(drain))
		if e != nil {
			return e
		}
		if coreAfter != out.Core {
			return ErrConflict
		}
		if _, e = s.stoppedStateProof(ctx, base, request, m, proof.empty); e != nil {
			return e
		}
		out.Core.CoreAuthorityParsed = true
		out.BackendInventoryParsed = true
		out.BackendResourcesAbsent = out.Owners == 0 && out.Jails == 0 && out.InstanceGroups == 0 && !out.NodeEnvelopePresent && out.Projects.AllReleased && out.Core.LedgerNonterminal == 0 && out.Core.SessionNonterminal == 0
		// NEVER promote this observation to successful work, complete all-authority
		// reclaim, durable media proof, activation or permission to select files.
		return nil
	})
	if e != nil {
		return runtimeBackendInventory{}, e
	}
	return out, nil
}

func sameInspectionOwners(a, b []firecracker.InspectionOwnership) bool {
	if len(a) != len(b) {
		return false
	}
	for n := range a {
		if a[n] != b[n] {
			return false
		}
	}
	return true
}
