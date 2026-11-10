//go:build linux

package installtxn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"os"
	"sort"

	"github.com/123123213weqw/Xandbox/internal/diagnostics"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"golang.org/x/sys/unix"
)

// Joined observations under ONE original operation/state scope. Not a portable
// capability, result-retention proof or permission to select/activate files.
type runtimeClosedStateInventory struct {
	Terminal                                                 runtimeTerminalInventory
	Backend                                                  runtimeBackendInventory
	State                                                    runtimeStateFootprint
	ClosedStateJoined, ResourcesReclaimed, ActivationAllowed bool
}

type runtimeStateFootprint struct {
	digest             string
	Files, Sockets     int
	DiagnosticSequence uint64
}

// Deliberately exclude access time: reading a file is not a mutation authority.
// Bind identity, owner/group, type/mode, hard links, size and write/change times.
type stateEntryIdentity struct {
	Device, Inode, Links uint64
	Mode, UID, GID       uint32
	Bytes                int64
	Modified, Changed    unix.Timespec
}

func stateEntry(st unix.Stat_t) stateEntryIdentity {
	return stateEntryIdentity{uint64(st.Dev), st.Ino, uint64(st.Nlink), st.Mode, st.Uid, st.Gid, st.Size, st.Mtim, st.Ctim}
}

type stateInventoryReader struct {
	ctx    context.Context
	device uint64
	hash   hash.Hash
	view   runtimeStateFootprint
}

func (r *stateInventoryReader) bind(path string, st unix.Stat_t, raw []byte) {
	r.hash.Write(encode(struct {
		Path   string
		Entry  stateEntryIdentity
		SHA256 string
	}{path, stateEntry(st), digest(raw)}))
}

func (r *stateInventoryReader) entry(dir *os.File, name string) (unix.Stat_t, error) {
	var st unix.Stat_t
	if e := r.ctx.Err(); e != nil {
		return st, e
	}
	if e := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return st, e
	}
	if uint64(st.Dev) != r.device || st.Uid != uint32(os.Geteuid()) {
		return st, ErrInventory
	}
	return st, nil
}

// Open an independent directory description (never move the retained FD offset).
// Bounds/names are complete, sorted and checked BEFORE visiting any file.
func (r *stateInventoryReader) directory(parent *os.File, name, path string, max int, visit func(*os.File, []string) error) error {
	before, e := r.entry(parent, name)
	if e != nil {
		return e
	}
	fd, e := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	dir := os.NewFile(uintptr(fd), "closed-state-directory")
	defer dir.Close()
	if e = trustedStat(fd, true, 0700); e != nil {
		return e
	}
	var opened, after unix.Stat_t
	if e = unix.Fstat(fd, &opened); e != nil || stateEntry(opened) != stateEntry(before) {
		return ErrInventory
	}
	names, e := dir.Readdirnames(max + 1)
	if e != nil && e != io.EOF {
		return e
	}
	if len(names) > max {
		return ErrInventory
	}
	sort.Strings(names)
	r.bind(path, before, nil)
	if e = visit(dir, names); e != nil {
		return e
	}
	if e = unix.Fstat(fd, &after); e != nil {
		return e
	}
	linked, e := r.entry(parent, name)
	if e != nil {
		return e
	}
	if stateEntry(before) != stateEntry(after) || stateEntry(after) != stateEntry(linked) {
		return ErrInventory
	}
	return r.ctx.Err()
}

func (r *stateInventoryReader) file(dir *os.File, name, path string, limit int, empty bool) ([]byte, error) {
	before, e := r.entry(dir, name)
	if e != nil {
		return nil, e
	}
	var raw []byte
	if empty {
		if before.Mode != unix.S_IFREG|0600 || before.Nlink != 1 || before.Size != 0 {
			return nil, ErrInventory
		}
	} else {
		raw, e = readCoreRecord(r.ctx, dir, name, limit)
		if e != nil {
			return nil, e
		}
	}
	after, e := r.entry(dir, name)
	if e != nil || stateEntry(before) != stateEntry(after) {
		return nil, ErrInventory
	}
	r.bind(path, after, raw)
	r.view.Files++
	return raw, nil
}

func (r *stateInventoryReader) records(dir *os.File, names []string, path string, limit int) error {
	last := ""
	for _, name := range names {
		if len(name) != 37 || name[32:] != ".json" || !requestPattern.MatchString(name[:32]) || name <= last {
			return ErrInventory
		}
		last = name
	}
	for _, name := range names {
		if _, e := r.file(dir, name, path+"/"+name, limit, false); e != nil {
			return e
		}
	}
	return nil
}

// Complete CURRENT installed cold Firecracker state namespace. No generic walk,
// constructor/ordinary Load, orphan deletion, socket connection/unlink or sync.
// Semantic admission/ledger/session/owner joins run independently before/after.
func readClosedStateRoot(ctx context.Context, root *os.File, cfg firecracker.Config, metrics bool) (runtimeStateFootprint, error) {
	var st unix.Stat_t
	if e := unix.Fstat(int(root.Fd()), &st); e != nil {
		return runtimeStateFootprint{}, e
	}
	r := stateInventoryReader{ctx: ctx, device: uint64(st.Dev), hash: sha256.New()}
	r.hash.Write([]byte("Xandbox original closed state namespace v1\x00"))
	e := r.directory(root, ".", ".", 11, func(dir *os.File, names []string) error {
		required := map[string]bool{"controller.lock": true, "admission.identity": true, "maintenance.identity": true,
			"admission": true, "ledger": true, "sessions": true, "firecracker": true, "diagnostics": true}
		for _, name := range names {
			if !required[name] && name != "api.sock" && name != nodecontrol.SocketName && !(metrics && name == "metrics.sock") {
				return ErrInventory
			}
			delete(required, name)
		}
		if len(required) != 0 {
			return ErrInventory
		}
		for _, name := range names {
			switch name {
			case "controller.lock", "admission.identity", "maintenance.identity":
				if _, e := r.file(dir, name, name, nodecontrol.StateLimit, name == "controller.lock"); e != nil {
					return e
				}
			case "admission":
				if e := r.directory(dir, name, name, 2, func(d *os.File, n []string) error {
					if !sameNames(n, []string{nodecontrol.MaintenanceName, "state.json"}) {
						return ErrInventory
					}
					for _, file := range n {
						if _, e := r.file(d, file, name+"/"+file, nodecontrol.StateLimit, false); e != nil {
							return e
						}
					}
					return nil
				}); e != nil {
					return e
				}
			case "ledger", "sessions":
				max, limit := sandbox.MaxLedgerRecords, sandbox.MaxLedgerRecordBytes
				if name == "sessions" {
					max, limit = session.MaxRecords, session.MaxRecordBytes
				}
				if e := r.directory(dir, name, name, max, func(d *os.File, n []string) error { return r.records(d, n, name, limit) }); e != nil {
					return e
				}
			case "firecracker":
				if e := r.directory(dir, name, name, 1, func(d *os.File, n []string) error {
					if !sameNames(n, []string{"config.json"}) {
						return ErrInventory
					}
					b, e := r.file(d, "config.json", name+"/config.json", 16384, false)
					if e != nil {
						return e
					}
					got, e := firecracker.DecodeInspectionConfig(b)
					if e != nil || !firecracker.InspectionConfigEqual(got, cfg) {
						return ErrConflict
					}
					return nil
				}); e != nil {
					return e
				}
			case "diagnostics":
				if e := r.directory(dir, name, name, 2, func(d *os.File, n []string) error {
					if !sameNames(n, []string{"events.ring", "logger.lock"}) {
						return ErrInventory
					}
					for _, file := range n {
						b, e := r.file(d, file, name+"/"+file, diagnostics.RingBytes, file == "logger.lock")
						if e != nil {
							return e
						}
						if file == "events.ring" {
							v, e := diagnostics.DecodePersistedSnapshot(stateDir+"/diagnostics", b)
							if e != nil {
								return e
							}
							r.view.DiagnosticSequence = v.ObservedSequence
						}
					}
					return nil
				}); e != nil {
					return e
				}
			default: // Only the closed three-name optional socket set passed above.
				before, e := r.entry(dir, name)
				if e != nil || before.Mode != unix.S_IFSOCK|0600 || before.Nlink != 1 {
					return ErrInventory
				}
				after, e := r.entry(dir, name)
				if e != nil || stateEntry(before) != stateEntry(after) {
					return ErrInventory
				}
				r.bind(name, before, nil)
				r.view.Sockets++
			}
		}
		return nil
	})
	if e != nil {
		return runtimeStateFootprint{}, e
	}
	r.view.digest = hex.EncodeToString(r.hash.Sum(nil))
	return r.view, nil
}

func (s *runtimeScope) inspectClosedState(ctx context.Context, base, operation string, stopped *runtimeStoppedWorkProof, m systemManager) (runtimeClosedStateInventory, error) {
	return s.inspectClosedStateWithProofs(ctx, base, operation, stopped, m, backendInspectionProofs{m.fs.unitExecutionEmpty, cgroup2FD, firecracker.InspectReservedProjects})
}

func (s *runtimeScope) inspectClosedStateWithProofs(ctx context.Context, base, operation string, stopped *runtimeStoppedWorkProof, m systemManager, proof backendInspectionProofs) (runtimeClosedStateInventory, error) {
	var out runtimeClosedStateInventory
	if _, bounded := ctx.Deadline(); !bounded || !digestPattern.MatchString(base) || !requestPattern.MatchString(operation) || stopped == nil || stopped.scope != s || proof.empty == nil || proof.cgroup == nil || proof.projects == nil {
		return out, ErrPolicy
	}
	e := s.run(ctx, func(f *filesystem) error {
		var first, last runtimeTerminalInventory
		if e := s.inspectClosedTerminalLocked(ctx, base, operation, stopped, m, proof.empty, f, &first); e != nil {
			return e
		}
		raw, e := f.read(Root+"/backend.json", 16384, 0600)
		if e != nil {
			return e
		}
		cfg, e := firecracker.DecodeInspectionConfig(raw)
		if e != nil || cfg.Snapshot != nil {
			return ErrInventory
		}
		raw, e = f.read(Root+"/launch.json", launch.MaxManifest, 0600)
		if e != nil {
			return e
		}
		manifest, e := launch.Decode(raw)
		if e != nil || manifest.StateDir != stateDir {
			return ErrInventory
		}
		before, e := readClosedStateRoot(ctx, s.state.root, cfg, manifest.Frontend.Metrics)
		if e != nil {
			return e
		}
		if e = f.point("runtime-closed-state-after-root"); e != nil {
			return e
		}
		var backend runtimeBackendInventory
		if e = s.inspectStoppedBackendLocked(ctx, base, operation, m, proof, f, &backend); e != nil {
			return e
		}
		if !backend.BackendResourcesAbsent || backend.Core != first.Core {
			return ErrConflict
		}
		if e = f.point("runtime-closed-state-after-backend"); e != nil {
			return e
		}
		if e = s.inspectClosedTerminalLocked(ctx, base, operation, stopped, m, proof.empty, f, &last); e != nil {
			return e
		}
		if first != last {
			return ErrConflict
		}
		if e = f.point("runtime-closed-state-after-terminal"); e != nil {
			return e
		}
		// Finish ALL manager/quota/cgroup callbacks BEFORE final raw state/source
		// reads. Repeat the absent cold namespaces after these observations.
		if e = s.closedBackendTail(ctx, cfg, proof); e != nil {
			return e
		}
		if e = s.closedDurableFiles(ctx, base, operation, stopped); e != nil {
			return e
		}
		after, e := readClosedStateRoot(ctx, s.state.root, cfg, manifest.Frontend.Metrics)
		if e != nil {
			return e
		}
		if before != after {
			return ErrConflict
		}
		out = runtimeClosedStateInventory{Terminal: last, Backend: backend, State: after, ClosedStateJoined: true}
		return nil
	})
	if e != nil {
		return runtimeClosedStateInventory{}, e
	}
	return out, nil
}

func (s *runtimeScope) closedBackendTail(ctx context.Context, cfg firecracker.Config, proof backendInspectionProofs) error {
	runtime, e := s.fs.directory(runtimeDir)
	if e != nil {
		return e
	}
	defer runtime.Close()
	var before, after unix.Stat_t
	if e = unix.Fstat(int(runtime.Fd()), &before); e != nil {
		return e
	}
	p, e := proof.projects(ctx, cfg, runtime, nil)
	if e != nil {
		return e
	}
	if p.Reserved != cfg.UIDCount || p.Owned != 0 || p.Empty != cfg.UIDCount || !p.AllReleased {
		return ErrConflict
	}
	g, node, e := inspectBackendGroups(ctx, s.fs, map[string]bool{}, proof.cgroup)
	if e != nil {
		return e
	}
	if g != 0 || node {
		return ErrConflict
	}
	if j, e := inspectJailNamespaces(ctx, s.fs, cfg, map[string]bool{}); e != nil || j != 0 {
		return ErrInventory
	}
	linked, e := s.fs.directory(runtimeDir)
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
	return ctx.Err()
}

// No manager/kernel-model callback after this final original source/WAL check.
func (s *runtimeScope) closedDurableFiles(ctx context.Context, base, operation string, stopped *runtimeStoppedWorkProof) error {
	f := s.fs
	return f.runtimeDrainLocked(ctx, func() error {
		_, drain, e := f.runtimeStopBase(ctx, base, operation)
		if e != nil {
			return e
		}
		p, e := f.readRuntimeStop()
		if e != nil || p.Version != 4 || p.State == nil || *p.State != s.state.id || digest(encode(p)) != stopped.stop || p.Close != stopped.closure || p.Work != stopped.completion || p.Main != drain.Process || p.Drain != digest(encode(drain)) {
			return ErrConflict
		}
		if e = f.stopInventory(&p); e != nil {
			return e
		}
		return f.exact(runtimeStopRoot+"/stopped.json", encode(runtimeStopReceipt{Version: 1, Input: stopped.stop}), 0600)
	})
}
