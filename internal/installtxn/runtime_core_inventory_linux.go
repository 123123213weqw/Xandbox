//go:build linux

package installtxn

import (
	"context"
	"io"
	"os"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

// This reports ONLY parsed admission/ledger/session disk authority. Never full
// state-root inventory, task success, quota release, kernel or shared-catalog GC.
type runtimeCoreInventory struct {
	LedgerRecords, LedgerNonterminal                            int
	SessionRecords, SessionNonterminal, UnboundFailedTargets    int
	CoreAuthorityParsed                                         bool
	AcceptedWorkComplete, ResourcesReclaimed, ActivationAllowed bool
}
type coreGeneration struct{ tenant string }

func sameCoreStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func readCoreRecord(ctx context.Context, dir *os.File, name string, limit int) ([]byte, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	fd, e := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	in := os.NewFile(uintptr(fd), "runtime-core-record")
	defer in.Close()
	if e = trustedStat(fd, false, 0600); e != nil {
		return nil, e
	}
	var before, after, current unix.Stat_t
	if e = unix.Fstat(fd, &before); e != nil {
		return nil, e
	}
	if before.Size < 1 || before.Size > int64(limit) {
		return nil, ErrInventory
	}
	b, e := io.ReadAll(io.LimitReader(in, int64(limit)+1))
	if e != nil {
		return nil, e
	}
	if len(b) != int(before.Size) {
		return nil, ErrInventory
	}
	if e = unix.Fstat(fd, &after); e != nil {
		return nil, e
	}
	if e = unix.Fstatat(int(dir.Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return nil, e
	}
	if !sameCoreStat(before, after) || !sameCoreStat(after, current) {
		return nil, ErrInventory
	}
	return b, ctx.Err()
}

// Stream bounded directory pages/one bounded file at a time; do not call the
// effectful ordinary constructors/loaders. Any temp/unknown entry refuses,
// leaving its bytes intact. The ordinary hard schema ceilings are unchanged.
func scanCoreDirectory(ctx context.Context, f *filesystem, path string, max, limit int, visit func(string, []byte) error) error {
	dir, e := f.directory(path)
	if e != nil {
		return e
	}
	defer dir.Close()
	if e = trustedStat(int(dir.Fd()), true, 0700); e != nil {
		return e
	}
	var before, after unix.Stat_t
	if e = unix.Fstat(int(dir.Fd()), &before); e != nil {
		return e
	}
	seen := map[string]bool{}
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		names, err := dir.Readdirnames(128)
		if err != nil && err != io.EOF {
			return err
		}
		for _, name := range names {
			if len(seen) >= max || len(name) != 37 || name[32:] != ".json" || !requestPattern.MatchString(name[:32]) || seen[name] {
				return ErrInventory
			}
			seen[name] = true
			b, e := readCoreRecord(ctx, dir, name, limit)
			if e != nil {
				return e
			}
			if e = visit(name[:32], b); e != nil {
				return e
			}
		}
		if err == io.EOF {
			break
		}
	}
	if e = unix.Fstat(int(dir.Fd()), &after); e != nil {
		return e
	}
	if !sameCoreStat(before, after) {
		return ErrInventory
	}
	linked, e := f.directory(path)
	if e != nil {
		return e
	}
	defer linked.Close()
	var current unix.Stat_t
	if e = unix.Fstat(int(linked.Fd()), &current); e != nil {
		return e
	}
	if !sameCoreStat(after, current) {
		return ErrInventory
	}
	return ctx.Err()
}

func readCoreAdmission(ctx context.Context, f *filesystem, expected nodecontrol.State) error {
	dir, e := f.directory("/admission")
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
	names, e := dir.Readdirnames(2)
	if e != nil && e != io.EOF {
		return e
	}
	if !sameNames(names, []string{"state.json"}) {
		return ErrInventory
	}
	b, e := readCoreRecord(ctx, dir, "state.json", nodecontrol.StateLimit)
	if e != nil {
		return e
	}
	var state nodecontrol.State
	if strictjson.Decode(b, &state) != nil || !state.Valid() || state != expected || state.Mode != nodecontrol.ModeDrained {
		return ErrConflict
	}
	// Root-level file is opened RELATIVE to the held state FD. Do not relax the
	// install filesystem's global canonical-path policy to accept a slash root.
	b, e = readCoreRecord(ctx, f.root, "admission.identity", nodecontrol.StateLimit)
	if e != nil {
		return e
	}
	var id struct {
		Version int    `json:"version"`
		Epoch   string `json:"epoch"`
	}
	if strictjson.Decode(b, &id) != nil || id.Version != 1 || id.Epoch != state.Epoch {
		return ErrConflict
	}
	if e = unix.Fstat(int(dir.Fd()), &after); e != nil {
		return e
	}
	linked, e := f.directory("/admission")
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

func (s *runtimeScope) inspectStoppedCore(ctx context.Context, base, request string, m systemManager) (runtimeCoreInventory, error) {
	return s.inspectStoppedCoreWithProof(ctx, base, request, m, m.fs.unitExecutionEmpty)
}

// Private positive models cover image/manager/cgroups only; real BSD state lock,
// immutable identity, disk schemas and cross-record joins are never bypassed.
func (s *runtimeScope) inspectStoppedCoreWithProof(ctx context.Context, base, request string, m systemManager, empty func(string) error) (runtimeCoreInventory, error) {
	var out runtimeCoreInventory
	if !digestPattern.MatchString(base) || !requestPattern.MatchString(request) {
		return out, ErrPolicy
	}
	e := s.run(ctx, func(f *filesystem) error {
		if s.state == nil {
			return ErrConflict
		}
		p, e := s.stoppedStateProof(ctx, base, request, m, empty)
		if e != nil {
			return e
		}
		if p.State == nil || s.state.id != *p.State {
			return ErrConflict
		}
		drain, e := f.runtimeDrainReadIntent()
		if e != nil {
			return e
		}
		stateFS := &filesystem{root: s.state.root}
		if e = readCoreAdmission(ctx, stateFS, drainedRuntimeState(drain)); e != nil {
			return e
		}
		generations := map[sandbox.Ref]coreGeneration{}
		keys := map[string]bool{}
		e = scanCoreDirectory(ctx, stateFS, "/ledger", sandbox.MaxLedgerRecords, sandbox.MaxLedgerRecordBytes, func(id string, b []byte) error {
			r, e := sandbox.DecodePersistedRecord(b)
			if e != nil {
				return e
			}
			if r.ID != id || r.Backend != "firecracker" {
				return ErrInventory
			}
			if _, yes := generations[r.Ref]; yes {
				return ErrInventory
			}
			if r.CreateKeyHash != "" {
				k := r.TenantID + "\x00" + r.CreateKeyHash
				if keys[k] {
					return ErrInventory
				}
				keys[k] = true
			}
			generations[r.Ref] = coreGeneration{r.TenantID}
			out.LedgerRecords++
			if r.State != sandbox.Destroyed {
				out.LedgerNonterminal++
			}
			return nil
		})
		if e != nil {
			return e
		}
		keys = map[string]bool{}
		e = scanCoreDirectory(ctx, stateFS, "/sessions", session.MaxRecords, session.MaxRecordBytes, func(id string, b []byte) error {
			r, e := session.DecodePersistedRecord(b)
			if e != nil {
				return e
			}
			k := r.TenantID + "\x00" + r.CreateKeyHash
			if r.ID != id || keys[k] {
				return ErrInventory
			}
			keys[k] = true
			owns := func(ref sandbox.Ref) bool { return ref == (sandbox.Ref{}) || generations[ref].tenant == r.TenantID }
			if !owns(r.Current) {
				return ErrInventory
			}
			for _, a := range r.Attempts {
				if !owns(a.From) {
					return ErrInventory
				}
				if !owns(a.Target) {
					if a.State != "FAILED" {
						return ErrInventory
					}
					out.UnboundFailedTargets++
				}
			}
			out.SessionRecords++
			if r.State != session.Closed {
				out.SessionNonterminal++
			}
			return nil
		})
		if e != nil {
			return e
		}
		if e = readCoreAdmission(ctx, stateFS, drainedRuntimeState(drain)); e != nil {
			return e
		}
		if e = s.state.verify(f); e != nil {
			return e
		}
		if _, e = s.stoppedStateProof(ctx, base, request, m, empty); e != nil {
			return e
		}
		out.CoreAuthorityParsed = true
		return nil
	})
	if e != nil {
		return runtimeCoreInventory{}, e
	}
	return out, nil
}
