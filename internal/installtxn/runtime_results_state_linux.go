//go:build linux

package installtxn

import (
	"context"
	"errors"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"golang.org/x/sys/unix"
)

// Current complete disk/result observations joined to the authentic original
// V2 closure, physical Stop and SAME retained state FD. This is an observation,
// not a portable file-consumer capability, full reclaim or activation right.
// No serialized report, legacy stopped proof or unbound reader can enter it.
type runtimeResultsStateInventory struct {
	Retained                                   runtimeRetainedStateInventory
	BackendResourcesAbsent, ResultsStateJoined bool
	ResourcesReclaimed, ActivationAllowed      bool
}

type resultsStateSource struct {
	stop    runtimeResultsStopIntent
	drain   runtimeDrainIntent
	closure runtimeResultsCloseCompletion
}

// Caller holds s.mu and the original operation EX. Only bounded read-only file
// work is under the existing file flock; no manager/kernel callback is hidden
// here, and no new controller.lock descriptor is retained or flocked.
func (s *runtimeScope) readResultsStateSource(ctx context.Context, base, operation string, p *runtimeResultsStoppedWorkProof) (resultsStateSource, error) {
	var zero, out resultsStateSource
	e := s.fs.runtimeDrainLocked(ctx, func() error {
		ok, e := s.fs.readResultsStopRecord("intent.json", &out.stop)
		if e != nil || !ok {
			return ErrInventory
		}
		q := out.stop
		if !q.valid() || q.Plan.Base != base || q.Plan.Request != operation || q.Plan.State == nil || *q.Plan.State != p.state || p.closed.state != p.state || q.WorkIntent != p.closed.intent || q.Work != p.closed.work || q.Closure != p.closed.closure || digest(encode(q)) != p.stop {
			return ErrConflict
		}
		if e = s.fs.resultsStopInventory(ctx, q); e != nil {
			return e
		}
		if e = s.fs.exact(runtimeResultsStopRoot+"/intent.json", encode(q), 0600); e != nil {
			return e
		}
		if e = s.fs.exact(runtimeResultsStopRoot+"/stopped.json", encode(runtimeResultsStopReceipt{Version: 1, Input: p.stop}), 0600); e != nil {
			return e
		}
		ok, e = s.fs.readResultsCloseRecord("complete.json", &out.closure)
		if e != nil || !ok || out.closure != p.closed.observation {
			return ErrConflict
		}
		out.drain, e = s.fs.runtimeDrainReadIntent()
		if e != nil {
			return e
		}
		if !validRuntimeMaintenance(out.drain) || out.drain.Maintenance == nil || out.drain.Base != base || out.drain.Request != operation || q.Plan.Drain != digest(encode(out.drain)) || q.Plan.Main != out.drain.Process {
			return ErrConflict
		}
		return nil
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}

// Fixed pidfd-only tail after ALL injectable manager/kernel observations. An
// existing/reused PID or uncertain watch is never absence, and is never killed.
func resultsStateOriginalsExited(p runtimeResultsStopIntent) error {
	for _, id := range []*nodecontrol.ProcessIdentity{&p.Plan.Main, p.Plan.Ingress} {
		if id == nil {
			continue
		}
		w, e := nodecontrol.NewProcessWatch(id.PID)
		if errors.Is(e, unix.ESRCH) {
			continue
		}
		if w != nil {
			w.Close()
		}
		if e != nil {
			return e
		}
		return ErrConflict
	}
	return nil
}

func (s *runtimeScope) inspectResultsStoppedState(ctx context.Context, base, operation string, p *runtimeResultsStoppedWorkProof, m systemManager) (runtimeResultsStateInventory, error) {
	return s.inspectResultsStoppedStateWithProofs(ctx, base, operation, p, m, backendInspectionProofs{m.fs.unitExecutionEmpty, cgroup2FD, firecracker.InspectReservedProjects})
}

// Private seams cover ONLY manager and kernel domains, never the receipt,
// state ownership, actual V2 actor provenance or complete byte/semantic reader.
// No callback executes after the final source/root/FD/pidfd tail begins.
func (s *runtimeScope) inspectResultsStoppedStateWithProofs(ctx context.Context, base, operation string, p *runtimeResultsStoppedWorkProof, m systemManager, proof backendInspectionProofs) (runtimeResultsStateInventory, error) {
	var zero, out runtimeResultsStateInventory
	if _, bounded := ctx.Deadline(); !bounded || !digestPattern.MatchString(base) || !requestPattern.MatchString(operation) || p == nil || p.scope != s || p.closed.scope != s || proof.empty == nil || proof.cgroup == nil || proof.projects == nil {
		return zero, ErrPolicy
	}
	e := s.run(ctx, func(f *filesystem) error {
		if m.fs != f {
			return ErrPolicy
		}
		first, e := s.readResultsStateSource(ctx, base, operation, p)
		if e != nil {
			return e
		}
		if e = s.resultsStateLeaseHeld(ctx, p.state); e != nil {
			return e
		}
		if e = s.resultsStoppedStateProof(ctx, first.stop, m, proof.empty); e != nil {
			return e
		}
		if _, e = s.readResultsStateSource(ctx, base, operation, p); e != nil {
			return e
		}
		raw, e := f.read(Root+"/backend.json", 16384, 0600)
		if e != nil {
			return e
		}
		cfg, e := firecracker.DecodeInspectionConfig(raw)
		if e != nil || cfg.Snapshot != nil || cfg.Version != 3 || cfg.RuntimeRoot != runtimeDir || cfg.CgroupRoot != unitRoot+"/node/instances" || cfg.Node == nil || cfg.Quota == nil || cfg.IO == nil {
			return ErrInventory
		}
		backendDigest := digest(raw)
		raw, e = f.read(Root+"/launch.json", launch.MaxManifest, 0600)
		if e != nil {
			return e
		}
		manifest, e := launch.Decode(raw)
		if e != nil || manifest.StateDir != stateDir || manifest.Backend.Path != Root+"/backend.json" || manifest.Backend.SHA256 != backendDigest {
			return ErrInventory
		}
		lease := *first.drain.Maintenance
		read := func() (runtimeRetainedStateInventory, error) {
			return readClosedRetainedStateRoot(ctx, s.state.root, cfg, manifest.Frontend.Metrics, lease, first.closure.Core, first.closure.Sessions)
		}
		before, e := read()
		if e != nil {
			return e
		}
		if e = f.point("runtime-results-state-after-root"); e != nil {
			return e
		}
		// Complete root demands only the cold config (NO ownership records) and
		// destroyed/closed ledger/session sets. This stricter absent-resource
		// path checks the SAME existing cold jail/cgroup/reserved quota readers,
		// without converting new authority into a legacy backend/Stop proof.
		if e = s.resultsColdBackendAbsent(ctx, cfg, proof); e != nil {
			return e
		}
		if e = f.point("runtime-results-state-after-backend"); e != nil {
			return e
		}
		if e = s.resultsStoppedStateProof(ctx, first.stop, m, proof.empty); e != nil {
			return e
		}
		if e = f.point("runtime-results-state-after-peer"); e != nil {
			return e
		}
		if e = s.resultsColdBackendAbsent(ctx, cfg, proof); e != nil {
			return e
		}
		if e = f.point("runtime-results-state-before-final-root"); e != nil {
			return e
		}
		// NO manager/kernel-model callback or mutation after this boundary.
		last, e := s.readResultsStateSource(ctx, base, operation, p)
		if e != nil {
			return e
		}
		if last.closure != first.closure || digest(encode(last.drain)) != digest(encode(first.drain)) {
			return ErrConflict
		}
		if e = s.resultsStateLeaseHeld(ctx, p.state); e != nil {
			return e
		}
		if e = resultsStateOriginalsExited(last.stop); e != nil {
			return e
		}
		after, e := read()
		if e != nil {
			return e
		}
		if after != before {
			return ErrConflict
		}
		if e = s.resultsStateLeaseHeld(ctx, p.state); e != nil {
			return e
		}
		if e = resultsStateOriginalsExited(last.stop); e != nil {
			return e
		}
		out = runtimeResultsStateInventory{Retained: after, BackendResourcesAbsent: true, ResultsStateJoined: true}
		return nil
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}

func (s *runtimeScope) resultsColdBackendAbsent(ctx context.Context, cfg firecracker.Config, proof backendInspectionProofs) error {
	root, e := s.fs.directory(runtimeDir)
	if e != nil {
		return e
	}
	defer root.Close()
	var a, b unix.Stat_t
	if e = unix.Fstat(int(root.Fd()), &a); e != nil {
		return e
	}
	if e = unix.Fstat(int(s.state.root.Fd()), &b); e != nil {
		return e
	}
	if a.Dev != b.Dev {
		return ErrInventory
	}
	return s.closedBackendTail(ctx, cfg, proof)
}
