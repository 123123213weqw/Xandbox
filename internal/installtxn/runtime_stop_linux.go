//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const runtimeStopRoot = "/etc/xandbox-runtime-stop"

type runtimeStopReceipt struct {
	Version int    `json:"version"`
	Input   string `json:"intent_sha256"`
}
type runtimeStopResult struct {
	ExecutionStopped                                            bool
	AcceptedWorkComplete, ResourcesReclaimed, ActivationAllowed bool
}
type runtimeStopProofs struct {
	process func(context.Context, transaction, string, nodecontrol.ProcessIdentity) error
	empty   func(string) error
}

func validRuntimeStop(p runtimeStopIntent) bool {
	version := p.Close == "" && (p.Version == 1 && p.State == nil && p.Work == "" || p.Version == 2 && p.State != nil && p.State.valid() && p.Work == "" || p.Version == 3 && p.State != nil && p.State.valid() && digestPattern.MatchString(p.Work)) || p.Version == 4 && p.State != nil && p.State.valid() && digestPattern.MatchString(p.Work) && digestPattern.MatchString(p.Close)
	return version && digestPattern.MatchString(p.Base) && requestPattern.MatchString(p.Request) && digestPattern.MatchString(p.Drain) && p.Main.Valid() && (p.Ingress == nil || p.Ingress.Valid() && *p.Ingress != p.Main)
}
func (f *filesystem) readRuntimeStop() (runtimeStopIntent, error) {
	var p runtimeStopIntent
	b, e := f.read(runtimeStopRoot+"/intent.json", MaxPlan, 0600)
	if e != nil {
		return p, e
	}
	if strictjson.Decode(b, &p) != nil || !validRuntimeStop(p) || !bytes.Equal(b, encode(p)) {
		return p, ErrInventory
	}
	return p, nil
}
func (f *filesystem) stopInventory(p *runtimeStopIntent) error {
	if p != nil && p.Version == 4 {
		if e := f.closeStopLink(*p); e != nil {
			return e
		}
	}
	if p != nil && p.Version == 3 {
		if e := f.workStopLink(*p); e != nil {
			return e
		}
	}
	if p != nil && p.State != nil {
		if e := f.runtimeStateMatches(*p.State); e != nil {
			return e
		}
	}
	names, e := f.names(runtimeStopRoot)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	if e = f.privateDirectory(runtimeStopRoot, 0700); e != nil {
		return e
	}
	present := map[string]bool{}
	for _, n := range names {
		present[n] = true
	}
	for _, n := range names {
		if n != "intent.json" && n != ".intent.json.next" && n != "stopped.json" && n != ".stopped.json.next" {
			return ErrInventory
		}
		if p == nil {
			if n != ".intent.json.next" {
				return ErrInventory
			}
			continue
		}
		want := encode(*p)
		final := "intent.json"
		if n == "stopped.json" || n == ".stopped.json.next" {
			want = encode(runtimeStopReceipt{Version: 1, Input: digest(encode(*p))})
			final = "stopped.json"
		}
		if n[0] != '.' {
			if e = f.exact(runtimeStopRoot+"/"+n, want, 0600); e != nil {
				return e
			}
			continue
		}
		if present[final] {
			return ErrInventory
		}
		// The same bounded, read-only prefix contract as the drain WAL.
		in, e := f.open(runtimeStopRoot+"/"+n, unix.O_RDONLY, 0600)
		if e != nil {
			return e
		}
		b, err := io.ReadAll(io.LimitReader(in, int64(len(want))+1))
		in.Close()
		if err != nil {
			return err
		}
		if len(b) > len(want) || !bytes.HasPrefix(want, b) {
			return ErrInventory
		}
	}
	return nil
}
func (f *filesystem) runtimeStopBase(ctx context.Context, base, request string) (transaction, runtimeDrainIntent, error) {
	var zero transaction
	var drain runtimeDrainIntent
	t, e := f.runtimeBase(base)
	if e != nil {
		return zero, drain, e
	}
	if yes, e := f.exists(runtimeFilesRoot); e != nil {
		return zero, drain, e
	} else if yes {
		return zero, drain, ErrInventory
	}
	names, e := f.names(Root)
	if e != nil {
		return zero, drain, e
	}
	expected := append([]string{".lock", "commit.json"}, configNamesFor(t.Plan.Version)...)
	sort.Strings(expected)
	if !sameNames(names, expected) {
		return zero, drain, ErrInventory
	}
	if e = f.verifyTransaction(ctx, t); e != nil {
		return zero, drain, e
	}
	drain, e = f.runtimeDrainReadIntent()
	if e != nil {
		return zero, drain, e
	}
	if drain.Base != base || drain.Request != request {
		return zero, drain, ErrConflict
	}
	if e = f.runtimeDrainInventory(&drain); e != nil {
		return zero, drain, e
	}
	if e = f.exact(runtimeDrainRoot+"/drain.json", encode(runtimeDrainReceipt{Version: 1, Input: digest(encode(drain)), After: drainedRuntimeState(drain)}), 0600); e != nil {
		return zero, drain, e
	}
	return t, drain, nil
}

// Real production process proof: fixed /proc, exact committed image, argv and
// cgroup. It accepts neither a caller-selected proc root nor a stopped boolean.
func runtimeProcessProof(ctx context.Context, t transaction, unit string, id nodecontrol.ProcessIdentity) error {
	art, e := descriptor(t.Release)
	if e != nil {
		return e
	}
	if unit == IngressUnit {
		return policyProcessProof(ctx, id.PID, art["gateway"].SHA256)
	}
	if unit != MainUnit {
		return ErrPolicy
	}
	root := "/proc/" + strconv.Itoa(id.PID)
	b, e := boundedProcessFile(root+"/cgroup", 4096)
	if e != nil {
		return e
	}
	if strings.TrimSpace(string(b)) != "0::/system.slice/"+MainUnit+"/node/control" {
		return ErrInventory
	}
	b, e = boundedProcessFile(root+"/cmdline", 16384)
	if e != nil {
		return e
	}
	n := nodeManifest(t.Plan, art)
	if !bytes.Equal(b, []byte(strings.Join(n.Arguments(), "\x00")+"\x00")) {
		return ErrInventory
	}
	in, e := os.Open(root + "/exe")
	if e != nil {
		return e
	}
	defer in.Close()
	if e = trustedStat(int(in.Fd()), false, 0555); e != nil {
		return e
	}
	st, e := in.Stat()
	if e != nil {
		return e
	}
	if st.Size() < 1 || st.Size() > 64<<20 {
		return ErrInventory
	}
	sum, e := hashFile(ctx, in, st.Size())
	if e != nil {
		return e
	}
	if sum != art["daemon"].SHA256 {
		return ErrInventory
	}
	return nil
}

func (s *runtimeScope) stop(ctx context.Context, base, request string, client *nodecontrol.PinnedClient, m systemManager) (runtimeStopResult, error) {
	return s.stopWithProofs(ctx, base, request, client, m, runtimeStopProofs{process: runtimeProcessProof, empty: m.fs.unitExecutionEmpty})
}

// Private test seam models manager/image/placement/cgroups ONLY in test-owned
// roots. The production entry above always supplies fixed real kernel proofs.
// This stage requests physical termination, NOT successful work completion or
// full reclaim; no scope method permits selecting binaries using this result.
func (s *runtimeScope) stopWithProofs(ctx context.Context, base, request string, client *nodecontrol.PinnedClient, m systemManager, proof runtimeStopProofs) (runtimeStopResult, error) {
	var result runtimeStopResult
	if !digestPattern.MatchString(base) || !requestPattern.MatchString(request) || proof.process == nil || proof.empty == nil {
		return result, ErrPolicy
	}
	stage := proofStopScope
	e := s.run(ctx, func(f *filesystem) error {
		if m.fs != f {
			return ErrPolicy
		}
		var t transaction
		var drain runtimeDrainIntent
		var p runtimeStopIntent
		pending := false
		stage = proofStopInput
		if e := f.runtimeDrainLocked(ctx, func() error {
			var e error
			t, drain, e = f.runtimeStopBase(ctx, base, request)
			if e != nil {
				return e
			}
			p, e = f.readRuntimeStop()
			pending = e == nil
			if e != nil && !errors.Is(e, unix.ENOENT) {
				return e
			}
			var old *runtimeStopIntent
			if pending {
				old = &p
				if p.Base != base || p.Request != request || p.Drain != digest(encode(drain)) || p.Main != drain.Process {
					return ErrConflict
				}
			}
			return f.stopInventory(old)
		}); e != nil {
			return e
		}
		stage = proofStopEnabledLinks
		if e := m.enabledLinks(); e != nil {
			return e
		}
		observe := func(unit string) (observation, error) {
			o, e := m.observe(ctx, unit)
			if e != nil {
				return o, e
			}
			if !validManagedUnit(o, unit) {
				return o, ErrInventory
			}
			if o.pid > 1 && o.active == "active" || o.pid == 0 && (o.active == "inactive" || o.active == "failed") {
				return o, nil
			}
			return o, ErrInventory
		}
		stage = proofStopMainObservation
		main, e := observe(MainUnit)
		if e != nil {
			return e
		}
		stage = proofStopIngressObservation
		ingress, e := observe(IngressUnit)
		if e != nil {
			return e
		}
		checkDrain := func() error {
			if client == nil || client.Identity() != drain.Process {
				return ErrConflict
			}
			dir, e := f.directory(stateDir)
			if e != nil {
				return e
			}
			e = client.VerifyDirectory(dir)
			dir.Close()
			if e != nil {
				return e
			}
			return runtimeLiveDrain(ctx, drain, client)
		}
		if !pending {
			if main.pid != drain.Process.PID || main.active != "active" {
				return ErrConflict
			}
			stage = proofStopDrainPeer
			if e = checkDrain(); e != nil {
				return e
			}
			stage = proofStopStateOpen
			state, e := f.openRuntimeState()
			if e != nil {
				return e
			}
			id := state.id
			state.close()
			stage = proofStopOriginalStateOwner
			if e = f.runtimeStateOwnedBy(ctx, id, drain.Process); e != nil {
				return e
			}
			p = runtimeStopIntent{Version: 2, Base: base, Request: request, Drain: digest(encode(drain)), Main: drain.Process, State: &id}
			if ingress.pid > 1 {
				stage = proofStopIngressWatch
				w, e := nodecontrol.NewProcessWatch(ingress.pid)
				if e != nil {
					return e
				}
				id := w.Identity()
				w.Close()
				p.Ingress = &id
			}
			if !validRuntimeStop(p) {
				return ErrInventory
			}
		}
		stage = proofStopOriginalPeers
		ids := map[string]*nodecontrol.ProcessIdentity{MainUnit: &p.Main, IngressUnit: p.Ingress}
		watches := map[string]*nodecontrol.ProcessWatch{}
		defer func() {
			for _, w := range watches {
				w.Close()
			}
		}()
		for _, unit := range []string{MainUnit, IngressUnit} {
			o := main
			if unit == IngressUnit {
				o = ingress
			}
			id := ids[unit]
			if id == nil {
				if o.pid != 0 {
					return ErrConflict
				}
				continue
			}
			if o.pid != 0 && o.pid != id.PID {
				return ErrConflict
			}
			w, e := nodecontrol.NewProcessWatch(id.PID)
			if errors.Is(e, unix.ESRCH) {
				if !pending || o.pid != 0 {
					return ErrConflict
				}
				continue
			}
			if e != nil {
				return e
			}
			watches[unit] = w
			if w.Identity() != *id || o.pid != id.PID {
				return ErrConflict
			}
			stage = proofStopUnitProcess
			if e = proof.process(ctx, t, unit, *id); e != nil {
				return e
			}
			if e = w.Alive(); e != nil {
				return e
			}
		}
		stage = proofStopExistingReceipt
		for _, path := range []string{runtimeStopRoot + "/stopped.json", runtimeStopRoot + "/.stopped.json.next"} {
			if yes, err := f.exists(path); err != nil {
				return err
			} else if yes && (main.pid != 0 || ingress.pid != 0) {
				return ErrConflict
			}
		}
		if main.pid > 1 {
			stage = proofStopDrainPeer
			if e = checkDrain(); e != nil {
				return e
			}
			if p.State != nil {
				stage = proofStopPresignalStateOwner
				if e = f.runtimeStateOwnedBy(ctx, *p.State, p.Main); e != nil {
					return e
				}
			}
		}
		stage = proofStopIntentPersist
		if e = f.runtimeDrainLocked(ctx, func() error {
			if _, _, e := f.runtimeStopBase(ctx, base, request); e != nil {
				return e
			}
			if e := f.stopInventory(&p); e != nil {
				return e
			}
			if e := f.mkdir(runtimeStopRoot, 0700); e != nil {
				return e
			}
			return f.runtimeRecord(runtimeStopRoot+"/intent.json", nil, encode(p), "runtime-stop-intent")
		}); e != nil {
			return e
		}
		// Stop ingress before main, never propagate dependency jobs. Each stage
		// must prove process exit AND a real whole-subtree empty/unfrozen domain.
		for _, unit := range []string{IngressUnit, MainUnit} {
			stage = proofStopUnitObservation
			o, e := observe(unit)
			if e != nil {
				return e
			}
			id := ids[unit]
			w := watches[unit]
			if o.pid > 1 {
				if id == nil || w == nil || o.pid != id.PID {
					return ErrConflict
				}
				if e = w.Alive(); e != nil {
					return e
				}
				stage = proofStopUnitProcess
				if e = proof.process(ctx, t, unit, *id); e != nil {
					return e
				}
				// A foreign admission resume must be noticed before stopping
				// ingress too, not only before the later main-unit job.
				if main.pid > 1 {
					stage = proofStopDrainPeer
					if e = checkDrain(); e != nil {
						return e
					}
				}
				// A concurrent incarnation change in EITHER unit must not reach a
				// stop job, even when the other unit was the intended next stage.
				stage = proofStopOtherPeers
				for _, other := range []string{MainUnit, IngressUnit} {
					current, e := observe(other)
					if e != nil {
						return e
					}
					if current.pid > 1 {
						saved := ids[other]
						watch := watches[other]
						if saved == nil || watch == nil || current.pid != saved.PID {
							return ErrConflict
						}
						if e = watch.Alive(); e != nil {
							return e
						}
						if e = proof.process(ctx, t, other, *saved); e != nil {
							return e
						}
					}
				}
				stage = proofStopOperationScope
				if e = s.valid(ctx); e != nil {
					return e
				}
				if main.pid > 1 && p.State != nil {
					stage = proofStopPresignalStateOwner
					if e = f.runtimeStateOwnedBy(ctx, *p.State, p.Main); e != nil {
						return e
					}
				}
				stage = proofStopPresignalLinks
				if e = m.enabledLinks(); e != nil {
					return e
				}
				stage = proofStopPresignalAuthority
				if e = f.runtimeDrainLocked(ctx, func() error {
					if _, _, e := f.runtimeStopBase(ctx, base, request); e != nil {
						return e
					}
					if e := f.stopInventory(&p); e != nil {
						return e
					}
					return f.exact(runtimeStopRoot+"/intent.json", encode(p), 0600)
				}); e != nil {
					return e
				}
				stage = proofStopBeforeSignalCut
				if e = f.point("runtime-stop-before-" + unit); e != nil {
					return e
				}
				stage = proofStopManagerStop
				if _, e = m.command(ctx, []string{"--job-mode=ignore-dependencies", "stop", unit}); e != nil {
					return e
				}
				stage = proofStopAfterSignalCut
				if e = f.point("runtime-stop-after-" + unit); e != nil {
					return e
				}
			}
			stage = proofStopExitObservation
			o, e = observe(unit)
			if e != nil {
				return e
			}
			if o.pid != 0 {
				return ErrInventory
			}
			stage = proofStopExitWatch
			if w != nil {
				dead, e := w.Exited()
				if e != nil {
					return e
				}
				if !dead {
					return ErrInventory
				}
			}
			stage = proofStopEmptyDomain
			if e = proof.empty(unit); e != nil {
				return e
			}
		}
		stage = proofStopEmptyCut
		if e = f.point("runtime-stop-domains-empty"); e != nil {
			return e
		}
		stage = proofStopReceiptPersist
		if e = f.runtimeDrainLocked(ctx, func() error {
			if _, _, e := f.runtimeStopBase(ctx, base, request); e != nil {
				return e
			}
			if e := f.stopInventory(&p); e != nil {
				return e
			}
			if e := f.exact(runtimeStopRoot+"/intent.json", encode(p), 0600); e != nil {
				return e
			}
			return f.runtimeRecord(runtimeStopRoot+"/stopped.json", nil, encode(runtimeStopReceipt{Version: 1, Input: digest(encode(p))}), "runtime-stop-receipt")
		}); e != nil {
			return e
		}
		// A receipt is not a cached kernel observation; recheck both domains.
		for _, unit := range []string{IngressUnit, MainUnit} {
			stage = proofStopUnitObservation
			o, e := observe(unit)
			if e != nil {
				return e
			}
			if o.pid != 0 {
				return ErrConflict
			}
			stage = proofStopEmptyDomain
			if e = proof.empty(unit); e != nil {
				return e
			}
			if w := watches[unit]; w != nil {
				dead, e := w.Exited()
				if e != nil {
					return e
				}
				if !dead {
					return ErrInventory
				}
			}
		}
		result.ExecutionStopped = true
		return nil
	})
	if e != nil {
		return runtimeStopResult{}, runtimeProofFailure(stage, e)
	}
	return result, nil
}
