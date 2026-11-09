//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sort"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const runtimeDrainRoot = "/etc/xandbox-runtime-drain"

type runtimeDrainIntent struct {
	Version int                         `json:"version"`
	Base    string                      `json:"base_commit_sha256"`
	Request string                      `json:"request_id"`
	Process nodecontrol.ProcessIdentity `json:"process"`
	Before  nodecontrol.State           `json:"before"`
}
type runtimeDrainReceipt struct {
	Version int               `json:"version"`
	Input   string            `json:"intent_sha256"`
	After   nodecontrol.State `json:"after"`
}
type runtimeDrainResult struct {
	AdmissionDrained bool
	WasOpen          bool
	Revision         uint64
	// Deliberately never certified by an admission ACK or resource counters.
	AcceptedWorkComplete, StopObserved, ResourcesReclaimed, ActivationAllowed bool
}

func validRuntimeDrain(p runtimeDrainIntent) bool {
	return p.Version == 1 && digestPattern.MatchString(p.Base) && requestPattern.MatchString(p.Request) && p.Process.Valid() && p.Before.Valid() && p.Request != p.Before.LastRequestID
}
func drainedRuntimeState(p runtimeDrainIntent) nodecontrol.State {
	if p.Before.Mode == nodecontrol.ModeDrained {
		return p.Before
	}
	return nodecontrol.State{Version: 1, Epoch: p.Before.Epoch, Revision: p.Before.Revision + 1, Mode: nodecontrol.ModeDrained, LastRequestID: p.Request, LastExpectedRevision: p.Before.Revision}
}
func runtimeDrainStatus(s nodecontrol.Status, expected nodecontrol.State) bool {
	return s.Phase == "ready" && s.PendingRequestID == "" && s.Committed == expected && s.DesiredMode == expected.Mode && s.AdmissionOpen == (expected.Mode == nodecontrol.ModeOpen)
}

// The current adapter admits only a clean, genesis-pinned running installation.
// Repeated activation on an overlay needs its own durable activation protocol;
// a fenced file selection must NOT be mistaken for a running runtime release.
func (f *filesystem) runtimeDrainBase(ctx context.Context, base string, client *nodecontrol.PinnedClient) error {
	t, e := f.runtimeBase(base)
	if e != nil {
		return e
	}
	if yes, e := f.exists(runtimeFilesRoot); e != nil {
		return e
	} else if yes {
		return ErrInventory
	}
	names, e := f.names(Root)
	if e != nil {
		return e
	}
	expected := append([]string{".lock", "commit.json"}, configNamesFor(t.Plan.Version)...)
	sort.Strings(expected)
	if !sameNames(names, expected) {
		return ErrInventory
	}
	if e = f.verifyTransaction(ctx, t); e != nil {
		return e
	}
	dir, e := f.directory(stateDir)
	if e != nil {
		return e
	}
	defer dir.Close()
	if e = trustedStat(int(dir.Fd()), true, 0700); e != nil {
		return e
	}
	return client.VerifyDirectory(dir)
}
func (f *filesystem) runtimeDrainReadIntent() (runtimeDrainIntent, error) {
	var p runtimeDrainIntent
	b, e := f.read(runtimeDrainRoot+"/intent.json", MaxPlan, 0600)
	if e != nil {
		return p, e
	}
	if strictjson.Decode(b, &p) != nil || !validRuntimeDrain(p) || !bytes.Equal(b, encode(p)) {
		return p, ErrInventory
	}
	return p, nil
}
func (f *filesystem) runtimeDrainInventory(p *runtimeDrainIntent) error {
	names, e := f.names(runtimeDrainRoot)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	if e = f.privateDirectory(runtimeDrainRoot, 0700); e != nil {
		return e
	}
	present := map[string]bool{}
	for _, n := range names {
		present[n] = true
	}
	for _, n := range names {
		if n != "intent.json" && n != ".intent.json.next" && n != "drain.json" && n != ".drain.json.next" {
			return ErrInventory
		}
		if p == nil {
			if n != ".intent.json.next" {
				return ErrInventory
			}
			continue // Its exact input prefix is checked once the input is known.
		}
		want := encode(*p)
		if n == "drain.json" || n == ".drain.json.next" {
			want = encode(runtimeDrainReceipt{Version: 1, Input: digest(encode(*p)), After: drainedRuntimeState(*p)})
		}
		if n[0] != '.' {
			if e := f.exact(runtimeDrainRoot+"/"+n, want, 0600); e != nil {
				return e
			}
			continue
		}
		final := "intent.json"
		if n == ".drain.json.next" {
			final = "drain.json"
		}
		if present[final] {
			return ErrInventory
		}
		in, e := f.open(runtimeDrainRoot+"/"+n, unix.O_RDONLY, 0600)
		if e != nil {
			return e
		}
		b, e := io.ReadAll(io.LimitReader(in, int64(len(want))+1))
		in.Close()
		if e != nil {
			return e
		}
		if len(b) > len(want) || !bytes.HasPrefix(want, b) {
			return ErrInventory
		}
	}
	return nil
}
func (f *filesystem) runtimeDrainLocked(ctx context.Context, work func() error) error {
	done, e := f.existingLock(ctx, true)
	if e != nil {
		return e
	}
	defer done()
	return work()
}

// runtimeDrainAdmission is INTERNAL effectful write-ahead admission drain, not
// a public updater, Stop/reclaim operation or a lifecycle/activation certificate.
// Original operation EX spans RPC and persistence, but NO file flock spans RPC.
// Never invoke it inside another operation-lock scope: the complete coordinator
// still needs an owned scope adapter before composing it with the file engine.
// Existing stopped callbacks, manager/executable/placement proof and all-authority
// compatibility remain separate prerequisites, not booleans this method accepts.
func (f *filesystem) runtimeDrainAdmission(ctx context.Context, base, request string, client *nodecontrol.PinnedClient) (runtimeDrainResult, error) {
	var zero runtimeDrainResult
	if !digestPattern.MatchString(base) || !requestPattern.MatchString(request) || client == nil || !client.Identity().Valid() {
		return zero, ErrPolicy
	}
	if e := ctx.Err(); e != nil {
		return zero, e
	}
	done, e := f.operationLock(ctx, true)
	if e != nil {
		return zero, e
	}
	defer done()
	var p runtimeDrainIntent
	pending := false
	e = f.runtimeDrainLocked(ctx, func() error {
		if e := f.runtimeDrainBase(ctx, base, client); e != nil {
			return e
		}
		var err error
		p, err = f.runtimeDrainReadIntent()
		pending = err == nil
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
		if pending && (p.Base != base || p.Request != request || p.Process != client.Identity()) {
			return ErrConflict
		}
		var prior *runtimeDrainIntent
		if pending {
			prior = &p
		}
		return f.runtimeDrainInventory(prior)
	})
	if e != nil {
		return zero, e
	}
	if !pending {
		// Read-only RPC before write-ahead intent. Any mutation waits for fsync.
		r, err := client.Status(ctx)
		if err != nil {
			return zero, err
		}
		if !runtimeDrainStatus(r.Control, r.Control.Committed) {
			return zero, ErrConflict
		}
		p = runtimeDrainIntent{Version: 1, Base: base, Request: request, Process: client.Identity(), Before: r.Control.Committed}
		if !validRuntimeDrain(p) {
			return zero, ErrPolicy
		}
	}
	e = f.runtimeDrainLocked(ctx, func() error {
		if e := f.runtimeDrainBase(ctx, base, client); e != nil {
			return e
		}
		if e := f.runtimeDrainInventory(&p); e != nil {
			return e
		}
		if e := f.mkdir(runtimeDrainRoot, 0700); e != nil {
			return e
		}
		return f.runtimeRecord(runtimeDrainRoot+"/intent.json", nil, encode(p), "runtime-drain-intent")
	})
	if e != nil {
		return zero, e
	}
	// Recheck live state after durable intent. Foreign node operations do not
	// share the installer lock; they must conflict, never be overwritten/resumed.
	r, e := client.Status(ctx)
	if e != nil {
		return zero, e
	}
	want := drainedRuntimeState(p)
	if !runtimeDrainStatus(r.Control, want) {
		// Receipt bytes cannot authorize replay after authority apparently went
		// backwards. Even a matching prefix is inconsistent with original/open.
		for _, path := range []string{runtimeDrainRoot + "/drain.json", runtimeDrainRoot + "/.drain.json.next"} {
			if yes, err := f.exists(path); err != nil {
				return zero, err
			} else if yes {
				return zero, ErrConflict
			}
		}
		if !runtimeDrainStatus(r.Control, p.Before) || p.Before.Mode != nodecontrol.ModeOpen {
			return zero, ErrConflict
		}
		if e = f.point("runtime-drain-before-rpc"); e != nil {
			return zero, e
		}
		r, e = client.Drain(ctx, nodecontrol.Command{Version: 1, Epoch: p.Before.Epoch, ExpectedRevision: p.Before.Revision, RequestID: p.Request})
		if e != nil {
			return zero, e
		}
		if e = f.point("runtime-drain-after-rpc"); e != nil {
			return zero, e
		}
	}
	if !runtimeDrainStatus(r.Control, want) {
		return zero, ErrConflict
	}
	r, e = client.Status(ctx)
	if e != nil {
		return zero, e
	}
	if !runtimeDrainStatus(r.Control, want) {
		return zero, ErrConflict
	}
	receipt := runtimeDrainReceipt{Version: 1, Input: digest(encode(p)), After: want}
	e = f.runtimeDrainLocked(ctx, func() error {
		if e := f.runtimeDrainBase(ctx, base, client); e != nil {
			return e
		}
		if e := f.runtimeDrainInventory(&p); e != nil {
			return e
		}
		if e := f.exact(runtimeDrainRoot+"/intent.json", encode(p), 0600); e != nil {
			return e
		}
		return f.runtimeRecord(runtimeDrainRoot+"/drain.json", nil, encode(receipt), "runtime-drain-receipt")
	})
	if e != nil {
		return zero, e
	}
	// A stored receipt is never a substitute for a live current-state query.
	r, e = client.Status(ctx)
	if e != nil {
		return zero, e
	}
	if !runtimeDrainStatus(r.Control, want) {
		return zero, ErrConflict
	}
	return runtimeDrainResult{AdmissionDrained: true, WasOpen: p.Before.Mode == nodecontrol.ModeOpen, Revision: want.Revision}, nil
}
