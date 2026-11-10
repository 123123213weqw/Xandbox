package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

// ClosureObservation binds the actual durably closed journal records of ONE
// broker. It is NOT resource reclaim, work success or a raw disk certificate.
type ClosureObservation struct {
	Version       int    `json:"version"`
	Records       int    `json:"records"`
	RecordsSHA256 string `json:"records_sha256"`
}

func (o ClosureObservation) Valid() bool {
	return o.Version == 1 && o.Records >= 0 && o.Records <= MaxRecords && hashPattern.MatchString(o.RecordsSHA256)
}

type ClosureProof struct {
	owner       *Broker
	core        *sandbox.Manager
	observation ClosureObservation
}

func (p *ClosureProof) For(b *Broker, m *sandbox.Manager) bool {
	return p != nil && b != nil && m != nil && p.owner == b && p.core == m && b.Uses(m) && p.observation.Valid()
}
func (p *ClosureProof) Observation() ClosureObservation {
	if p == nil {
		return ClosureObservation{}
	}
	return p.observation
}

// ClosedProof requires the actual close fence, finished mutation/journal actor,
// no routing/busy/dirty entry and validated terminal records, never a count.
func (b *Broker) ClosedProof(ctx context.Context) (*ClosureProof, error) {
	if b == nil {
		return nil, sandbox.ErrNotReady
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	select {
	case <-b.done:
	default:
		return nil, sandbox.ErrNotReady
	}
	b.mu.Lock()
	closing := b.closing
	b.mu.Unlock()
	if !closing || !b.fencesInstalled.Load() || b.ops.Load() != 0 {
		return nil, sandbox.ErrNotReady
	}
	items := b.all()
	sort.Slice(items, func(i, j int) bool { return items[i].record.ID < items[j].record.ID })
	h := sha256.New()
	_, _ = h.Write([]byte("xandbox-session-closure-v1\n"))
	encoder := json.NewEncoder(h)
	for _, entry := range items {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		entry.mu.Lock()
		r := clone(entry.record)
		clear := !entry.busy && !entry.dirty && entry.closed.Load() && entry.route.Load() == nil
		entry.mu.Unlock()
		if !clear || r.State != Closed || validate(r) != nil {
			return nil, sandbox.ErrNotReady
		}
		for _, a := range r.Attempts {
			if a.State != "COMMITTED" && a.State != "FAILED" {
				return nil, sandbox.ErrNotReady
			}
		}
		if e := encoder.Encode(r); e != nil {
			return nil, e
		}
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	return &ClosureProof{owner: b, core: b.core, observation: ClosureObservation{Version: 1, Records: len(items), RecordsSHA256: hex.EncodeToString(h.Sum(nil))}}, nil
}
