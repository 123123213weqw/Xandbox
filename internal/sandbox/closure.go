package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// ClosureObservation binds the terminal records of ONE live Manager after its
// real Stop/Cleanup/durable DESTROYED paths and pools finished. This is semantic
// record binding, NOT a raw disk snapshot or whole-host/quota/catalog proof.
type ClosureObservation struct {
	Version       int    `json:"version"`
	Records       int    `json:"records"`
	RecordsSHA256 string `json:"records_sha256"`
}

func (o ClosureObservation) Valid() bool {
	return o.Version == 1 && o.Records >= 0 && o.Records <= 100_000 && hashPattern.MatchString(o.RecordsSHA256)
}

type ClosureProof struct {
	owner       *Manager
	observation ClosureObservation
}

func (p *ClosureProof) For(m *Manager) bool {
	return p != nil && m != nil && p.owner == m && p.observation.Valid()
}
func (p *ClosureProof) Observation() ClosureObservation {
	if p == nil {
		return ClosureObservation{}
	}
	return p.observation
}
func (m *Manager) UsesAdmissionGate(g *AdmissionGate) bool {
	return m != nil && g != nil && m.opts.AdmissionGate == g
}

// ClosedProof never uses Stats or LifecycleDone alone. No I/O/repair/backend
// constructor is performed here. The frozen work barrier must already have
// observed actual terminal success; cancelled/unknown/unfinished calls refuse.
func (m *Manager) ClosedProof(ctx context.Context) (*ClosureProof, error) {
	if m == nil || !m.opts.AdmissionGate.AcceptedWorkStatus().Complete() {
		return nil, ErrNotReady
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	select {
	case <-m.workerDone:
	default:
		return nil, ErrNotReady
	}
	m.mu.Lock()
	if !m.closing || len(m.active) != 0 {
		m.mu.Unlock()
		return nil, ErrNotReady
	}
	ids := make([]string, 0, len(m.records))
	items := make(map[string]*instance, len(m.records))
	for id, i := range m.records {
		ids = append(ids, id)
		items[id] = i
	}
	m.mu.Unlock()
	sort.Strings(ids)
	h := sha256.New()
	_, _ = h.Write([]byte("xandbox-core-closure-v1\n"))
	encoder := json.NewEncoder(h)
	for _, id := range ids {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		i := items[id]
		i.mu.Lock()
		r := i.record
		clear := i.running == 0 && i.prepareCancel == nil && len(i.jobs) == 0
		i.mu.Unlock()
		if !clear || r.State != Destroyed || validateRecord(r) != nil {
			return nil, ErrNotReady
		}
		if e := encoder.Encode(r); e != nil {
			return nil, e
		}
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	return &ClosureProof{owner: m, observation: ClosureObservation{Version: 1, Records: len(ids), RecordsSHA256: hex.EncodeToString(h.Sum(nil))}}, nil
}
