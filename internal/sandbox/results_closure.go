package sandbox

import "context"

// ResultClosureObservation binds complete CURRENT canonical V2 result bytes,
// not delivery, old V1 integrity, physical reclaim, or an activation capability.
type ResultClosureObservation struct {
	Version       int    `json:"version"`
	Records       int    `json:"records"`
	Bytes         int64  `json:"bytes"`
	ReservedBytes int64  `json:"reserved_bytes"`
	RecordsSHA256 string `json:"records_sha256"`
}

func (o ResultClosureObservation) Valid() bool {
	return o.Version == 2 && o.Records >= 0 && o.Records <= MaxResultRecords && o.Bytes >= 0 && o.Bytes <= MaxResultBytes && o.ReservedBytes >= o.Bytes && o.ReservedBytes <= MaxResultBytes && hashPattern.MatchString(o.RecordsSHA256) && ((o.Records == 0 && o.Bytes == 0 && o.ReservedBytes == 0) || (o.Records > 0 && o.Bytes > 0 && o.ReservedBytes > 0))
}

type ResultBoundClosureObservation struct {
	Version int                      `json:"version"`
	Core    ClosureObservation       `json:"core"`
	Results ResultClosureObservation `json:"results"`
}

func (o ResultBoundClosureObservation) Valid() bool {
	return o.Version == 2 && o.Core.Valid() && o.Results.Valid()
}

type ResultBoundClosureProof struct {
	owner       *Manager
	store       *FileResultStore
	observation ResultBoundClosureObservation
}

func (p *ResultBoundClosureProof) For(m *Manager) bool {
	return p != nil && m != nil && p.owner == m && m.opts.Results == p.store && p.store != nil && p.store.resultsAlive() && p.observation.Valid()
}
func (p *ResultBoundClosureProof) Observation() ResultBoundClosureObservation {
	if p == nil {
		return ResultBoundClosureObservation{}
	}
	return p.observation
}
func (m *Manager) UsesResultRetention() bool { return m != nil && m.opts.Results != nil }

// ClosedResultsProof joins the ACTUAL closed Manager's record authority with
// the actual FileResultStore's writer seal and full read-only namespace scans.
// No caller callbacks, counts, portable report or alternate store can attest it.
func (m *Manager) ClosedResultsProof(ctx context.Context) (*ResultBoundClosureProof, error) {
	if m == nil || m.opts.Results == nil {
		return nil, ErrNotReady
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	store, ok := m.opts.Results.(*FileResultStore)
	if !ok {
		return nil, ErrResultUnavailable
	}
	before, e := m.closedRecordsProof(ctx)
	if e != nil {
		return nil, e
	}
	m.mu.Lock()
	items := make([]*instance, 0, len(m.records))
	for _, i := range m.records {
		items = append(items, i)
	}
	m.mu.Unlock()
	records := make([]Record, 0, len(items))
	for _, i := range items {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		i.mu.Lock()
		records = append(records, i.record)
		i.mu.Unlock()
	}
	result, e := store.sealResults(ctx, records)
	if e != nil {
		return nil, e
	}
	// File inspection performs no more user/model callbacks after its last scan.
	// Rejoin actual actor memory; pools are done and no record writer is allowed.
	after, e := m.closedRecordsProof(ctx)
	if e != nil {
		return nil, e
	}
	if before.Observation() != after.Observation() {
		return nil, ErrNotReady
	}
	p := &ResultBoundClosureProof{owner: m, store: store, observation: ResultBoundClosureObservation{Version: 2, Core: after.Observation(), Results: result}}
	if !p.For(m) {
		return nil, ErrResultUnavailable
	}
	return p, nil
}
