package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
)

// MaxResultRecordBytes is the existing envelope ceiling, not a larger allowance.
const MaxResultRecordBytes = 2*65_536 + 16_384

// ResultRecordInspection contains no output/error payload and is NOT an actor,
// state-lock, delivery, reclaim or activation capability. The reader must bind
// the actual raw FD-relative read and join Reservation to the original ledger.
type ResultRecordInspection struct {
	Reservation   ResultReservation
	Bytes         int64
	ReservedBytes int64
	RawSHA256     string
}

// DecodePersistedTerminalResult uses the ordinary canonical/checksum decoder,
// without a constructor, recovery, rewrite, sync or namespace operation. Legacy
// V1 and pending rows remain readable by the ordinary store but cannot attest a
// complete V2 terminal result set, and therefore refuse this distinct inspector.
func DecodePersistedTerminalResult(raw []byte) (ResultRecordInspection, error) {
	r, e := decodeResult(raw)
	if e != nil || r.Version != resultVersion || r.Result == nil {
		return ResultRecordInspection{}, ErrResultUnavailable
	}
	sum := sha256.Sum256(raw)
	return ResultRecordInspection{Reservation: r.Reservation, Bytes: int64(len(raw)), ReservedBytes: r.Reservation.charge(), RawSHA256: hex.EncodeToString(sum[:])}, nil
}

// ResultInspectionProjection streams the SAME sorted raw-record framing as the
// actual sealed actor. This is disk-format comparison only: neither this object
// nor its plain observation can create a ResultBoundClosureProof. Every entry
// must be visited and independently joined to the original ledger by the caller.
// Do not use concurrently or resume any rejected prefix.
type ResultInspectionProjection struct {
	h               hash.Hash
	last            string
	count           int
	bytes, reserved int64
	failed          bool
}

func NewResultInspectionProjection() *ResultInspectionProjection {
	h := sha256.New()
	_, _ = h.Write([]byte("xandbox-results-closure-v2\n"))
	return &ResultInspectionProjection{h: h}
}
func (p *ResultInspectionProjection) Add(id string, raw []byte) (out ResultRecordInspection, err error) {
	if p == nil || p.h == nil || p.failed {
		return out, ErrResultUnavailable
	}
	defer func() {
		if err != nil {
			p.failed = true
		}
	}()
	if !tokenPattern.MatchString(id) || id <= p.last || p.count >= MaxResultRecords {
		return out, ErrResultUnavailable
	}
	row, e := DecodePersistedTerminalResult(raw)
	if e != nil || row.Reservation.JobID != id || row.Bytes > MaxResultBytes-p.bytes || row.ReservedBytes > MaxResultBytes-p.reserved {
		return out, ErrResultUnavailable
	}
	if e = json.NewEncoder(p.h).Encode(struct{ Name, SHA256 string }{id + ".json", row.RawSHA256}); e != nil {
		return out, e
	}
	p.last, p.count, p.bytes, p.reserved = id, p.count+1, p.bytes+row.Bytes, p.reserved+row.ReservedBytes
	return row, nil
}
func (p *ResultInspectionProjection) Observation() (ResultClosureObservation, error) {
	if p == nil || p.h == nil || p.failed {
		return ResultClosureObservation{}, ErrResultUnavailable
	}
	o := ResultClosureObservation{Version: 2, Records: p.count, Bytes: p.bytes, ReservedBytes: p.reserved, RecordsSHA256: hex.EncodeToString(p.h.Sum(nil))}
	if !o.Valid() {
		return ResultClosureObservation{}, ErrResultUnavailable
	}
	return o, nil
}
