package installtxn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
)

// Streaming projections of already bounded records, not ownership or reclaim
// capabilities. Keep the original live actors' domains and Encoder.Encode wire.
// The Linux caller must also prove the whole original byte set and held leases.
type terminalProjection struct {
	h       hash.Hash
	encoder *json.Encoder
	last    string
	count   int
	failed  bool
	core    bool
}

func newTerminalProjection(core bool) *terminalProjection {
	h := sha256.New()
	domain := "xandbox-session-closure-v1\n"
	if core {
		domain = "xandbox-core-closure-v1\n"
	}
	_, _ = h.Write([]byte(domain))
	return &terminalProjection{h: h, encoder: json.NewEncoder(h), core: core}
}

func (p *terminalProjection) add(id string, raw []byte) (err error) {
	if p == nil || p.failed {
		return ErrInventory
	}
	defer func() {
		if err != nil {
			p.failed = true // A rejected prefix can never be resumed as a proof.
		}
	}()
	if !requestPattern.MatchString(id) || id <= p.last {
		return ErrInventory
	}
	if p.core {
		if p.count >= sandbox.MaxLedgerRecords {
			return ErrInventory
		}
		r, e := sandbox.DecodePersistedRecord(raw)
		if e != nil || r.ID != id || r.Backend != "firecracker" || r.State != sandbox.Destroyed {
			return ErrInventory
		}
		err = p.encoder.Encode(r)
	} else {
		if p.count >= session.MaxRecords {
			return ErrInventory
		}
		r, e := session.DecodePersistedRecord(raw)
		if e != nil || r.ID != id || r.State != session.Closed {
			return ErrInventory
		}
		for _, a := range r.Attempts {
			if a.State != "COMMITTED" && a.State != "FAILED" {
				return ErrInventory
			}
		}
		err = p.encoder.Encode(r)
	}
	if err != nil {
		return err
	}
	p.last, p.count = id, p.count+1
	return nil
}

func (p *terminalProjection) observation() (int, string) {
	if p == nil || p.failed {
		return 0, ""
	}
	return p.count, hex.EncodeToString(p.h.Sum(nil))
}
