package firecracker

import (
	"errors"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

// Explicit config-v4 opt-in, never inferred from existing result data or an
// external-disk allowance. Legacy config/installed launch schemas stay unchanged.
type ResultPolicy struct {
	Version     int   `json:"version"`
	Bytes       int64 `json:"bytes"`
	TenantBytes int64 `json:"tenant_bytes"`
	Records     int   `json:"records"`
}

func (p ResultPolicy) Limits() sandbox.ResultLimits {
	return sandbox.ResultLimits{Bytes: p.Bytes, TenantBytes: p.TenantBytes, Records: p.Records}
}
func (p ResultPolicy) Valid() bool { return p.Version == 1 && p.Limits().Valid() }

type resultReservation struct{ memory, disk, inodes uint64 }

// Conservative PLANNING margins, not unique RSS, a filesystem quota or measured
// capacity: logical final+temporary payloads, up to 64-KiB allocation padding per
// file, directory margins and 16-KiB loaded-index/control margin per record.
// All are charged INSIDE the existing immutable controller/disk/inode envelope.
// Nothing automatically grows a cgroup, IO limit, node capacity or operator reserve.
func (c Config) resultReservation() (resultReservation, error) {
	var out resultReservation
	if c.Results == nil {
		return out, nil
	}
	p := *c.Results
	if c.Version != 4 || c.Node == nil || !p.Valid() {
		return out, errors.New("unbound retained result reservation")
	}
	index, e := checkedProduct(uint64(p.Records), 16<<10)
	if e != nil {
		return out, e
	}
	out.memory, e = checkedSum(4<<20, index)
	if e != nil {
		return out, e
	}
	padding, e := checkedProduct(uint64(p.Records), 2*(64<<10))
	if e != nil {
		return out, e
	}
	payload, e := checkedProduct(uint64(p.Bytes), 2)
	if e != nil {
		return out, e
	}
	out.disk, e = checkedSum(256<<10, padding, payload)
	if e != nil {
		return out, e
	}
	out.inodes, e = checkedSum(4, 2*uint64(p.Records))
	return out, e
}

func (c Config) checkResultAdmission(l sandbox.ResultLimits) error {
	if c.Results == nil {
		if l == (sandbox.ResultLimits{}) {
			return nil
		}
		return errors.New("retention requires explicit immutable config-v4 reservation")
	}
	if c.Version != 4 || c.Node == nil || !c.Results.Valid() || l != c.Results.Limits() {
		return errors.New("retained result limits differ from immutable node reservation")
	}
	return nil
}

// Read-only preflight BEFORE OpenResultStore or a backend constructor. The
// constructor independently repeats the match on its OWN freshly read config;
// this check is neither a cached config nor permission to bind a different one.
func ValidateResultAdmissionConfig(path string, limits sandbox.ResultLimits) error {
	c, e := loadConfig(path)
	if e != nil {
		return e
	}
	return c.checkResultAdmission(limits)
}
