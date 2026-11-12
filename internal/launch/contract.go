package launch

import (
	"encoding/json"
	"strconv"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// Contract is a decoded, bounded launch policy. Its closed value fields cannot
// be changed by another package after decoding. It is not an execution token,
// a pinned file, a current-state inventory or an upgrade/rollback approval.
// Manifest and its V1 wire contract remain unchanged.
type Contract struct {
	version int
	node    Manifest
	results firecracker.ResultPolicy
}

// V2 deliberately wraps the unchanged V1 node policy, instead of adding fields
// to Manifest or repurposing its version. Old binaries reject this envelope.
type resultContractWire struct {
	Version int                      `json:"version"`
	Launch  Manifest                 `json:"launch"`
	Results firecracker.ResultPolicy `json:"results"`
}

// DecodeContract accepts either the exact legacy schema or the explicit V2
// envelope. Both branches use bounded strict decoders; an invalid V1 object
// cannot fall back to a permissive parser or silently enable result retention.
func DecodeContract(data []byte) (Contract, error) {
	if len(data) > MaxManifest {
		return Contract{}, errPolicy
	}
	if n, e := Decode(data); e == nil {
		return Contract{version: 1, node: n}, nil
	}
	var w resultContractWire
	if strictjson.Decode(data, &w) != nil || w.Version != 2 || !w.Results.Valid() {
		return Contract{}, errPolicy
	}
	n, e := ValidateValue(w.Launch)
	if e != nil {
		return Contract{}, errPolicy
	}
	return Contract{version: 2, node: n, results: w.Results}, nil
}

// NewResultContract builds only a candidate value, with the SAME strict wire
// and LF-inclusive size ceiling as the real file reader. No files are written,
// budgets expanded, existing results migrated or service admission changed.
func NewResultContract(n Manifest, p firecracker.ResultPolicy) (Contract, error) {
	b, e := json.Marshal(resultContractWire{Version: 2, Launch: n, Results: p})
	if e != nil {
		return Contract{}, errPolicy
	}
	return DecodeContract(append(b, '\n'))
}

func (c Contract) valid() bool {
	return validateManifest(c.node) == nil && (c.version == 1 && c.results == (firecracker.ResultPolicy{}) || c.version == 2 && c.results.Valid())
}

// Node returns a COPY of the shared placement/asset/parent metadata. It remains
// a V1 Manifest, NOT the V2 backend policy or execution arguments. Consumers
// must use this Contract's CheckServiceBackend and Arguments for those joins.
func (c Contract) Node() Manifest { return c.node }

// Line returns fresh canonical JSON+LF. It is not the original file bytes or a
// proof that a caller's manifest hash names those bytes. Actual consumers still
// read the trusted/pinned file and the original backend independently.
func (c Contract) Line() ([]byte, error) {
	if !c.valid() {
		return nil, errPolicy
	}
	var v any = c.node
	if c.version == 2 {
		v = resultContractWire{Version: 2, Launch: c.node, Results: c.results}
	}
	b, e := json.Marshal(v)
	if e != nil || len(b) >= MaxManifest {
		return nil, errPolicy
	}
	return append(b, '\n'), nil
}

// Arguments is the ONE argv contract used by the launcher AND the readiness
// process proof. No caller-supplied argv, retention defaults or source config
// paths are accepted; every enabled dimension is emitted explicitly.
func (c Contract) Arguments() []string {
	if !c.valid() {
		return nil
	}
	args := c.node.Arguments()
	if c.version == 2 {
		args = append(args, "-result-bytes", strconv.FormatInt(c.results.Bytes, 10),
			"-result-tenant-bytes", strconv.FormatInt(c.results.TenantBytes, 10),
			"-result-records", strconv.Itoa(c.results.Records))
	}
	return args
}

// CheckServiceBackend is structural composition, NOT full config validation,
// fresh capacity admission, a backend constructor or an execution capability.
// The actual launcher/ingress retain their ordinary fresh ValidateAdmissionConfig
// checks, and sandboxd independently validates its own config and loaded budget.
func (c Contract) CheckServiceBackend(b firecracker.Config) error {
	if !c.valid() {
		return errPolicy
	}
	if c.version == 1 {
		return c.node.checkBackend(b)
	}
	if b.Version != 4 || b.Results == nil || *b.Results != c.results {
		return errPolicy
	}
	// Reuse the exact old nested placement/parent predicate on a LOCAL value
	// projection only. Never serialize, bind, execute or pass this projection to
	// a driver. All real preparation and daemon paths retain the original V4.
	legacyShape := b
	legacyShape.Version = 3
	legacyShape.Results = nil
	return c.node.checkBackend(legacyShape)
}
