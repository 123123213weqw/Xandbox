// Package policycontrol provides a bounded local operator transport. The opt-in
// managed gateway composition binds it separately from the tenant/child protocol.
package policycontrol

import (
	"encoding/hex"
	"errors"
	"strings"
)

// Fixed local endpoint of the managed gateway composition, never tenant input.
const OperatorDirectory = "/run/xandbox-ingress-control"
const OperatorSocket = OperatorDirectory + "/operator.sock"
const OperatorPacketLimit = 1024

type PolicyCommand struct {
	Version        int    `json:"version"`
	Operation      string `json:"operation"`
	ExpectedEpoch  uint64 `json:"expected_epoch"`
	TargetEpoch    uint64 `json:"target_epoch"`
	SnapshotSHA256 string `json:"snapshot_sha256"`
}
type PolicyStatus struct {
	Version        int    `json:"version"`
	DurableEpoch   uint64 `json:"durable_epoch"`
	SnapshotSHA256 string `json:"snapshot_sha256"`
	ActiveEpoch    uint64 `json:"active_epoch"`
	ActiveSHA256   string `json:"active_sha256"`
	Phase          string `json:"phase"`
}
type policyReply struct {
	Version int          `json:"version"`
	Status  PolicyStatus `json:"status"`
	Code    string       `json:"code"`
}

func (r policyReply) valid() bool {
	if r.Version != 1 {
		return false
	}
	if r.Code == "" {
		return r.Status.Valid()
	}
	if r.Status != (PolicyStatus{}) {
		return false
	}
	switch r.Code {
	case "INVALID", "CONFLICT", "BUSY", "UNAVAILABLE":
		return true
	default:
		return false
	}
}

func operatorDigest(s string) bool {
	if len(s) != 64 || s != strings.ToLower(s) {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil
}
func (c PolicyCommand) Valid() bool {
	if c.Version != 1 {
		return false
	}
	if c.Operation == "status" {
		return c.ExpectedEpoch == 0 && c.TargetEpoch == 0 && c.SnapshotSHA256 == ""
	}
	return c.Operation == "activate" && c.ExpectedEpoch != ^uint64(0) && c.TargetEpoch == c.ExpectedEpoch+1 && operatorDigest(c.SnapshotSHA256)
}
func (s PolicyStatus) Valid() bool {
	if s.Version != 1 || s.DurableEpoch == 0 || !operatorDigest(s.SnapshotSHA256) || s.ActiveEpoch > s.DurableEpoch || (s.ActiveEpoch == 0 && s.ActiveSHA256 != "") || (s.ActiveEpoch != 0 && !operatorDigest(s.ActiveSHA256)) {
		return false
	}
	if s.ActiveEpoch == s.DurableEpoch && s.ActiveSHA256 != s.SnapshotSHA256 {
		return false
	}
	switch s.Phase {
	case "active", "committing":
		return s.ActiveEpoch == s.DurableEpoch
	case "waiting":
		return s.ActiveEpoch < s.DurableEpoch
	case "fenced":
		return true
	default:
		return false
	}
}

// Only one supervisor writer may advance this observation. Durable means the
// policy-store commit completed; active means the exact child ACK was received,
// NOT that requests are healthy or that an installation transaction committed.
func validPolicyTransition(old, next PolicyStatus) bool {
	if !old.Valid() || !next.Valid() {
		return false
	}
	if old == next {
		return true
	}
	sameDurable := old.DurableEpoch == next.DurableEpoch && old.SnapshotSHA256 == next.SnapshotSHA256
	sameActive := old.ActiveEpoch == next.ActiveEpoch && old.ActiveSHA256 == next.ActiveSHA256
	if old.Phase == "fenced" {
		return false
	}
	if next.Phase == "fenced" {
		return sameDurable && sameActive
	}
	switch old.Phase {
	case "waiting":
		return next.Phase == "active" && sameDurable
	case "active":
		return next.Phase == "committing" && sameDurable && sameActive
	case "committing":
		return next.Phase == "waiting" && old.DurableEpoch != ^uint64(0) && next.DurableEpoch == old.DurableEpoch+1 && sameActive
	default:
		return false
	}
}

// Classify before any mutation. A lost response is an observation of the same
// epoch/digest, not permission to replay a non-idempotent SIGHUP.
func Classify(c PolicyCommand, s PolicyStatus) (duplicate bool, err error) {
	if !c.Valid() || c.Operation != "activate" || !s.Valid() || s.Phase == "fenced" {
		return false, errors.New("invalid policy activation")
	}
	if c.TargetEpoch == s.DurableEpoch && c.SnapshotSHA256 == s.SnapshotSHA256 {
		return true, nil
	}
	if s.Phase != "active" || c.ExpectedEpoch != s.DurableEpoch {
		return false, errors.New("policy activation conflict")
	}
	return false, nil
}
