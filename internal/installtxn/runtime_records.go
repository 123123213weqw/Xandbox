package installtxn

import (
	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
)

// Pure wire records, not constructors or portable recovery authority. These
// declarations are byte-for-byte the former Linux declarations; rehoming them
// permits common-platform equivalence tests of the EXACT production types.
// All effect/authority validators and syscall users remain Linux-only.
type runtimeStateIdentity struct {
	RootDevice        uint64 `json:"root_device"`
	RootInode         uint64 `json:"root_inode"`
	LockDevice        uint64 `json:"lock_device"`
	LockInode         uint64 `json:"lock_inode"`
	LockChangeSeconds int64  `json:"lock_change_seconds"`
	LockChangeNanos   int64  `json:"lock_change_nanos"`
}

type runtimeDrainIntent struct {
	Version     int                            `json:"version"`
	Base        string                         `json:"base_commit_sha256"`
	Request     string                         `json:"request_id"`
	Process     nodecontrol.ProcessIdentity    `json:"process"`
	Before      nodecontrol.State              `json:"before"`
	Maintenance *nodecontrol.MaintenanceRecord `json:"maintenance,omitempty"`
}

type runtimeStopIntent struct {
	Version int                          `json:"version"`
	Base    string                       `json:"base_commit_sha256"`
	Request string                       `json:"request_id"`
	Drain   string                       `json:"drain_intent_sha256"`
	Main    nodecontrol.ProcessIdentity  `json:"main"`
	Ingress *nodecontrol.ProcessIdentity `json:"ingress,omitempty"`
	State   *runtimeStateIdentity        `json:"state_identity,omitempty"`
	Work    string                       `json:"work_completion_sha256,omitempty"`
	Close   string                       `json:"runtime_close_sha256,omitempty"`
}

type runtimeWorkStopIntent struct {
	Version int                `json:"version"`
	Policy  string             `json:"policy"`
	Drain   runtimeDrainIntent `json:"drain"`
	Stop    runtimeStopIntent  `json:"original_stop_plan"`
}

type runtimeWorkCompletion struct {
	Version int                        `json:"version"`
	Input   string                     `json:"intent_sha256"`
	Work    sandbox.AcceptedWorkStatus `json:"terminal_work"`
}

type runtimeCloseIntent struct {
	Version int               `json:"version"`
	Policy  string            `json:"policy"`
	Input   string            `json:"work_intent_sha256"`
	Stop    runtimeStopIntent `json:"original_work_stop_plan"`
}

type runtimeCloseCompletion struct {
	Version  int                        `json:"version"`
	Input    string                     `json:"intent_sha256"`
	Work     sandbox.AcceptedWorkStatus `json:"terminal_work"`
	Core     sandbox.ClosureObservation `json:"core"`
	Sessions session.ClosureObservation `json:"sessions"`
}
