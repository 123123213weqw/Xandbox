package installtxn

import (
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
)

// Separate wire types. The old V1 completion and v4 Stop validators are NEVER
// widened to reinterpret/drop result authority. Ordinary strict canonical JSON
// remains mandatory; these types do not enter the old closed fast-path union.
type runtimeResultsCloseIntent struct {
	Version int               `json:"version"`
	Policy  string            `json:"policy"`
	Input   string            `json:"work_intent_sha256"`
	Stop    runtimeStopIntent `json:"original_work_stop_plan"`
}
type runtimeResultsCloseCompletion struct {
	Version  int                                   `json:"version"`
	Input    string                                `json:"intent_sha256"`
	Work     sandbox.AcceptedWorkStatus            `json:"terminal_work"`
	Core     sandbox.ResultBoundClosureObservation `json:"core"`
	Sessions session.ClosureObservation            `json:"sessions"`
}
