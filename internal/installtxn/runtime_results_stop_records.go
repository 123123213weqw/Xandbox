package installtxn

// Distinct physical Stop wire. No V1 close/v4 Stop validator or old fast-path
// union accepts this type. Plan is ONLY the original v2 process/state plan,
// never a legacy claimed work/close receipt. All four actual linked hashes are
// independently re-read before effects and before an opaque receipt returns.
type runtimeResultsStopIntent struct {
	Version     int               `json:"version"`
	Policy      string            `json:"policy"`
	WorkIntent  string            `json:"work_intent_sha256"`
	Work        string            `json:"work_completion_sha256"`
	CloseIntent string            `json:"results_close_intent_sha256"`
	Closure     string            `json:"results_close_completion_sha256"`
	Plan        runtimeStopIntent `json:"original_process_state_plan"`
}
type runtimeResultsStopReceipt struct {
	Version int    `json:"version"`
	Input   string `json:"results_stop_intent_sha256"`
}
