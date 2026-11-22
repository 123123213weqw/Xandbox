package installtxn

import "github.com/123123213weqw/Xandbox/internal/strictjson"

// UpdateInspectionPlan pins observations, not permission to install or rewind
// anything. Commit and policy pins are private operator data. No caller-selected
// service, destination, mutable-state backup or compatibility override exists.
type UpdateInspectionPlan struct {
	Version             int    `json:"version"`
	InstallCommitSHA256 string `json:"install_commit_sha256"`
	ReleaseRevision     uint64 `json:"release_revision"`
	CandidateRelease    string `json:"candidate_release"`
	RetainedRelease     string `json:"retained_release"`
	PolicyRevision      uint64 `json:"policy_revision"`
	PolicySHA256        string `json:"policy_sha256"`
}

func DecodeUpdateInspection(raw []byte) (UpdateInspectionPlan, error) {
	var p UpdateInspectionPlan
	if len(raw) == 0 || len(raw) > MaxPlan || strictjson.Decode(raw, &p) != nil || p.Version != 1 || !digestPattern.MatchString(p.InstallCommitSHA256) || p.ReleaseRevision < 2 || p.ReleaseRevision == ^uint64(0) || !digestPattern.MatchString(p.CandidateRelease) || !digestPattern.MatchString(p.RetainedRelease) || p.CandidateRelease == p.RetainedRelease || p.PolicyRevision == ^uint64(0) || (p.PolicyRevision == 0 && p.PolicySHA256 != "") || (p.PolicyRevision > 0 && !digestPattern.MatchString(p.PolicySHA256)) {
		return p, ErrPolicy
	}
	return p, nil
}

// UpdateInspectionResult is intentionally not a reusable authorization receipt.
// A live service may change mutable state immediately after this observation.
// Hashes, paths, credentials, request IDs and raw manager output are not public
// output. Every unimplemented activation/compatibility/health proof stays false.
type UpdateInspectionResult struct {
	Version                  int  `json:"version"`
	InstalledFilesVerified   bool `json:"installed_files_verified"`
	CandidateReleaseVerified bool `json:"candidate_release_verified"`
	CurrentReleaseRetained   bool `json:"current_release_retained"`
	ChangedArtifacts         int  `json:"changed_artifacts"`
	ChangedBackendAssets     int  `json:"changed_backend_assets"`
	CompatibilityProven      bool `json:"compatibility_proven"`
	DrainReclaimProven       bool `json:"drain_reclaim_proven"`
	ActivationAllowed        bool `json:"activation_allowed"`
	ServicesChanged          bool `json:"services_changed"`
	StateChanged             bool `json:"state_changed"`
	ProductionReady          bool `json:"production_ready"`
}
