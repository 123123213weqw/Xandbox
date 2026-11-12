package installtxn

import (
	"bytes"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// Distinct opt-in wire type. Plan remains the unchanged managed placement and
// asset metadata; its Backend SHA binds the COMPLETE Config4.ResultPolicy.
// Neither an old Version1 transaction nor an old installer opts into this.
// This is cold bootstrap ONLY, not existing-state migration or rollback.
type resultTransaction struct {
	Version   int     `json:"version"`
	Revision  uint64  `json:"revision"`
	RequestID string  `json:"request_id"`
	Plan      Plan    `json:"plan"`
	Release   Release `json:"release"`
	Files     []File  `json:"files"`
}

func validResultTransaction(t resultTransaction) bool {
	return t.Version == 2 && t.Revision == 1 && requestPattern.MatchString(t.RequestID) && t.Plan.Version == 2 && validInstallationFiles(t.Plan, t.Release, t.Files)
}
func decodeResultTransaction(raw []byte) (resultTransaction, error) {
	var t resultTransaction
	if len(raw) == 0 || len(raw) > 65536 || strictjson.Decode(raw, &t) != nil || !validResultTransaction(t) || !bytes.Equal(raw, encode(t)) {
		return resultTransaction{}, ErrInventory
	}
	return t, nil
}
