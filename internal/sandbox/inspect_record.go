package sandbox

// DecodePersistedRecord validates the current on-disk schema without constructing
// a store, migrating, publishing an index or removing/syncing orphan files.
// The caller must bound and anchor its read and hold exclusive state ownership.
// A valid DESTROYED record alone is never a kernel/resource reclaim certificate.
func DecodePersistedRecord(data []byte) (Record, error) {
	if len(data) == 0 || len(data) > MaxLedgerRecordBytes {
		return Record{}, ErrInvalid
	}
	r, _, e := decodeLedger(data, false)
	return r, e
}
