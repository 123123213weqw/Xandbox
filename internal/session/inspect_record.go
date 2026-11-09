package session

// MaxRecordBytes is the existing persisted schema limit, not an admission limit.
const MaxRecordBytes = maxFileBytes

// DecodePersistedRecord is a pure current-schema reader. Unlike FileStore.Load
// it never removes orphan temps or syncs files, and unlike Broker.New it never
// recovers/fences records. The caller supplies anchored, exclusively owned reads.
func DecodePersistedRecord(data []byte) (Record, error) { return decodeRecord(data) }
