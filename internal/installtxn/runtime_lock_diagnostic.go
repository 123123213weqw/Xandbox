package installtxn

import "strings"

// A bounded diagnostic of rows in ONE already-read kernel payload, never a
// count of actual lock objects or authority to ignore ambiguous ownership.
// No row, ordinal, PID, device, inode, path or hash is retained in the error.
type runtimeLockAmbiguity struct {
	count uint8 // 0 absent; 1 two; 2 three; 3 at least four
	shape uint8 // 0 absent; 1 identical text; 2 same ordinal; 3 different ordinals
}

func runtimeLockAmbiguityFailure(matches int, sameText, sameOrdinal bool) error {
	var d runtimeLockAmbiguity
	if matches >= 2 {
		switch matches {
		case 2:
			d.count = 1
		case 3:
			d.count = 2
		default:
			d.count = 3
		}
		switch {
		case sameText && sameOrdinal:
			d.shape = 1
		case sameOrdinal:
			d.shape = 2
		default:
			d.shape = 3
		}
	}
	return &runtimeProofError{stage: proofStateLockOwnerAmbiguous, cause: ErrConflict, lock: d}
}

func (d runtimeLockAmbiguity) appendTo(b *strings.Builder) {
	if d == (runtimeLockAmbiguity{}) {
		return // Existing errors without diagnostics retain their exact text.
	}
	var count, shape string
	switch d.count {
	case 1:
		count = "two"
	case 2:
		count = "three"
	case 3:
		count = "many"
	}
	switch d.shape {
	case 1:
		shape = "exact-text"
	case 2:
		shape = "same-ordinal"
	case 3:
		shape = "different-ordinal"
	}
	if count == "" || shape == "" {
		b.WriteString("/lock-rows-unavailable")
		return
	}
	b.WriteString("/lock-rows-")
	b.WriteString(count)
	b.WriteByte('/')
	b.WriteString(shape)
}
