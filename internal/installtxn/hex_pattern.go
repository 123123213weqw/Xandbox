package installtxn

// The installer repeatedly validates fixed-width lowercase hexadecimal pins.
// Keep the exact byte language of ^[0-9a-f]{N}$ without a regexp interpreter.
// This is not Unicode case folding, JSON parsing, a cache or source attestation.
type lowerHexPattern int

func (p lowerHexPattern) MatchString(value string) bool {
	if p <= 0 || len(value) != int(p) {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
