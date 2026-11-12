// Package fixedhex recognizes fixed-width lowercase ASCII hexadecimal strings.
// This is pure syntax, never JSON decoding, a cache or source authority.
package fixedhex

// Pattern recognizes exactly the byte language ^[0-9a-f]{N}$ for positive N.
// Deployment callers use fixed compile-time widths; zero/negative widths refuse.
// Keep the exact byte language of ^[0-9a-f]{N}$ without a regexp interpreter.
// This is not Unicode case folding, JSON parsing, a cache or source attestation.
type Pattern int

func (p Pattern) MatchString(value string) bool {
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
