package serviceready

import (
	"bytes"
	"strings"
)

// Linux /proc cmdline has exactly one trailing NUL. This is an equality check,
// not parsing a prefix, sorting flags, filling defaults or ignoring extra argv.
// The actual caller obtains expected solely from the decoded pinned Contract.
func processArgumentsMatch(actual []byte, expected []string) bool {
	return len(expected) != 0 && bytes.Equal(actual, []byte(strings.Join(expected, "\x00")+"\x00"))
}
