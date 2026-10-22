package guest

import (
	"errors"
	"strings"

	"github.com/123123213weqw/Xandbox/internal/guestwire"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

// parseBoot permits EITHER an immutable cold Ref OR a pristine template flag.
// Templates contain no prior tenant identity. Duplicate identity flags fail.
func parseBoot(cmdline string) (ref sandbox.Ref, pristine bool, err error) {
	seen := map[string]bool{}
	for _, field := range strings.Fields(cmdline) {
		key, value, ok := strings.Cut(field, "=")
		if key != "xandbox.guest" && key != "xandbox.id" && key != "xandbox.generation" && key != "xandbox.pristine" {
			continue
		}
		if !ok || seen[key] {
			return ref, false, errors.New("duplicate or incomplete guest boot identity")
		}
		seen[key] = true
		switch key {
		case "xandbox.guest":
			if value != "1" {
				return ref, false, errors.New("invalid guest boot flag")
			}
		case "xandbox.pristine":
			if value != "1" {
				return ref, false, errors.New("invalid pristine flag")
			}
			pristine = true
		case "xandbox.id":
			ref.ID = value
		case "xandbox.generation":
			ref.Generation = value
		}
	}
	if !seen["xandbox.guest"] {
		return ref, false, errors.New("missing guest boot flag")
	}
	if pristine {
		if seen["xandbox.id"] || seen["xandbox.generation"] {
			return ref, false, errors.New("pristine template carries a prior identity")
		}
		return ref, true, nil
	}
	if !(guestwire.Request{Version: guestwire.Version, Operation: "health", Ref: ref}).Valid() {
		return ref, false, errors.New("missing guest boot identity")
	}
	return ref, false, nil
}
