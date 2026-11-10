package launch

import (
	"encoding/json"
	"unicode/utf8"
)

// ValidateValue is pure validation of an already constructed value against the
// SAME policy and serialized ceiling as Decode(json.Marshal(m)). It is not a
// wire parser, source proof, cached authority or permission to execute.
func ValidateValue(m Manifest) (Manifest, error) { return validateValue(m, false) }

// ValidateLineValue additionally budgets the canonical final LF, exactly as
// Decode(append(json.Marshal(m),'\n')). No caller-selected size bypass exists.
func ValidateLineValue(m Manifest) (Manifest, error) { return validateValue(m, true) }

func validateValue(m Manifest, line bool) (Manifest, error) {
	data, e := json.Marshal(m)
	if e != nil {
		return Manifest{}, errPolicy
	}
	if line {
		data = append(data, '\n')
	}
	if len(data) > MaxManifest {
		return Manifest{}, errPolicy
	}
	// encoding/json replaces invalid UTF-8. Preserve that normalization (including
	// accepted Unicode paths and error results) instead of changing path policy.
	for _, s := range []string{m.UnitRoot, m.InputDir, m.StateDir, m.Daemon.Path, m.Daemon.SHA256, m.Backend.Path, m.Backend.SHA256, m.Auth.Path, m.Auth.SHA256} {
		if !utf8.ValidString(s) {
			return Decode(data)
		}
	}
	return m, validateManifest(m)
}
