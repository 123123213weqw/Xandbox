package releasestore

import (
	"encoding/json"
	"unicode/utf8"
)

// ValidateValue snapshots an already constructed manifest and applies the SAME
// normalized policy/serialization ceiling as Decode(json.Marshal(m)). It does
// no filesystem/manager work and cannot authorize installation or activation.
func ValidateValue(m Manifest) (Manifest, error) { return validateValue(m, false) }

// ValidateLineValue includes the existing canonical LF in the SAME ceiling.
func ValidateLineValue(m Manifest) (Manifest, error) { return validateValue(m, true) }

func validateValue(m Manifest, line bool) (Manifest, error) {
	// Preserve nil versus non-nil empty slices and detach the caller's backing
	// array BEFORE validation/sorting. normalize retains its existing own copy.
	if m.Files != nil {
		m.Files = append([]File{}, m.Files...)
	}
	data, e := json.Marshal(m)
	if e != nil {
		return Manifest{}, ErrPolicy
	}
	if line {
		data = append(data, '\n')
	}
	if len(data) > MaxManifest {
		return Manifest{}, ErrPolicy
	}
	for _, s := range []string{m.SourceRevision, m.Toolchain, m.GOARCH} {
		if !utf8.ValidString(s) {
			return Decode(data)
		}
	}
	for _, f := range m.Files {
		for _, s := range []string{f.Role, f.Source, f.SHA256} {
			if !utf8.ValidString(s) {
				return Decode(data)
			}
		}
	}
	return normalize(m)
}
