package ingresslaunch

import (
	"encoding/json"
	"unicode/utf8"
)

// ValidateValue is pure typed validation, not a wire parser or host certificate.
// It shares Decode's ENTIRE policy and original json.Marshal size budget.
func ValidateValue(m Manifest) (Manifest, error) {
	data, e := json.Marshal(m)
	if e != nil || len(data) > MaxManifest {
		return Manifest{}, errPolicy
	}
	for _, s := range []string{m.UnitRoot, m.PolicyStateDir, m.Gateway.Path, m.Gateway.SHA256, m.Config.Path, m.Config.SHA256, m.NodeLaunch.Path, m.NodeLaunch.SHA256, m.Device} {
		if !utf8.ValidString(s) {
			return Decode(data)
		}
	}
	return m, validateManifest(m)
}
