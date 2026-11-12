package installtxn

import (
	"bytes"
	"encoding/json"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// Pure declarations rehomed verbatim; all filesystem/effect methods remain
// Linux-only. Neither this policy nor a decoded value is installation authority.
var configNames = []string{"auth.json", "backend.json", "gateway.json", "ingress.json", "launch.json", "readiness.json", "tls.key", "tls.pem"}

func configNamesFor(version int) []string {
	if version == 2 {
		return []string{"auth.json", "backend.json", "gateway.json", "gateway-policy.json", "ingress.json", "launch.json", "readiness.json"}
	}
	return configNames
}

func planInputs(p Plan) []struct {
	name string
	a    firecracker.Asset
	max  int64
} {
	values := []struct {
		name string
		a    firecracker.Asset
		max  int64
	}{{"backend.json", p.Backend, 16384}, {"auth.json", p.Auth, 65536}, {"gateway.json", p.Gateway, gateway.MaxSnapshotBytes}}
	if p.Version == 2 && p.Policy != nil {
		return append(values, struct {
			name string
			a    firecracker.Asset
			max  int64
		}{"gateway-policy.json", *p.Policy, gateway.MaxSnapshotBytes})
	}
	return append(values, struct {
		name string
		a    firecracker.Asset
		max  int64
	}{"tls.pem", p.Certificate, 65536}, struct {
		name string
		a    firecracker.Asset
		max  int64
	}{"tls.key", p.PrivateKey, 65536})
}

func validFileList(t transaction) bool {
	if t.Version != 1 || t.Revision != 1 || !requestPattern.MatchString(t.RequestID) {
		return false
	}
	return validInstallationFiles(t.Plan, t.Release, t.Files)
}

// Pure shared inventory policy. Each versioned caller keeps its OWN exact
// version/revision/request guard; no transaction or backend is normalized.
func validInstallationFiles(plan Plan, release Release, files []File) bool {
	p, e := validatedPlanValue(plan)
	if e != nil {
		return false
	}
	expected := map[string]uint32{SelfPath: 0555, childRoot + "/gateway": 0555, UnitDir + "/" + MainUnit: 0600, UnitDir + "/" + IngressUnit: 0600}
	for _, name := range configNamesFor(p.Version) {
		expected[Root+"/"+name] = 0600
	}
	for _, r := range roles {
		mode := uint32(0444)
		if executable(r) {
			mode = 0555
		}
		expected[rolePath(r)] = mode
	}
	art, err := descriptor(release)
	if err != nil || digest(encode(release)) != plan.Release {
		return false
	}
	if len(files) != len(expected) {
		return false
	}
	sourcePins := map[string]string{}
	for _, input := range planInputs(plan) {
		sourcePins[Root+"/"+input.name] = input.a.SHA256
	}
	type artifactPin struct {
		path, sha string
		bytes     int64
	}
	pins := make([]artifactPin, 0, len(art)+1)
	for role, a := range art {
		pins = append(pins, artifactPin{rolePath(role), a.SHA256, a.Bytes})
		if role == "gateway" {
			pins = append(pins, artifactPin{childRoot + "/gateway", a.SHA256, a.Bytes})
		}
	}
	for _, v := range files {
		mode, ok := expected[v.Path]
		if !ok || mode != v.Mode || v.Bytes < 1 || v.Bytes > 512<<20 || !digestPattern.MatchString(v.SHA256) {
			return false
		}
		if v.Path == SelfPath && v.SHA256 != plan.Self.SHA256 {
			return false
		}
		if pin, ok := sourcePins[v.Path]; ok && v.SHA256 != pin {
			return false
		}
		// Preserve ALL matching constraints, including any path aliases. Do not
		// overwrite a constraint in a path-keyed map and silently weaken it.
		for _, pin := range pins {
			if v.Path == pin.path && (v.SHA256 != pin.sha || v.Bytes != pin.bytes) {
				return false
			}
		}
		delete(expected, v.Path)
	}
	return len(expected) == 0
}

// Read ONLY the bytes already obtained by the original bounded, trusted file
// reader. For this closed schema, exact canonical re-encoding excludes unknown,
// folded/duplicate keys, alternate spelling/order/whitespace and trailing data.
// A fresh candidate owns every pointer/slice; no authority or decoded-value cache.
func decodeTransactionBytes(data []byte) (transaction, error) {
	// Conservatively bypass the candidate when total opening bytes exceed the
	// old parser's depth ceiling. Counting quoted bytes too can only select the
	// EXACT old path; malformed deep input never reaches a looser deep parser.
	if len(data) > 1 && data[0] == '{' && data[len(data)-1] == '\n' &&
		bytes.Count(data, []byte{'{'})+bytes.Count(data, []byte{'['}) <= 64 {
		var candidate transaction
		if json.Unmarshal(data, &candidate) == nil && bytes.Equal(data, encode(candidate)) && validFileList(candidate) {
			return candidate, nil
		}
	}
	// Preserve the EXACT old expression on ANY rejected fast candidate, including
	// the original partially populated/normalized value returned WITH an error.
	// Never merge fallback decoding into the rejected candidate or reread the file.
	var value transaction
	if strictjson.Decode(data, &value) != nil || !validFileList(value) || !bytes.Equal(data, encode(value)) {
		return value, ErrInventory
	}
	return value, nil
}
