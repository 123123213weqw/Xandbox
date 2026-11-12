package launch

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
)

func resultPolicy() firecracker.ResultPolicy {
	return firecracker.ResultPolicy{Version: 1, Bytes: 8 << 20, TenantBytes: 2 << 20, Records: 32}
}

func TestRetainedLaunchContractLegacySeparationAndOwnedValues(t *testing.T) {
	n := policy()
	legacy, _ := json.Marshal(n)
	legacy = append(legacy, '\n')
	old, e := DecodeContract(legacy)
	if e != nil || old.Node() != n || !reflect.DeepEqual(old.Arguments(), n.Arguments()) {
		t.Fatal("legacy contract drift", e)
	}
	line, e := old.Line()
	if e != nil || !bytes.Equal(line, legacy) {
		t.Fatal("legacy bytes drift", e)
	}
	p := resultPolicy()
	c, e := NewResultContract(n, p)
	if e != nil {
		t.Fatal(e)
	}
	line, e = c.Line()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(line); e == nil {
		t.Fatal("old decoder reinterpreted the new envelope")
	}
	round, e := DecodeContract(line)
	if e != nil || round != c || round.Node() != n {
		t.Fatal("new contract roundtrip", e)
	}
	want := append(n.Arguments(), "-result-bytes", "8388608", "-result-tenant-bytes", "2097152", "-result-records", "32")
	if !reflect.DeepEqual(c.Arguments(), want) {
		t.Fatal("explicit argument dimensions/defaults drift")
	}
	n.StateDir += "-other"
	p.Bytes++
	projection := c.Node()
	projection.Daemon.Path = "/bin/sh"
	args := c.Arguments()
	args[0] = "/bin/sh"
	line[0] = '['
	if c.Node() != policy() || !reflect.DeepEqual(c.Arguments(), want) {
		t.Fatal("input/output mutation changed the retained contract")
	}
	if (Contract{}).Arguments() != nil || (Contract{}).CheckServiceBackend(config(policy())) == nil {
		t.Fatal("zero contract gained authority")
	}
	if _, e = (Contract{}).Line(); e == nil {
		t.Fatal("zero contract serialized as valid policy")
	}
}

func TestRetainedLaunchContractStrictEnvelopeAndBudget(t *testing.T) {
	c, e := NewResultContract(policy(), resultPolicy())
	if e != nil {
		t.Fatal(e)
	}
	line, _ := c.Line()
	raw := string(bytes.TrimSpace(line))
	cases := map[string]string{
		"wrong-version":       strings.Replace(raw, `"version":2`, `"version":3`, 1),
		"folded-duplicate":    `{"Version":2,` + raw[1:],
		"unknown-argv":        raw[:len(raw)-1] + `,"argv":["/bin/sh"]}`,
		"nested-version":      strings.Replace(raw, `"launch":{"version":1`, `"launch":{"version":2`, 1),
		"nested-unknown":      strings.Replace(raw, `"launch":{`, `"launch":{"extra":1,`, 1),
		"null-launch":         `{"version":2,"launch":null,"results":{"version":1,"bytes":8,"tenant_bytes":4,"records":1}}`,
		"null-results":        `{"version":2,"launch":` + string(mustJSON(policy())) + `,"results":null}`,
		"missing-results":     `{"version":2,"launch":` + string(mustJSON(policy())) + `}`,
		"results-duplicate":   strings.Replace(raw, `"results":{"version":1`, `"results":{"version":1,"Version":1`, 1),
		"result-version":      strings.Replace(raw, `"results":{"version":1`, `"results":{"version":2`, 1),
		"zero-bytes":          strings.Replace(raw, `"bytes":8388608`, `"bytes":0`, 1),
		"tenant-over":         strings.Replace(raw, `"tenant_bytes":2097152`, `"tenant_bytes":8388609`, 1),
		"records-over":        strings.Replace(raw, `"records":32`, `"records":100001`, 1),
		"fractional-version":  strings.Replace(raw, `"version":2`, `"version":2.0`, 1),
		"trailing-value":      raw + `{}`,
		"legacy-with-results": string(mustJSON(policy()))[:len(mustJSON(policy()))-1] + `,"results":{"version":1,"bytes":8,"tenant_bytes":4,"records":1}}`,
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeContract([]byte(bad)); e == nil {
				t.Fatal("ambiguous, unknown, unbound or invalid envelope accepted")
			}
		})
	}
	n := policy()
	n.Auth.Path = "/etc/auth.json"
	base, e := NewResultContract(n, resultPolicy())
	if e != nil {
		t.Fatal(e)
	}
	b, _ := base.Line()
	n.Auth.Path = "/etc/" + strings.Repeat("a", MaxManifest-len(b)) + "auth.json"
	edge, e := NewResultContract(n, resultPolicy())
	if e != nil {
		t.Fatal("LF-inclusive exact ceiling rejected", e)
	}
	b, e = edge.Line()
	if e != nil || len(b) != MaxManifest {
		t.Fatal("outer wrapper byte budget drift", len(b), e)
	}
	if _, e = DecodeContract(append(b, ' ')); e == nil {
		t.Fatal("outer read ceiling bypass")
	}
	n.Auth.Path += "a"
	if _, e = ValidateValue(n); e != nil {
		t.Fatal("test must isolate wrapper ceiling from old inner schema", e)
	}
	if _, e = NewResultContract(n, resultPolicy()); e == nil {
		t.Fatal("LF-inclusive wrapper overflow accepted")
	}
}

func mustJSON(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}

func TestRetainedLaunchBackendExactMatchAndSharedStructuralPolicy(t *testing.T) {
	n, p := policy(), resultPolicy()
	c, e := NewResultContract(n, p)
	if e != nil {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*firecracker.Config){
		"matched":         func(*firecracker.Config) {},
		"node-missing":    func(b *firecracker.Config) { b.Node = nil },
		"quota-missing":   func(b *firecracker.Config) { b.Quota = nil },
		"io-missing":      func(b *firecracker.Config) { b.IO = nil },
		"placement":       func(b *firecracker.Config) { b.CgroupRoot += "/foreign" },
		"node-placement":  func(b *firecracker.Config) { b.Node.CgroupRoot += "/foreign" },
		"state-overlap":   func(b *firecracker.Config) { b.RuntimeRoot = n.StateDir },
		"parent-memory":   func(b *firecracker.Config) { b.Node.MemoryMax = n.Parent.MemoryMax },
		"parent-pids":     func(b *firecracker.Config) { b.Node.PidsMax = n.Parent.PidsMax },
		"parent-cpu":      func(b *firecracker.Config) { b.Node.CPUQuota = n.Parent.CPUQuota + 1 },
		"parent-io-bytes": func(b *firecracker.Config) { b.Node.IOBytesPerSecond = n.Parent.IOBytesPerSecond + 1 },
		"parent-io-ops":   func(b *firecracker.Config) { b.Node.IOOperationsPerSecond = n.Parent.IOOperationsPerSecond + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			legacy := config(n)
			change(&legacy)
			next := legacy
			next.Version, next.Results = 4, &p
			before := mustJSON(next)
			if (n.checkBackend(legacy) == nil) != (c.CheckServiceBackend(next) == nil) {
				t.Fatal("shared nested structural predicate drift")
			}
			if !bytes.Equal(before, mustJSON(next)) || next.Version != 4 || next.Results != &p {
				t.Fatal("real config projected/mutated for the consumer")
			}
		})
	}
	for name, change := range map[string]func(*firecracker.Config){
		"legacy-backend": func(b *firecracker.Config) { b.Version = 3 },
		"missing-policy": func(b *firecracker.Config) { b.Results = nil },
		"policy-version": func(b *firecracker.Config) { b.Results.Version++ },
		"bytes":          func(b *firecracker.Config) { b.Results.Bytes++ },
		"tenant-bytes":   func(b *firecracker.Config) { b.Results.TenantBytes++ },
		"records":        func(b *firecracker.Config) { b.Results.Records++ },
	} {
		t.Run(name, func(t *testing.T) {
			b := config(n)
			q := p
			b.Version, b.Results = 4, &q
			change(&b)
			if c.CheckServiceBackend(b) == nil {
				t.Fatal("non-identical backend result policy accepted")
			}
		})
	}
	b := config(n)
	b.Version, b.Results = 4, &p
	if n.checkBackend(b) == nil {
		t.Fatal("old manifest silently enabled V4")
	}
}
