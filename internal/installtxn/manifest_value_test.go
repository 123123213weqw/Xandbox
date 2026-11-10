package installtxn

import (
	"bytes"
	"encoding/json"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/ingresslaunch"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"github.com/123123213weqw/Xandbox/internal/releasestore"
	"math"
	"reflect"
	"strings"
	"testing"
)

// Exact pre-change44 constructed validation/composition/descriptor expressions.
// Raw package decoders remain independently differential-tested against44.
func originalCompositionInside44(parent, path string) bool {
	return parent == path || strings.HasPrefix(path, parent+"/")
}
func originalManifestComposition44(m ingresslaunch.Manifest, n launch.Manifest) error {
	raw, e := json.Marshal(m)
	if e != nil {
		return ErrPolicy
	}
	if _, e = ingresslaunch.Decode(raw); e != nil {
		return ErrPolicy
	}
	raw, e = json.Marshal(n)
	if e != nil {
		return ErrPolicy
	}
	if _, e = launch.Decode(raw); e != nil {
		return ErrPolicy
	}

	if m.UnitRoot == n.UnitRoot || originalCompositionInside44(n.StateDir, m.PolicyStateDir) || originalCompositionInside44(m.PolicyStateDir, n.StateDir) || originalCompositionInside44(n.InputDir, m.PolicyStateDir) || originalCompositionInside44(m.PolicyStateDir, n.InputDir) {
		return ErrPolicy
	}
	dimensions := func(p launch.ParentEnvelope) []uint64 {
		return []uint64{p.MemoryMax, p.PidsMax, p.CPUQuota, p.IOBytesPerSecond, p.IOOperationsPerSecond}
	}
	cap, ing, res, node := dimensions(m.Capacity), dimensions(m.Ingress), dimensions(m.Reserve), dimensions(n.Parent)
	for i, total := range cap {
		for _, used := range []uint64{ing[i], res[i], node[i]} {
			if used > total {
				return ErrPolicy
			}
			total -= used
		}
	}
	return nil
}

func originalValidatePlan44(p Plan) error {
	if (p.Version != 1 && p.Version != 2) || p.ReleaseRevision == 0 || !digestPattern.MatchString(p.Release) || !devicePattern.MatchString(p.DevicePath) {
		return ErrPolicy
	}
	inputs := []firecracker.Asset{p.Self, p.Backend, p.Auth, p.Gateway}
	if p.Version == 1 {
		if p.Policy != nil {
			return ErrPolicy
		}
		inputs = append(inputs, p.Certificate, p.PrivateKey)
	} else {
		if p.Policy == nil || p.Certificate != (firecracker.Asset{}) || p.PrivateKey != (firecracker.Asset{}) {
			return ErrPolicy
		}
		inputs = append(inputs, *p.Policy)
	}
	paths := map[string]bool{}
	for i, a := range inputs {
		if !canonical(a.Path) || !digestPattern.MatchString(a.SHA256) || paths[a.Path] || inside(a.Path, Root) || inside(a.Path, DataRoot) || inside(a.Path, UnitDir) || (i != 0 && inside(a.Path, "/usr/libexec")) {
			return ErrPolicy
		}
		paths[a.Path] = true
	}
	// Reuse the existing strict budget/serialization rules, not a looser unit template.
	n := nodeManifest(p, map[string]Artifact{"daemon": {SHA256: strings.Repeat("0", 64)}})
	if _, e := launch.Decode(encode(n)); e != nil {
		return ErrPolicy
	}
	g := ingressManifest(p, n, "1:1", map[string]Artifact{"gateway": {SHA256: strings.Repeat("0", 64)}})
	if originalManifestComposition44(g, n) != nil {
		return ErrPolicy
	}
	return nil
}
func originalDescriptor44(r Release) (map[string]Artifact, error) {
	m := releasestore.Manifest{Version: r.Version, SourceRevision: r.SourceRevision, Toolchain: r.Toolchain, GOARCH: r.GOARCH}
	for _, v := range r.Files {
		m.Files = append(m.Files, releasestore.File{Role: v.Role, Source: "/descriptor/" + v.Role, SHA256: v.SHA256, Bytes: v.Bytes})
	}
	normalized, e := releasestore.Decode(encode(m))
	if e != nil || len(normalized.Files) != len(roles) {
		return nil, ErrPolicy
	}
	out := map[string]Artifact{}
	for i, v := range r.Files {
		if v.Role != roles[i] {
			return nil, ErrPolicy
		}
		out[v.Role] = v
	}
	return out, nil
}

func TestRuntimeFileManifestValuePlanCompositionOracle44(t *testing.T) {
	for _, version := range []int{1, 2} {
		seed := typedPlanSeed(version)
		check := func(p Plan) {
			t.Helper()
			before := encode(p)
			old, got := originalValidatePlan44(p), validatePlan(p)
			if (old == nil) != (got == nil) || !bytes.Equal(before, encode(p)) {
				t.Fatal("plan policy or caller mutation changed", old, got)
			}
		}
		check(seed)
		planScalarLeaves(reflect.ValueOf(seed), "Plan", func(path string, v reflect.Value) {
			var values []reflect.Value
			switch v.Kind() {
			case reflect.String:
				for _, s := range []string{"", "\xff", "/srv/<>&", strings.Repeat("x", MaxPlan), v.String()} {
					values = append(values, reflect.ValueOf(s))
				}
			case reflect.Bool:
				values = []reflect.Value{reflect.ValueOf(false), reflect.ValueOf(true)}
			case reflect.Int:
				for _, n := range []int{-1, 0, 1, 64, 65, 10000, 10001, math.MaxInt} {
					values = append(values, reflect.ValueOf(n))
				}
			case reflect.Uint64:
				for _, n := range []uint64{0, 1, 16, 128, 64 << 20, 1 << 30, 1 << 40, math.MaxUint64} {
					values = append(values, reflect.ValueOf(n))
				}
			default:
				t.Fatal("new Plan schema")
			}
			for _, value := range values {
				p := snapshotPlanValue(seed)
				planScalarLeaves(reflect.ValueOf(&p).Elem(), "Plan", func(name string, f reflect.Value) {
					if name == path {
						f.Set(value)
					}
				})
				check(p)
			}
		})
	}
}
func descriptorValueSeed44() Release {
	r := Release{Version: 1, SourceRevision: strings.Repeat("a", 40), Toolchain: "go1.27.3", GOARCH: "amd64"}
	for _, role := range roles {
		r.Files = append(r.Files, Artifact{Role: role, SHA256: strings.Repeat("b", 64), Bytes: 1})
	}
	return r
}
func TestRuntimeFileManifestValueDescriptorOracle44(t *testing.T) {
	check := func(r Release) {
		t.Helper()
		before := encode(r)
		want, e := originalDescriptor44(r)
		got, x := descriptor(r)
		if (e == nil) != (x == nil) || !reflect.DeepEqual(want, got) || !bytes.Equal(before, encode(r)) {
			t.Fatal("descriptor changed", e, x)
		}
	}
	seed := descriptorValueSeed44()
	check(seed)
	for _, header := range []string{"Version", "SourceRevision", "Toolchain", "GOARCH"} {
		for _, value := range []string{"", "\xff", "<>&", strings.Repeat("a", MaxPlan), "arm64", "386", "go1.27.3;sh"} {
			r := seed
			r.Files = append([]Artifact(nil), seed.Files...)
			v := reflect.ValueOf(&r).Elem().FieldByName(header)
			if v.Kind() == reflect.Int {
				v.SetInt(0)
			} else {
				v.SetString(value)
			}
			check(r)
		}
	}
	for i := range seed.Files {
		for _, field := range []string{"Role", "SHA256", "Bytes"} {
			for _, value := range []string{"", "\xff", "../file", strings.Repeat("a", 64)} {
				r := seed
				r.Files = append([]Artifact(nil), seed.Files...)
				v := reflect.ValueOf(&r.Files[i]).Elem().FieldByName(field)
				if v.Kind() == reflect.Int64 {
					for _, n := range []int64{-1, 0, 1, 128 << 20, 512 << 20, 1 << 30, math.MaxInt64} {
						v.SetInt(n)
						check(r)
					}
				} else {
					v.SetString(value)
					check(r)
				}
			}
		}
	}
	r := seed
	r.Files = nil
	check(r)
	r.Files = []Artifact{}
	check(r)
	r.Files = append([]Artifact(nil), seed.Files...)
	r.Files[0], r.Files[1] = r.Files[1], r.Files[0]
	check(r)
	if _, e := descriptor(r); e == nil {
		t.Fatal("sorted bundle normalization must not waive descriptor order")
	}
	r.Files = append([]Artifact(nil), seed.Files...)
	r.Files[1] = r.Files[0]
	check(r)
}
func BenchmarkRuntimeFileManifestValueDescriptor44(b *testing.B) {
	r := descriptorValueSeed44()
	for _, kind := range []string{"old44", "typed"} {
		b.Run(kind, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var e error
				if kind == "old44" {
					_, e = originalDescriptor44(r)
				} else {
					_, e = descriptor(r)
				}
				if e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}
func BenchmarkRuntimeFileManifestValuePlan44(b *testing.B) {
	p := typedPlanSeed(2)
	for _, kind := range []string{"old44", "typed"} {
		b.Run(kind, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var e error
				if kind == "old44" {
					e = originalValidatePlan44(p)
				} else {
					e = validatePlan(p)
				}
				if e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}
