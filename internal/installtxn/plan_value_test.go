package installtxn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

func typedPlanSeed(version int) Plan {
	p := samplePlan()
	if version == 2 {
		p.Version = 2
		p.Policy = &firecracker.Asset{Path: "/bootstrap/policy.json", SHA256: strings.Repeat("b", 64)}
		p.Certificate, p.PrivateKey = firecracker.Asset{}, firecracker.Asset{}
	}
	return p
}

// Independent pinned2792b89 wire decoder AND semantic policy oracle. No call
// into the candidate validatePlan is used for the baseline comparison.
func originalDecodePlan2792(raw []byte) (Plan, error) {
	var p Plan
	if len(raw) == 0 || len(raw) > MaxPlan || strictjson.Decode(raw, &p) != nil || (p.Version != 1 && p.Version != 2) || p.ReleaseRevision == 0 || !digestPattern.MatchString(p.Release) || !devicePattern.MatchString(p.DevicePath) {
		return p, ErrPolicy
	}
	inputs := []firecracker.Asset{p.Self, p.Backend, p.Auth, p.Gateway}
	if p.Version == 1 {
		if p.Policy != nil {
			return p, ErrPolicy
		}
		inputs = append(inputs, p.Certificate, p.PrivateKey)
	} else {
		if p.Policy == nil || p.Certificate != (firecracker.Asset{}) || p.PrivateKey != (firecracker.Asset{}) {
			return p, ErrPolicy
		}
		inputs = append(inputs, *p.Policy)
	}
	paths := map[string]bool{}
	for i, a := range inputs {
		if !originalCanonicalPathE57(a.Path) || !digestPattern.MatchString(a.SHA256) || paths[a.Path] || inside(a.Path, Root) || inside(a.Path, DataRoot) || inside(a.Path, UnitDir) || (i != 0 && inside(a.Path, "/usr/libexec")) {
			return p, ErrPolicy
		}
		paths[a.Path] = true
	}
	// Reuse the existing strict budget/serialization rules, not a looser unit template.
	n := nodeManifest(p, map[string]Artifact{"daemon": {SHA256: strings.Repeat("0", 64)}})
	if _, e := launch.Decode(encode(n)); e != nil {
		return p, ErrPolicy
	}
	g := ingressManifest(p, n, "1:1", map[string]Artifact{"gateway": {SHA256: strings.Repeat("0", 64)}})
	if g.CheckComposition(n) != nil {
		return p, ErrPolicy
	}
	return p, nil
}

// Exact old validFileList plan-validation expression at2792b89.
func originalPlanRoundtrip(p Plan) (Plan, error) {
	got, e := originalDecodePlan2792(encode(p))
	if e != nil || !bytes.Equal(encode(got), encode(p)) {
		return got, ErrPolicy
	}
	return got, nil
}

func comparePlanValidation(t *testing.T, p Plan) {
	t.Helper()
	before := encode(p)
	old, oldErr := originalPlanRoundtrip(p)
	got, gotErr := validatedPlanValue(p)
	if (oldErr == nil) != (gotErr == nil) || (gotErr == nil && !reflect.DeepEqual(old, got)) {
		t.Fatal("typed validation differs from original roundtrip", oldErr, gotErr)
	}
	if !bytes.Equal(before, encode(p)) {
		t.Fatal("validator changed caller policy")
	}
}

func planScalarLeaves(v reflect.Value, path string, visit func(string, reflect.Value)) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			planScalarLeaves(v.Elem(), path, visit)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			planScalarLeaves(v.Field(i), path+"."+v.Type().Field(i).Name, visit)
		}
	default:
		visit(path, v)
	}
}

func TestRuntimeFileTypedPlanSchemaContract(t *testing.T) {
	typeOf := reflect.TypeOf(Plan{})
	fields := []string{"Version", "ReleaseRevision", "Release", "Self", "Backend", "Auth", "Gateway", "Certificate", "PrivateKey", "Policy", "DevicePath", "Frontend", "Parent", "Ingress", "Reserve", "Capacity"}
	if typeOf.NumField() != len(fields) {
		t.Fatal("Plan shape changed: review typed snapshot/JSON equivalence")
	}
	for i, n := range fields {
		if typeOf.Field(i).Name != n {
			t.Fatal("Plan field contract changed", n)
		}
	}
	marshaler := reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	unmarshaler := reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	var inspect func(reflect.Type, string)
	inspect = func(typ reflect.Type, path string) {
		if typ.Implements(marshaler) || reflect.PointerTo(typ).Implements(marshaler) || typ.Implements(unmarshaler) || reflect.PointerTo(typ).Implements(unmarshaler) {
			t.Fatal("custom JSON normalization needs review", path)
		}
		switch typ.Kind() {
		case reflect.Pointer:
			if path != "Plan.Policy" || typ.Elem() != reflect.TypeOf(firecracker.Asset{}) {
				t.Fatal("new reference field needs snapshot review", path)
			}
			inspect(typ.Elem(), path)
		case reflect.Struct:
			seen := map[string]bool{}
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				tag := strings.Split(f.Tag.Get("json"), ",")[0]
				if f.PkgPath != "" || tag == "" || tag == "-" || seen[tag] {
					t.Fatal("non-closed JSON field contract", path, f.Name)
				}
				seen[tag] = true
				inspect(f.Type, path+"."+f.Name)
			}
		case reflect.Int, reflect.Uint64, reflect.String, reflect.Bool:
		default:
			t.Fatal("new normalization/reference kind needs review", path, typ.Kind())
		}
	}
	inspect(typeOf, "Plan")
}

func TestRuntimeFileTypedPlanOriginalRoundtripDifferential(t *testing.T) {
	changes := map[string]func(*Plan){
		"version": func(p *Plan) { p.Version = 3 }, "zero-revision": func(p *Plan) { p.ReleaseRevision = 0 },
		"bad-release": func(p *Plan) { p.Release = "A" + p.Release[1:] }, "device": func(p *Plan) { p.DevicePath = "/dev/vda;sh" },
		"duplicate-source": func(p *Plan) { p.Auth = p.Backend }, "protected-source": func(p *Plan) { p.Auth.Path = Root + "/auth.json" },
		"other-libexec": func(p *Plan) { p.Backend.Path = "/usr/libexec/foreign" }, "unclean": func(p *Plan) { p.Self.Path = "/bootstrap/../self" },
		"bad-budget": func(p *Plan) { p.Frontend.MaxInstances = 0 }, "insufficient-parent": func(p *Plan) { p.Parent.MemoryMax = 1 },
		"insufficient-capacity": func(p *Plan) { p.Capacity.MemoryMax = 1 }, "overflow": func(p *Plan) { p.Parent.CPUQuota = ^uint64(0) },
		"mixed-cert": func(p *Plan) { p.Certificate = typedPlanSeed(1).Certificate }, "nil-policy": func(p *Plan) { p.Policy = nil },
		"policy": func(p *Plan) {
			p.Policy = &firecracker.Asset{Path: "/bootstrap/policy.json", SHA256: strings.Repeat("b", 64)}
		},
	}
	for _, version := range []int{1, 2} {
		p := typedPlanSeed(version)
		comparePlanValidation(t, p)
		for name, change := range changes {
			t.Run(fmt.Sprintf("v%d/%s", version, name), func(t *testing.T) { q := snapshotPlanValue(p); change(&q); comparePlanValidation(t, q) })
		}
		r := rand.New(rand.NewSource(145987))
		for i := 0; i < 128; i++ {
			q := snapshotPlanValue(p)
			switch i % 8 {
			case 0:
				q.Frontend.Metrics = r.Intn(2) == 0
			case 1:
				q.Frontend.MaxRecords = r.Intn(2000) - 1
			case 2:
				q.Parent.PidsMax = uint64(r.Intn(1025))
			case 3:
				q.Ingress.MemoryMax = uint64(r.Intn(1025)) << 20
			case 4:
				q.Reserve.IOBytesPerSecond = uint64(r.Intn(1025)) << 20
			case 5:
				q.Capacity.CPUQuota = uint64(r.Intn(1600001))
			case 6:
				q.Backend.SHA256 = strings.Repeat("a", r.Intn(67))
			case 7:
				q.Self.Path = "/bootstrap/" + strings.Repeat("x", r.Intn(40))
			}
			comparePlanValidation(t, q)
		}
	}
}

func TestRuntimeFileTypedPlanStringsAndSerializedCeiling(t *testing.T) {
	for _, version := range []int{1, 2} {
		p := typedPlanSeed(version)
		var paths []string
		planScalarLeaves(reflect.ValueOf(&p).Elem(), "Plan", func(path string, v reflect.Value) {
			if v.Kind() == reflect.String {
				paths = append(paths, path)
			}
		})
		for _, path := range paths {
			for _, bad := range []string{"\xff", "é", "ſ", "K", "\x00", "\r\n"} {
				q := snapshotPlanValue(p)
				planScalarLeaves(reflect.ValueOf(&q).Elem(), "Plan", func(n string, v reflect.Value) {
					if n == path {
						v.SetString(bad)
					}
				})
				comparePlanValidation(t, q)
				if _, e := validatedPlanValue(q); e == nil {
					t.Fatal("non-ASCII policy string accepted", path)
				}
			}
		}
		for _, size := range []int{MaxPlan - 1, MaxPlan, MaxPlan + 1} {
			q := snapshotPlanValue(p)
			q.Self.Path += strings.Repeat("x", size-len(encode(q)))
			if len(encode(q)) != size {
				t.Fatal("ceiling fixture drift")
			}
			comparePlanValidation(t, q)
			_, e := validatedPlanValue(q)
			if (e == nil) != (size <= MaxPlan) {
				t.Fatal("serialized ceiling changed", size, e)
			}
		}
	}
}

func TestRuntimeFileTypedPlanSnapshotAndDeepComparison(t *testing.T) {
	p := typedPlanSeed(2)
	got, e := validatedPlanValue(p)
	if e != nil || got.Policy == p.Policy || !samePlanValue(got, p) {
		t.Fatal("not a private equivalent snapshot", e)
	}
	before := *p.Policy
	got.Policy.Path += "-changed"
	if *p.Policy != before || samePlanValue(got, p) {
		t.Fatal("policy alias or content comparison lost")
	}
	q := snapshotPlanValue(p)
	q.Policy = nil
	if samePlanValue(p, q) || samePlanValue(q, p) {
		t.Fatal("nil policy mismatch accepted")
	}
	pointers := snapshotPlanValue(p)
	if pointers.Policy == p.Policy || !samePlanValue(pointers, p) {
		t.Fatal("pointer identity substituted for value")
	}
	var names []string
	planScalarLeaves(reflect.ValueOf(&p).Elem(), "Plan", func(n string, v reflect.Value) { names = append(names, n) })
	for _, name := range names {
		q := snapshotPlanValue(p)
		planScalarLeaves(reflect.ValueOf(&q).Elem(), "Plan", func(n string, v reflect.Value) {
			if n != name {
				return
			}
			switch v.Kind() {
			case reflect.Int:
				v.SetInt(v.Int() + 1)
			case reflect.Uint64:
				v.SetUint(v.Uint() + 1)
			case reflect.Bool:
				v.SetBool(!v.Bool())
			case reflect.String:
				v.SetString(v.String() + "x")
			default:
				t.Fatal("unreviewed scalar", n)
			}
		})
		if samePlanValue(p, q) || samePlanValue(q, p) {
			t.Fatal("changed scalar omitted", name)
		}
	}
}

func TestRuntimeFileTypedPlanWireDecoderStaysStrict(t *testing.T) {
	for _, version := range []int{1, 2} {
		raw := strings.TrimSpace(string(encode(typedPlanSeed(version))))
		for _, text := range []string{
			"", "null", "[]", raw + "{}", strings.Repeat(" ", MaxPlan+1),
			raw[:len(raw)-1] + `,"VERSION":1}`, raw[:len(raw)-1] + `,"unknown":true}`,
			strings.Replace(raw, `"self":{`, `"self":{"unknown":true,`, 1),
			strings.Replace(raw, `"release_revision":1`, `"release_revision":"1"`, 1),
			strings.Replace(raw, `"sha256":"`+strings.Repeat("a", 64)+`"`, `"sha256":"`+strings.Repeat("a", 64)+`","SHA256":"`+strings.Repeat("a", 64)+`"`, 1),
		} {
			if _, e := Decode([]byte(text)); e == nil {
				t.Fatal("strict raw decoder bypassed")
			}
		}
		p, e := Decode([]byte(" \t\n" + raw + " \n"))
		if e != nil {
			t.Fatal("valid wire whitespace rejected", e)
		}
		comparePlanValidation(t, p)
	}
}

var planBenchmarkResult Plan

func BenchmarkRuntimeFileTypedPlanValidation(b *testing.B) {
	for _, version := range []int{1, 2} {
		p := typedPlanSeed(version)
		b.Run(fmt.Sprintf("v%d/original-roundtrip", version), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var e error
				planBenchmarkResult, e = originalPlanRoundtrip(p)
				if e != nil {
					b.Fatal(e)
				}
			}
		})
		b.Run(fmt.Sprintf("v%d/typed-shared-policy", version), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var e error
				planBenchmarkResult, e = validatedPlanValue(p)
				if e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}
