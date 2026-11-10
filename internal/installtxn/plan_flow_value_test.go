package installtxn

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/fixedhex"
	"github.com/123123213weqw/Xandbox/internal/launch"
)

// Exact pinned98 Plan flow. Dependency policies are separately compared with
// pinned literal regexp oracles; this baseline never calls candidate plan code.
func originalValidatePlanFlow98(p Plan) error {
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
	if _, e := launch.ValidateLineValue(n); e != nil {
		return ErrPolicy
	}
	g := ingressManifest(p, n, "1:1", map[string]Artifact{"gateway": {SHA256: strings.Repeat("0", 64)}})
	if g.CheckComposition(n) != nil {
		return ErrPolicy
	}
	return nil
}

func TestRuntimeFilePlanFlowAndLineCeilingMatch98(t *testing.T) {
	for _, version := range []int{1, 2} {
		p := typedPlanSeed(version)
		check := func() {
			t.Helper()
			before := encode(p)
			old, got := originalValidatePlanFlow98(p), validatePlan(p)
			if (old == nil) != (got == nil) || old != got || !bytes.Equal(before, encode(p)) {
				t.Fatal("plan policy/error/caller value changed", old, got)
			}
		}
		check()
		planScalarLeaves(reflect.ValueOf(&p).Elem(), "Plan", func(_ string, field reflect.Value) {
			prior := reflect.New(field.Type()).Elem()
			prior.Set(field)
			switch field.Kind() {
			case reflect.String:
				for _, v := range []string{"", "A", "\x00", "ſK", "\ufffd", string([]byte{255}), "<>&", strings.Repeat("x", MaxPlan)} {
					field.SetString(v)
					check()
				}
			case reflect.Int:
				for _, v := range []int64{-1, 0, 1, 64, 65, 10000, 10001, math.MaxInt64, math.MinInt64} {
					field.SetInt(v)
					check()
				}
			case reflect.Uint64:
				for _, v := range []uint64{0, 1, 15, 16, 127, 128, 64 << 20, 1 << 30, 1 << 40, 1<<40 + 1, math.MaxUint64} {
					field.SetUint(v)
					check()
				}
			case reflect.Bool:
				field.SetBool(!field.Bool())
				check()
			default:
				t.Fatal("new plan scalar")
			}
			field.Set(prior)
		})
		p.Policy = nil
		check()
		p.Policy = &firecracker.Asset{Path: "/bootstrap/policy", SHA256: strings.Repeat("a", 64)}
		check()
	}
	// Demonstrate the otherwise-valid case where BARE passes and LINE refuses.
	p := typedPlanSeed(2)
	n := nodeManifest(p, map[string]Artifact{"daemon": {SHA256: strings.Repeat("a", 64)}})
	for _, size := range []int{launch.MaxManifest - 1, launch.MaxManifest, launch.MaxManifest + 1} {
		q := n
		q.Daemon.Path = "/usr/libexec//sandboxd"
		data, _ := json.Marshal(q)
		q.Daemon.Path = "/usr/libexec/" + strings.Repeat("x", size-len(data)) + "/sandboxd"
		data, e := json.Marshal(q)
		if e != nil || len(data) != size {
			t.Fatal("wrong exact node wire size", len(data), e)
		}
		g := ingressManifest(p, q, "1:1", map[string]Artifact{"gateway": {SHA256: strings.Repeat("b", 64)}})
		_, old := launch.ValidateLineValue(q)
		bare := g.CheckComposition(q)
		if nodeLineFitsManifest(q) != (old == nil) || (bare == nil) != (size <= launch.MaxManifest) || (old == nil) != (size < launch.MaxManifest) {
			t.Fatal("lost final-LF ceiling distinction", size, old, bare)
		}
	}
	n.Version = 0
	g := ingressManifest(p, n, "1:1", map[string]Artifact{"gateway": {SHA256: strings.Repeat("b", 64)}})
	if !nodeLineFitsManifest(n) || g.CheckComposition(n) == nil {
		t.Fatal("byte-budget helper was treated as semantic authority")
	}
	// This optimization depends on a closed immutable value, not custom codecs.
	if reflect.TypeOf(n).NumField() != 9 {
		t.Fatal("node schema growth needs review")
	}
	methods := []reflect.Type{reflect.TypeOf((*json.Marshaler)(nil)).Elem(), reflect.TypeOf((*json.Unmarshaler)(nil)).Elem(), reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem(), reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()}
	var inspect func(reflect.Type)
	inspect = func(typ reflect.Type) {
		if !typ.Comparable() {
			t.Fatal("reference growth")
		}
		for _, m := range methods {
			if typ.Implements(m) || reflect.PointerTo(typ).Implements(m) {
				t.Fatal("custom JSON/text normalization")
			}
		}
		if typ.Kind() == reflect.Struct {
			for i := 0; i < typ.NumField(); i++ {
				inspect(typ.Field(i).Type)
			}
		} else if typ.Kind() != reflect.Int && typ.Kind() != reflect.Uint64 && typ.Kind() != reflect.String && typ.Kind() != reflect.Bool {
			t.Fatal("new mutable/normalizing value shape")
		}
	}
	inspect(reflect.TypeOf(n))
}

func TestRuntimeFileSharedFixedHexPinsMatchLiteral98(t *testing.T) {
	for _, width := range []int{32, 40, 64} {
		old := regexp.MustCompile(fmt.Sprintf(`^[0-9a-f]{%d}$`, width))
		v := []byte(strings.Repeat("a", width))
		for i := range v {
			for c := 0; c < 256; c++ {
				v[i] = byte(c)
				text := string(v)
				if fixedhex.Pattern(width).MatchString(text) != old.MatchString(text) {
					t.Fatal("literal regexp language differs", width, i, c)
				}
			}
			v[i] = 'a'
		}
	}
	// Bind deployment call sites, not only the standalone primitive.
	literal40, literal64 := regexp.MustCompile(`^[0-9a-f]{40}$`), regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, text := range []string{strings.Repeat("a", 39), strings.Repeat("a", 40), strings.Repeat("a", 41), strings.Repeat("A", 40), strings.Repeat("a", 40) + "\n"} {
		r := descriptorValueSeed44()
		r.SourceRevision = text
		_, e := descriptor(r)
		if (e == nil) != literal40.MatchString(text) {
			t.Fatal("release revision width binding")
		}
	}
	for _, text := range []string{strings.Repeat("a", 63), strings.Repeat("a", 64), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("a", 64) + "\n"} {
		r := descriptorValueSeed44()
		r.Files[0].SHA256 = text
		_, e := descriptor(r)
		if (e == nil) != literal64.MatchString(text) {
			t.Fatal("release digest width binding")
		}
		p := typedPlanSeed(2)
		n := nodeManifest(p, map[string]Artifact{"daemon": {SHA256: text}})
		_, e = launch.ValidateLineValue(n)
		if (e == nil) != literal64.MatchString(text) {
			t.Fatal("launch digest width binding")
		}
		n.Daemon.SHA256 = strings.Repeat("a", 64)
		g := ingressManifest(p, n, "1:1", map[string]Artifact{"gateway": {SHA256: text}})
		if (g.CheckComposition(n) == nil) != literal64.MatchString(text) {
			t.Fatal("ingress digest width binding")
		}
	}
}

var planFlowBenchmarkError error

// Incremental Plan-flow comparison with the SAME current pin matcher on both
// sides. The separate pinned-regexp benchmarks measure matcher change itself.
func BenchmarkRuntimePlanFlow98(b *testing.B) {
	for _, version := range []int{1, 2} {
		p := typedPlanSeed(version)
		for _, mode := range []string{"original-flow98", "same-policy-once"} {
			b.Run(fmt.Sprintf("%d/%s", version, mode), func(b *testing.B) {
				b.ReportAllocs()
				for n := 0; n < b.N; n++ {
					if mode == "original-flow98" {
						planFlowBenchmarkError = originalValidatePlanFlow98(p)
					} else {
						planFlowBenchmarkError = validatePlan(p)
					}
				}
			})
		}
	}
}

var sharedPinBenchmarkBool bool

func BenchmarkRuntimeFileSharedPins98(b *testing.B) {
	for _, width := range []int{32, 40, 64} {
		old := regexp.MustCompile(fmt.Sprintf(`^[0-9a-f]{%d}$`, width))
		current := fixedhex.Pattern(width)
		for _, c := range []struct{ name, text string }{{"valid", strings.Repeat("a", width)}, {"invalid-last", strings.Repeat("a", width-1) + "g"}} {
			b.Run(fmt.Sprintf("%d/%s/original-regexp98", width, c.name), func(b *testing.B) {
				b.ReportAllocs()
				for n := 0; n < b.N; n++ {
					sharedPinBenchmarkBool = old.MatchString(c.text)
				}
			})
			b.Run(fmt.Sprintf("%d/%s/same-byte-language", width, c.name), func(b *testing.B) {
				b.ReportAllocs()
				for n := 0; n < b.N; n++ {
					sharedPinBenchmarkBool = current.MatchString(c.text)
				}
			})
		}
	}
}
