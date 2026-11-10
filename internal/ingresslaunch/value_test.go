package ingresslaunch

import (
	"bytes"
	"encoding"
	"encoding/json"
	"math"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// Exact pre-change44 oracle; never calls the candidate value helper/predicate.
func originalDecode44(data []byte) (Manifest, error) {
	var m Manifest
	if len(data) > 16384 || strictjson.Decode(data, &m) != nil {
		return m, errPolicy
	}
	if m.Version != 1 || !canonical(m.UnitRoot) || filepath.Dir(m.UnitRoot) != "/sys/fs/cgroup/system.slice" || !unitName.MatchString(filepath.Base(m.UnitRoot)) || !canonical(m.PolicyStateDir) || !strings.HasPrefix(m.PolicyStateDir, "/srv/") || !device.MatchString(m.Device) || m.Device == "0:0" || !validBudget(m.Ingress) || !validBudget(m.Reserve) || !validBudget(m.Capacity) {
		return m, errPolicy
	}
	paths := map[string]bool{}
	for _, a := range []firecracker.Asset{m.Gateway, m.Config, m.NodeLaunch} {
		if !canonical(a.Path) || !sha.MatchString(a.SHA256) || paths[a.Path] || inside(m.PolicyStateDir, a.Path) {
			return m, errPolicy
		}
		paths[a.Path] = true
	}
	if filepath.Base(m.Gateway.Path) != "xandbox-gateway" {
		return m, errPolicy
	}
	return m, nil
}

func originalComposition44(m Manifest, n launch.Manifest) error {
	raw, e := json.Marshal(m)
	if e != nil {
		return errPolicy
	}
	if _, e = originalDecode44(raw); e != nil {
		return errPolicy
	}
	raw, e = json.Marshal(n)
	if e != nil {
		return errPolicy
	}
	if _, e = launch.Decode(raw); e != nil {
		return errPolicy
	}

	if m.UnitRoot == n.UnitRoot || inside(n.StateDir, m.PolicyStateDir) || inside(m.PolicyStateDir, n.StateDir) || inside(n.InputDir, m.PolicyStateDir) || inside(m.PolicyStateDir, n.InputDir) {
		return errPolicy
	}
	dimensions := func(p launch.ParentEnvelope) []uint64 {
		return []uint64{p.MemoryMax, p.PidsMax, p.CPUQuota, p.IOBytesPerSecond, p.IOOperationsPerSecond}
	}
	cap, ing, res, node := dimensions(m.Capacity), dimensions(m.Ingress), dimensions(m.Reserve), dimensions(n.Parent)
	for i, total := range cap {
		for _, used := range []uint64{ing[i], res[i], node[i]} {
			if used > total {
				return errPolicy
			}
			total -= used
		}
	}
	return nil
}

func cloneValue(m Manifest) Manifest { return m }

func compareValue44(t *testing.T, m Manifest) {
	t.Helper()
	raw, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	for _, line := range []bool{false, true} {
		data := append([]byte(nil), raw...)
		if line {
			data = append(data, '\n')
		}
		want, oldErr := originalDecode44(data)
		var got Manifest
		var newErr error
		if line {
			continue
		}
		got, newErr = ValidateValue(m)
		if (oldErr == nil) != (newErr == nil) || !reflect.DeepEqual(want, got) {
			t.Fatal("typed validation diverged", line, oldErr, newErr)
		}
	}
}
func TestTypedValueSharedSchemaAndScalarOracle44(t *testing.T) {
	m := policy()
	before, _ := json.Marshal(m)
	mar := reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	unmar := reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	tm := reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
	tu := reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()
	var inspect func(reflect.Type, int)
	inspect = func(typ reflect.Type, depth int) {
		if depth > 12 || typ.Implements(mar) || typ.Implements(unmar) || typ.Implements(tm) || typ.Implements(tu) || reflect.PointerTo(typ).Implements(mar) || reflect.PointerTo(typ).Implements(unmar) || reflect.PointerTo(typ).Implements(tm) || reflect.PointerTo(typ).Implements(tu) {
			t.Fatal("custom/recursive schema normalization needs review")
		}
		switch typ.Kind() {
		case reflect.Struct:
			seen := map[string]bool{}
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				tag := strings.Split(f.Tag.Get("json"), ",")[0]
				if f.PkgPath != "" || f.Anonymous || tag == "" || seen[tag] {
					t.Fatal("non-closed tag schema")
				}
				seen[tag] = true
				inspect(f.Type, depth+1)
			}
		case reflect.Slice:
			t.Fatal("new reference shape")
		case reflect.Int, reflect.Int64, reflect.Uint64, reflect.Bool, reflect.String:
		default:
			t.Fatal("new scalar/reference shape", typ)
		}
	}
	inspect(reflect.TypeOf(m), 0)
	// Canonical typed scalar changes: accepted AND rejected old values, Unicode
	// normalization, endpoints/overflow; do not use only reordered map JSON.
	var walk func(reflect.Value, []int)
	walk = func(v reflect.Value, path []int) {
		if v.Kind() == reflect.Struct {
			for i := 0; i < v.NumField(); i++ {
				walk(v.Field(i), append(append([]int(nil), path...), i))
			}
			return
		}
		if v.Kind() == reflect.Slice {
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i), append(append([]int(nil), path...), -i-1))
			}
			return
		}
		values := []any{}
		switch v.Kind() {
		case reflect.String:
			values = []any{"", "A", "\x00", "\r\n", "<>&", "ſK", string([]byte{0xff}), v.String() + string([]byte{0xff}), v.String()}
		case reflect.Bool:
			values = []any{true, false}
		case reflect.Int, reflect.Int64:
			values = []any{int64(-1), int64(0), int64(1), int64(64), int64(65), int64(10000), int64(10001), int64(math.MaxInt64), int64(math.MinInt64)}
		case reflect.Uint64:
			values = []any{uint64(0), uint64(1), uint64(15), uint64(16), uint64(127), uint64(128), uint64(64 << 20), uint64(1 << 30), uint64(1 << 40), uint64(1<<40 + 1), ^uint64(0)}
		}
		for _, value := range values {
			copy := cloneValue(m)
			leaf := reflect.ValueOf(&copy).Elem()
			for _, i := range path {
				if i < 0 {
					leaf = leaf.Index(-i - 1)
				} else {
					leaf = leaf.Field(i)
				}
			}
			switch leaf.Kind() {
			case reflect.String:
				leaf.SetString(value.(string))
			case reflect.Bool:
				leaf.SetBool(value.(bool))
			case reflect.Int, reflect.Int64:
				leaf.SetInt(value.(int64))
			case reflect.Uint64:
				leaf.SetUint(value.(uint64))
			}
			compareValue44(t, copy)
		}
	}
	walk(reflect.ValueOf(m), nil)
	after, _ := json.Marshal(m)
	if !bytes.Equal(before, after) {
		t.Fatal("caller value mutated")
	}
	compareValue44(t, m)
}
func TestTypedValueWireAndSerializedBoundariesStayIndependent44(t *testing.T) {
	m := policy()
	base, _ := json.Marshal(m)
	cases := [][]byte{base, nil, []byte("null"), []byte("{}"), append(append([]byte(nil), base...), []byte("{}")...), append([]byte(`{"unknown":true,`), base[1:]...), append([]byte(`{"version":1,`), base[1:]...), append([]byte(`{"Version":1,`), base[1:]...), append([]byte(`{"verſion":1,`), base[1:]...), bytes.Replace(base, []byte(`"version":1`), []byte(`"version":null`), 1)}
	for _, raw := range cases {
		old, e := originalDecode44(raw)
		got, x := Decode(raw)
		if (e == nil) != (x == nil) || !reflect.DeepEqual(old, got) {
			t.Fatal("raw decoder changed", e, x)
		}
	}
	for _, target := range []int{16383, 16384, 16385} {
		copy := cloneValue(m)
		copy.PolicyStateDir = "/srv/"
		b, _ := json.Marshal(copy)
		copy.PolicyStateDir += strings.Repeat("x", target-len(b))
		raw, _ := json.Marshal(copy)
		if len(raw) != target {
			t.Fatal("wrong serialized boundary")
		}
		compareValue44(t, copy)
	}
	// UTF-8 behavior is relevant even for rejected manifests and must not create
	// a silent normalization/policy difference from the old roundtrip.
	if utf8.ValidString(string([]byte{0xff})) {
		t.Fatal("invalid UTF-8 control")
	}
}
func BenchmarkTypedValueManifest44(b *testing.B) {
	m := policy()
	for _, kind := range []string{"old44", "typed"} {
		b.Run(kind, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var e error
				if kind == "old44" {
					raw, _ := json.Marshal(m)
					_, e = originalDecode44(raw)
				} else {
					_, e = ValidateValue(m)
				}
				if e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}

// All JSON-normalized strings must remain covered by the UTF-8 fallback.
func TestTypedValueUTF8FieldRoster44(t *testing.T) {
	want := map[string]bool{"UnitRoot": true, "PolicyStateDir": true, "Gateway.Path": true, "Gateway.SHA256": true, "Config.Path": true, "Config.SHA256": true, "NodeLaunch.Path": true, "NodeLaunch.SHA256": true, "Device": true}
	got := map[string]bool{}
	var walk func(reflect.Type, string)
	walk = func(typ reflect.Type, prefix string) {
		switch typ.Kind() {
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				name := f.Name
				if prefix != "" {
					name = prefix + "." + name
				}
				walk(f.Type, name)
			}
		case reflect.Slice:
			walk(typ.Elem(), prefix+"[]")
		case reflect.String:
			got[prefix] = true
		}
	}
	walk(reflect.TypeOf(Manifest{}), "")
	if !reflect.DeepEqual(want, got) {
		t.Fatal("string schema changed: update normalization review", got)
	}
}

func TestTypedValueCompositionOriginal44(t *testing.T) {
	check := func(m Manifest, n launch.Manifest, want bool) {
		t.Helper()
		old, got := originalComposition44(m, n), m.CheckComposition(n)
		if (old == nil) != (got == nil) || (got == nil) != want {
			t.Fatal("composition changed", old, got, want)
		}
	}
	check(policy(), nodePolicy(), true)
	for dim := 0; dim < 5; dim++ {
		m, n := policy(), nodePolicy()
		cap := reflect.ValueOf(&m.Capacity).Elem().Field(dim)
		ing := reflect.ValueOf(m.Ingress).Field(dim).Uint()
		res := reflect.ValueOf(m.Reserve).Field(dim).Uint()
		node := reflect.ValueOf(n.Parent).Field(dim).Uint()
		cap.SetUint(ing + res + node)
		check(m, n, true)
		cap.SetUint(ing + res + node - 1)
		check(m, n, false)
		cap.SetUint(math.MaxUint64)
		check(m, n, false)
		m = policy()
		reflect.ValueOf(&m.Ingress).Elem().Field(dim).SetUint(math.MaxUint64)
		check(m, n, false)
		m = policy()
		reflect.ValueOf(&n.Parent).Elem().Field(dim).SetUint(math.MaxUint64)
		check(m, n, false)
	}
	for _, mutate := range []func(*Manifest, *launch.Manifest){
		func(m *Manifest, n *launch.Manifest) { m.UnitRoot = n.UnitRoot },
		func(m *Manifest, n *launch.Manifest) { m.PolicyStateDir = n.StateDir },
		func(m *Manifest, n *launch.Manifest) { m.PolicyStateDir = n.StateDir + "/child" },
		func(m *Manifest, n *launch.Manifest) { m.PolicyStateDir = "/srv/xb" },
		func(m *Manifest, n *launch.Manifest) { m.Config.Path = m.NodeLaunch.Path },
		func(m *Manifest, n *launch.Manifest) { n.Version = 0 },
		func(m *Manifest, n *launch.Manifest) { m.Device = "0:0" },
		func(m *Manifest, n *launch.Manifest) { m.PolicyStateDir += "\xff" },
		func(m *Manifest, n *launch.Manifest) { n.StateDir = "/srv/" + strings.Repeat("<", 3000) },
	} {
		m, n := policy(), nodePolicy()
		mutate(&m, &n)
		check(m, n, false)
	}
	// Node's accepted UTF-8 replacement is not permission to alter the original
	// values used by the subsequent, unchanged composition comparisons.
	m, n := policy(), nodePolicy()
	n.StateDir = "/srv/" + string([]byte{0xff})
	check(m, n, true)
}
func BenchmarkTypedValueComposition44(b *testing.B) {
	m, n := policy(), nodePolicy()
	for _, kind := range []string{"old44", "typed"} {
		b.Run(kind, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var e error
				if kind == "old44" {
					e = originalComposition44(m, n)
				} else {
					e = m.CheckComposition(n)
				}
				if e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}
