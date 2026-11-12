package launch

import (
	"bytes"
	"encoding"
	"encoding/json"
	"math"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// Independent pinned regexp(s), not candidate shared pattern aliases.
var originalSha98 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Exact pre-change44 oracle; never calls the candidate value helper/predicate.
func originalDecode44(data []byte) (Manifest, error) {
	var m Manifest
	if len(data) > 16384 {
		return m, errPolicy
	}
	if e := strictjson.Decode(data, &m); e != nil {
		return m, errPolicy
	}
	f, p := m.Frontend, m.Parent
	if m.Version != 1 || !canonical(m.UnitRoot) || filepath.Dir(m.UnitRoot) != "/sys/fs/cgroup/system.slice" || !unitName.MatchString(filepath.Base(m.UnitRoot)) ||
		m.InputDir != "/run/"+strings.TrimSuffix(filepath.Base(m.UnitRoot), ".service")+"-inputs" || !canonical(m.StateDir) || !strings.HasPrefix(m.StateDir, "/srv/") ||
		f.MaxInstances < 1 || f.MaxInstances > 10000 || f.MaxRecords < f.MaxInstances || f.MaxRecords > sandbox.MaxLedgerRecords || f.MaxTenantRecords < 1 || f.MaxTenantRecords > f.MaxRecords ||
		f.MaxSessions < 1 || f.MaxSessions > 10000 || f.MaxTenantSessions < 1 || f.MaxTenantSessions > f.MaxSessions || f.SessionHistory < 1 || f.SessionHistory > 64 ||
		f.StopWorkers < 1 || f.StopWorkers > 64 || f.CleanupWorkers < 1 || f.CleanupWorkers > 64 || f.WorkQueueSize < 1 || f.WorkQueueSize > 10000 ||
		p.MemoryMax == 0 || p.MemoryMax > 1<<40 || p.PidsMax == 0 || p.PidsMax > 1<<24 || p.CPUQuota == 0 || p.CPUQuota > 1000000000 ||
		p.IOBytesPerSecond < 1<<20 || p.IOBytesPerSecond > 1<<30 || p.IOOperationsPerSecond < 128 || p.IOOperationsPerSecond > 65536 {
		return m, errPolicy
	}
	for _, a := range []firecracker.Asset{m.Daemon, m.Backend, m.Auth} {
		if !canonical(a.Path) || !originalSha98.MatchString(a.SHA256) {
			return m, errPolicy
		}
	}
	if filepath.Base(m.Daemon.Path) != "sandboxd" || m.Backend.Path == m.Auth.Path || inside(m.StateDir, m.Daemon.Path) || inside(m.StateDir, m.Backend.Path) || inside(m.StateDir, m.Auth.Path) {
		return m, errPolicy
	}
	return m, nil
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
			got, newErr = ValidateLineValue(m)
		} else {
			got, newErr = ValidateValue(m)
		}
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
		copy.StateDir = "/srv/"
		b, _ := json.Marshal(copy)
		copy.StateDir += strings.Repeat("x", target-len(b))
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
	want := map[string]bool{"UnitRoot": true, "InputDir": true, "StateDir": true, "Daemon.Path": true, "Daemon.SHA256": true, "Backend.Path": true, "Backend.SHA256": true, "Auth.Path": true, "Auth.SHA256": true}
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

func TestTypedValueRawEscapesAndAcceptedUTF8Normalization44(t *testing.T) {
	m := policy()
	m.StateDir = "/srv/" + string([]byte{0xff})
	raw, _ := json.Marshal(m)
	old, e := originalDecode44(raw)
	if e != nil || old.StateDir == m.StateDir || !utf8.ValidString(old.StateDir) {
		t.Fatal("normalization control was not accepted")
	}
	compareValue44(t, m)
	// Raw decoding budgets the ACTUAL received bytes, not json.Marshal's HTML
	// escape expansion. Typed validation budgets the old constructed roundtrip.
	m.StateDir = "/srv/" + strings.Repeat("<", 3000)
	escaped, _ := json.Marshal(m)
	raw = bytes.ReplaceAll(escaped, []byte(`\u003c`), []byte("<"))
	if len(raw) >= MaxManifest || len(escaped) <= MaxManifest {
		t.Fatal("invalid length control")
	}
	for _, decode := range []func([]byte) (Manifest, error){originalDecode44, Decode} {
		got, e := decode(raw)
		if e != nil || got != m {
			t.Fatal("raw canonical expansion changed wire acceptance", e)
		}
	}
	if _, e := ValidateValue(m); e == nil {
		t.Fatal("typed serialized ceiling waived")
	}
	compareValue44(t, m)
}
