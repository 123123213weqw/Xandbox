package installtxn

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// Exact pinned5f30 pure file-list oracle; never calls the candidate validator.
func originalFileList5f30(t transaction) bool {
	if t.Version != 1 || t.Revision != 1 || !requestPattern.MatchString(t.RequestID) {
		return false
	}
	p, e := validatedPlanValue(t.Plan)
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
	art, err := descriptor(t.Release)
	if err != nil || digest(encode(t.Release)) != t.Plan.Release {
		return false
	}
	if len(t.Files) != len(expected) {
		return false
	}
	for _, v := range t.Files {
		mode, ok := expected[v.Path]
		if !ok || mode != v.Mode || v.Bytes < 1 || v.Bytes > 512<<20 || !digestPattern.MatchString(v.SHA256) {
			return false
		}
		if v.Path == SelfPath && v.SHA256 != t.Plan.Self.SHA256 {
			return false
		}
		sourcePins := map[string]string{}
		for _, input := range planInputs(t.Plan) {
			sourcePins[Root+"/"+input.name] = input.a.SHA256
		}
		if pin, ok := sourcePins[v.Path]; ok && v.SHA256 != pin {
			return false
		}
		for role, a := range art {
			if v.Path == rolePath(role) || (role == "gateway" && v.Path == childRoot+"/gateway") {
				if v.SHA256 != a.SHA256 || v.Bytes != a.Bytes {
					return false
				}
			}
		}
		delete(expected, v.Path)
	}
	return len(expected) == 0
}

// Exact old post-read expression, including the returned value on errors.
func originalTransactionBytes5f30(raw []byte) (transaction, error) {
	var t transaction
	if strictjson.Decode(raw, &t) != nil || !originalFileList5f30(t) || !bytes.Equal(raw, encode(t)) {
		return t, ErrInventory
	}
	return t, nil
}
func transactionValueSeed(version int) transaction {
	p := typedPlanSeed(version)
	release := descriptorValueSeed44()
	p.Release = digest(encode(release))
	tx := transaction{Version: 1, Revision: 1, RequestID: strings.Repeat("a", 32), Plan: p, Release: release}
	paths := map[string]File{}
	add := func(path, hash string, size int64, mode uint32) {
		if _, ok := paths[path]; ok {
			panic("fixture path alias")
		}
		paths[path] = File{path, hash, size, mode}
	}
	add(SelfPath, p.Self.SHA256, 1, 0555)
	add(childRoot+"/gateway", strings.Repeat("b", 64), 1, 0555)
	for _, unit := range []string{MainUnit, IngressUnit} {
		add(UnitDir+"/"+unit, strings.Repeat("c", 64), 1, 0600)
	}
	sourcePins := map[string]string{}
	for _, v := range planInputs(p) {
		sourcePins[v.name] = v.a.SHA256
	}
	for _, name := range configNamesFor(version) {
		hash := sourcePins[name]
		if hash == "" {
			hash = strings.Repeat("c", 64)
		}
		add(Root+"/"+name, hash, 1, 0600)
	}
	for _, a := range release.Files {
		mode := uint32(0444)
		if executable(a.Role) {
			mode = 0555
		}
		add(rolePath(a.Role), a.SHA256, a.Bytes, mode)
	}
	names := []string{}
	for name := range paths {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		tx.Files = append(tx.Files, paths[name])
	}
	return tx
}
func cloneTransactionValue(t transaction) transaction {
	t.Plan = snapshotPlanValue(t.Plan)
	if t.Files != nil {
		t.Files = append([]File{}, t.Files...)
	}
	if t.Release.Files != nil {
		t.Release.Files = append([]Artifact{}, t.Release.Files...)
	}
	return t
}
func compareTransactionPolicy(t *testing.T, q transaction) {
	t.Helper()
	before := encode(q)
	old, got := originalFileList5f30(q), validFileList(q)
	if old != got || !bytes.Equal(before, encode(q)) {
		t.Fatal("file policy or caller value changed")
	}
}
func compareTransactionRaw(t *testing.T, raw []byte) {
	t.Helper()
	before := append([]byte(nil), raw...)
	want, e := originalTransactionBytes5f30(raw)
	got, x := decodeTransactionBytes(raw)
	if (e == nil) != (x == nil) || errors.Is(e, ErrInventory) != errors.Is(x, ErrInventory) || !reflect.DeepEqual(want, got) || !bytes.Equal(raw, before) {
		t.Fatal("wire policy or complete error-return value diverged")
	}
}
func TestRuntimeFileTransactionPolicyMatchesPinned5f30(t *testing.T) {
	for _, version := range []int{1, 2} {
		seed := transactionValueSeed(version)
		if !originalFileList5f30(seed) || !validFileList(seed) {
			t.Fatal("invalid seed")
		}
		compareTransactionPolicy(t, seed)
		for i := range seed.Files {
			for _, field := range []string{"Path", "SHA256", "Bytes", "Mode"} {
				q := cloneTransactionValue(seed)
				f := reflect.ValueOf(&q.Files[i]).Elem().FieldByName(field)
				switch f.Kind() {
				case reflect.String:
					for _, s := range []string{"", "foreign", "/alias/../file", "\xff", strings.Repeat("f", 64)} {
						f.SetString(s)
						compareTransactionPolicy(t, q)
					}
				case reflect.Int64:
					for _, n := range []int64{-1, 0, 1, 512 << 20, (512 << 20) + 1, math.MaxInt64} {
						f.SetInt(n)
						compareTransactionPolicy(t, q)
					}
				case reflect.Uint32:
					for _, n := range []uint64{0, 0444, 0555, 0600, math.MaxUint32} {
						f.SetUint(n)
						compareTransactionPolicy(t, q)
					}
				}
			}
		}
		for i := range seed.Release.Files {
			for _, field := range []string{"Role", "SHA256", "Bytes"} {
				q := cloneTransactionValue(seed)
				f := reflect.ValueOf(&q.Release.Files[i]).Elem().FieldByName(field)
				if f.Kind() == reflect.Int64 {
					f.SetInt(math.MaxInt64)
				} else {
					f.SetString("invalid")
				}
				q.Plan.Release = digest(encode(q.Release))
				compareTransactionPolicy(t, q)
			}
		}
		changes := []func(*transaction){
			func(q *transaction) { q.Version = 0 }, func(q *transaction) { q.Revision = math.MaxUint64 }, func(q *transaction) { q.RequestID = strings.Repeat("A", 32) }, func(q *transaction) { q.Plan.Release = "bad" },
			func(q *transaction) { q.Files = nil }, func(q *transaction) { q.Files = []File{} }, func(q *transaction) { q.Files = q.Files[1:] }, func(q *transaction) { q.Files = append(q.Files, q.Files[0]) }, func(q *transaction) { q.Files[1] = q.Files[0] },
			func(q *transaction) {
				for i, j := 0, len(q.Files)-1; i < j; i, j = i+1, j-1 {
					q.Files[i], q.Files[j] = q.Files[j], q.Files[i]
				}
			},
			func(q *transaction) { q.Release.Files = nil; q.Plan.Release = digest(encode(q.Release)) }, func(q *transaction) {
				q.Release.Files[0], q.Release.Files[1] = q.Release.Files[1], q.Release.Files[0]
				q.Plan.Release = digest(encode(q.Release))
			},
			func(q *transaction) { q.Plan.Auth.SHA256 = strings.Repeat("f", 64) },
			func(q *transaction) {
				q.Plan.Auth.SHA256 = strings.Repeat("f", 64)
				for i := range q.Files {
					if q.Files[i].Path == Root+"/auth.json" {
						q.Files[i].SHA256 = q.Plan.Auth.SHA256
					}
				}
			},
			func(q *transaction) {
				q.Plan.Self.SHA256 = strings.Repeat("e", 64)
				for i := range q.Files {
					if q.Files[i].Path == SelfPath {
						q.Files[i].SHA256 = q.Plan.Self.SHA256
					}
				}
			},
		}
		for _, change := range changes {
			q := cloneTransactionValue(seed)
			change(&q)
			compareTransactionPolicy(t, q)
			compareTransactionRaw(t, encode(q))
		}
	}
}
func TestRuntimeFileTransactionCanonicalWireAndErrorValuesMatch5f30(t *testing.T) {
	for _, version := range []int{1, 2} {
		seed := transactionValueSeed(version)
		raw := encode(seed)
		compareTransactionRaw(t, raw)
		cases := [][]byte{nil, []byte("null\n"), []byte("{}\n"), []byte("[]\n"), raw[:len(raw)-1], append([]byte(" "), raw...), append(append([]byte(nil), raw...), '\n'), append(append([]byte(nil), raw...), []byte("{}")...), append([]byte(`{"unknown":1,`), raw[1:]...), append([]byte(`{"version":1,`), raw[1:]...), append([]byte(`{"Version":1,`), raw[1:]...), append([]byte(`{"verſion":1,`), raw[1:]...), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":null`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1.0`), 1), bytes.Replace(raw, []byte(`"revision":1`), []byte(`"revision":18446744073709551616`), 1), bytes.Replace(raw, []byte(`"revision":1`), []byte(`"revision":-1`), 1), bytes.Replace(raw, []byte(`"plan":{`), []byte(`"plan":{"unknown":true,`), 1), bytes.Replace(raw, []byte(`"mode":`), []byte(`"Mode":`), 1), bytes.Replace(raw, []byte(`"request_id":`), []byte(`"request_id":"x","request_id":`), 1)}
		cases = append(cases, append([]byte(`{"unknown":`+strings.Repeat("[", 65)+"0"+strings.Repeat("]", 65)+","), raw[1:]...))
		cases = append(cases, append([]byte(`{"unknown":"`+strings.Repeat("{", 70)+`",`), raw[1:]...))
		for _, data := range cases {
			compareTransactionRaw(t, data)
		}
		for i := 0; i < len(raw); i += 97 {
			compareTransactionRaw(t, raw[:i])
		}
		// Accepted-with-error values are deliberately not zero: old canonical-LF
		// rejection decodes the entire valid value before reporting ErrInventory.
		old, e := originalTransactionBytes5f30(raw[:len(raw)-1])
		if e == nil || reflect.DeepEqual(old, transaction{}) {
			t.Fatal("error-return-value control drift")
		}
		for _, size := range []int{MaxPlan - 1, MaxPlan, MaxPlan + 1, 65535, 65536, 65537} {
			q := cloneTransactionValue(seed)
			q.Plan.Self.Path = "/bootstrap/"
			n := size - len(encode(q))
			if n < 0 {
				t.Fatal("seed too large")
			}
			q.Plan.Self.Path += strings.Repeat("x", n)
			b := encode(q)
			if len(b) != size {
				t.Fatal("size control drift")
			}
			compareTransactionRaw(t, b)
		}
		for _, s := range []string{"\xff", "é", "ſK", "\x00", "\r\n", "<>&"} {
			q := cloneTransactionValue(seed)
			q.Plan.Self.Path = "/bootstrap/" + s
			compareTransactionRaw(t, encode(q))
		}
		state := uint32(0x391f5)
		for i := 0; i < 1024; i++ {
			b := append([]byte(nil), raw...)
			for j := 0; j < 1+i%4; j++ {
				state = 1664525*state + 1013904223
				b[int(state)%len(b)] = byte(state >> 24)
			}
			compareTransactionRaw(t, b)
		}
	}
}
func TestRuntimeFileTransactionClosedSchemaAndFreshReferences(t *testing.T) {
	expected := map[reflect.Type][]string{
		reflect.TypeOf(transaction{}): {"Version/version/int", "Revision/revision/uint64", "RequestID/request_id/string", "Plan/plan/struct", "Release/release/struct", "Files/files/slice"},
		reflect.TypeOf(Release{}):     {"Version/version/int", "SourceRevision/source_revision/string", "Toolchain/toolchain/string", "GOARCH/goarch/string", "Files/files/slice"},
		reflect.TypeOf(Artifact{}):    {"Role/role/string", "SHA256/sha256/string", "Bytes/bytes/int64"},
		reflect.TypeOf(File{}):        {"Path/path/string", "SHA256/sha256/string", "Bytes/bytes/int64", "Mode/mode/uint32"},
	}
	for typ, fields := range expected {
		if typ.NumField() != len(fields) {
			t.Fatal("transaction schema changed")
		}
		for i, want := range fields {
			f := typ.Field(i)
			if f.Name+"/"+f.Tag.Get("json")+"/"+f.Type.Kind().String() != want {
				t.Fatal("transaction field schema changed")
			}
		}
	}
	mar := reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	unmar := reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	tm := reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
	tu := reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()
	var inspect func(reflect.Type, string, int)
	inspect = func(typ reflect.Type, path string, depth int) {
		if depth > 12 || typ.Implements(mar) || typ.Implements(unmar) || typ.Implements(tm) || typ.Implements(tu) || reflect.PointerTo(typ).Implements(mar) || reflect.PointerTo(typ).Implements(unmar) || reflect.PointerTo(typ).Implements(tm) || reflect.PointerTo(typ).Implements(tu) {
			t.Fatal("custom/recursive JSON schema needs review")
		}
		switch typ.Kind() {
		case reflect.Struct:
			seen := map[string]bool{}
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				parts := strings.Split(f.Tag.Get("json"), ",")
				tag := parts[0]
				if f.PkgPath != "" || f.Anonymous || tag == "" || strings.Trim(tag, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" || seen[tag] {
					t.Fatal("ambiguous or non-closed tag schema")
				}
				seen[tag] = true
				if len(parts) > 1 && (path+"."+f.Name != "transaction.Plan.Policy" || f.Tag.Get("json") != "policy,omitempty") {
					t.Fatal("new JSON options")
				}
				inspect(f.Type, path+"."+f.Name, depth+1)
			}
		case reflect.Pointer:
			if path != "transaction.Plan.Policy" || typ.Elem() != reflect.TypeOf(firecracker.Asset{}) {
				t.Fatal("new reference field")
			}
			inspect(typ.Elem(), path, depth+1)
		case reflect.Slice:
			if !((path == "transaction.Files" && typ.Elem() == reflect.TypeOf(File{})) || (path == "transaction.Release.Files" && typ.Elem() == reflect.TypeOf(Artifact{}))) {
				t.Fatal("new slice field")
			}
			inspect(typ.Elem(), path+"[]", depth+1)
		case reflect.String, reflect.Bool, reflect.Int, reflect.Int64, reflect.Uint32, reflect.Uint64:
		default:
			t.Fatal("new non-closed kind")
		}
	}
	inspect(reflect.TypeOf(transaction{}), "transaction", 0)
	seed := transactionValueSeed(2)
	raw := encode(seed)
	if bytes.Count(raw, []byte{'{'})+bytes.Count(raw, []byte{'['}) > 64 {
		t.Fatal("closed canonical seed lost the bounded fast path")
	}
	a, e := decodeTransactionBytes(raw)
	b, x := decodeTransactionBytes(raw)
	if e != nil || x != nil {
		t.Fatal(e, x)
	}
	before := encode(b)
	a.Plan.Policy.Path = "/changed-policy"
	a.Release.Files[0].Role = "changed-release"
	a.Files[0].Path = "/changed-file"
	if !bytes.Equal(encode(b), before) || !bytes.Equal(raw, encode(seed)) {
		t.Fatal("decoded references/input alias")
	}
	var wg sync.WaitGroup
	fail := make(chan bool, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 4; k++ {
				v, e := decodeTransactionBytes(raw)
				if e != nil || !bytes.Equal(encode(v), before) {
					fail <- true
					return
				}
				v.Files[0].Path = "/private-mutation"
			}
		}()
	}
	wg.Wait()
	close(fail)
	if len(fail) != 0 {
		t.Fatal("concurrent fresh values changed")
	}
	for i := range raw {
		raw[i] = 0
	}
	if !bytes.Equal(encode(b), before) {
		t.Fatal("decoded strings alias the caller byte buffer")
	}
}
func BenchmarkRuntimeFileTransactionValue(b *testing.B) {
	for _, version := range []int{1, 2} {
		seed := transactionValueSeed(version)
		raw := encode(seed)
		for _, kind := range []string{"policy-old5f30", "policy-candidate", "decode-old5f30", "decode-candidate"} {
			b.Run(fmt.Sprintf("v%d/%s", version, kind), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					switch kind {
					case "policy-old5f30":
						if !originalFileList5f30(seed) {
							b.Fatal("old policy")
						}
					case "policy-candidate":
						if !validFileList(seed) {
							b.Fatal("policy")
						}
					case "decode-old5f30":
						if _, e := originalTransactionBytes5f30(raw); e != nil {
							b.Fatal(e)
						}
					case "decode-candidate":
						if _, e := decodeTransactionBytes(raw); e != nil {
							b.Fatal(e)
						}
					}
				}
			})
		}
	}
}
