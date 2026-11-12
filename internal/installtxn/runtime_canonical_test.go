package installtxn

import (
	"bytes"
	"encoding"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

func canonicalWorkSeed() (runtimeWorkStopIntent, runtimeWorkCompletion, runtimeCloseIntent, runtimeCloseCompletion) {
	process := nodecontrol.ProcessIdentity{PID: 123, BootID: "00000000-0000-0000-0000-000000000000", StartTicks: 17}
	before := nodecontrol.State{Version: 1, Epoch: strings.Repeat("a", 32), Revision: 2, Mode: nodecontrol.ModeOpen, LastRequestID: strings.Repeat("b", 32), LastExpectedRevision: 1}
	base, operation := strings.Repeat("c", 64), strings.Repeat("d", 32)
	owner := nodecontrol.MaintenanceRecord{Version: 1, Before: before, Request: nodecontrol.MaintenanceRequest{Version: 1, Owner: nodecontrol.MaintenanceOwner{Version: 1, InstallCommitSHA256: base, OperationID: operation}, Command: nodecontrol.Command{Version: 1, Epoch: before.Epoch, ExpectedRevision: before.Revision, RequestID: strings.Repeat("e", 32)}}}
	drain := runtimeDrainIntent{Version: 2, Base: base, Request: operation, Process: process, Before: before, Maintenance: &owner}
	ingress := process
	ingress.PID++
	stop := runtimeStopIntent{Version: 2, Base: base, Request: operation, Drain: digest(encode(drain)), Main: process, Ingress: &ingress, State: &runtimeStateIdentity{RootDevice: 1, RootInode: 2, LockDevice: 1, LockInode: 3, LockChangeSeconds: 4}}
	p := runtimeWorkStopIntent{Version: 1, Policy: "finish-only-v1", Drain: drain, Stop: stop}
	w := runtimeWorkCompletion{Version: 1, Input: digest(encode(p)), Work: sandbox.AcceptedWorkStatus{Version: 1, Frozen: true, Succeeded: 3}}
	stop.Version, stop.Work = 3, digest(encode(w))
	c := runtimeCloseIntent{Version: 1, Policy: "close-bound-runtime-v1", Input: digest(encode(p)), Stop: stop}
	r := runtimeCloseCompletion{Version: 1, Input: digest(encode(c)), Work: w.Work, Core: sandbox.ClosureObservation{Version: 1, Records: 1, RecordsSHA256: strings.Repeat("f", 64)}, Sessions: session.ClosureObservation{Version: 1, Records: 1, RecordsSHA256: strings.Repeat("a", 64)}}
	return p, w, c, r
}
func canonicalRecordSeeds() []any { p, w, c, r := canonicalWorkSeed(); return []any{p, w, c, r} }

// Independent original ce053ce expression. No candidate decoder/helper here.
func originalCanonicalPredicateCe053(data []byte, out any) bool {
	return strictjson.Decode(data, out) == nil && bytes.Equal(data, encode(out))
}
func freshCanonicalValue(seed any) any { return reflect.New(reflect.TypeOf(seed)).Interface() }
func cloneCanonicalValue(seed any) any {
	v := freshCanonicalValue(seed)
	if json.Unmarshal(encode(seed), v) != nil {
		panic("test seed")
	}
	return v
}

func TestRuntimeWorkCanonicalClosedSchemaContract(t *testing.T) {
	marshaler := reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	unmarshaler := reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	textMarshaler := reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
	textUnmarshaler := reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()
	pointers := 0
	var inspect func(reflect.Type, int)
	inspect = func(typ reflect.Type, depth int) {
		if typ.Implements(textMarshaler) || typ.Implements(textUnmarshaler) || reflect.PointerTo(typ).Implements(textMarshaler) || reflect.PointerTo(typ).Implements(textUnmarshaler) {
			t.Fatal("custom text normalization requires review", typ)
		}
		if depth > 16 || typ.Implements(marshaler) || typ.Implements(unmarshaler) || reflect.PointerTo(typ).Implements(marshaler) || reflect.PointerTo(typ).Implements(unmarshaler) {
			t.Fatal("recursive/custom JSON schema requires review", typ)
		}
		switch typ.Kind() {
		case reflect.Pointer:
			pointers++
			elem := typ.Elem()
			if elem != reflect.TypeOf(nodecontrol.MaintenanceRecord{}) && elem != reflect.TypeOf(nodecontrol.ProcessIdentity{}) && elem != reflect.TypeOf(runtimeStateIdentity{}) {
				t.Fatal("new reference kind", typ)
			}
			inspect(elem, depth+1)
		case reflect.Struct:
			seen := map[string]bool{}
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				tag := strings.Split(f.Tag.Get("json"), ",")[0]
				if f.PkgPath != "" || f.Anonymous || tag == "" || strings.Trim(tag, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" || seen[tag] {
					t.Fatal("not a closed unambiguous ASCII JSON schema", typ, f.Name)
				}
				seen[tag] = true
				inspect(f.Type, depth+1)
			}
		case reflect.Int, reflect.Int64, reflect.Uint64, reflect.String, reflect.Bool:
		default:
			t.Fatal("non-closed JSON normalization/reference type", typ)
		}
	}
	for _, seed := range canonicalRecordSeeds() {
		typ := reflect.TypeOf(seed)
		if !typ.Comparable() {
			t.Fatal("record no longer comparable", typ)
		}
		inspect(typ, 0)
	}
	if pointers != 5 {
		t.Fatal("reference growth needs review", pointers)
	}
}

// Include CANONICAL invalid semantic values too: the decoder must NOT quietly
// replace the separate validators with a lighter semantic policy.
func canonicalRawCorpus(seed any) [][]byte {
	data := encode(seed)
	out := [][]byte{data, nil, []byte("{}\n"), []byte("null\n"), []byte("[]\n"), []byte(" "), append([]byte(" "), data...), append(append([]byte(nil), data...), byte(' ')), bytes.TrimSuffix(data, []byte("\n")), append(append([]byte(nil), data...), data...)}
	for _, prefix := range []string{`"unknown":0,`, `"version":1,`, `"Version":1,`, `"ver\u0073ion":1,`, `"verſion":1,`, `"\u0076ersion":null,`} {
		out = append(out, append(append([]byte("{"), prefix...), data[1:]...))
	}
	for _, value := range []string{"null", "-0", "1.0", "1e0", "true", "[]", "{}", "\"1\"", "18446744073709551616", "-9223372036854775809", "NaN"} {
		out = append(out, bytes.Replace(data, []byte(`"version":1`), []byte(`"version":`+value), 1))
	}
	var generic map[string]any
	_ = json.Unmarshal(data, &generic)
	for name := range generic {
		// Per-field unknown, folded duplicate, null/wrong type and omission forms.
		for _, value := range []any{nil, true, "text", []any{}, map[string]any{}, json.Number("18446744073709551616")} {
			copy := map[string]any{}
			for k, v := range generic {
				copy[k] = v
			}
			copy[name] = value
			b, _ := json.Marshal(copy)
			out = append(out, append(b, '\n'))
		}
		copy := map[string]any{}
		for k, v := range generic {
			if k != name {
				copy[k] = v
			}
		}
		b, _ := json.Marshal(copy)
		out = append(out, append(b, '\n'))
	}
	for i := range data {
		for _, c := range []byte{0, '{', '}', ':', ',', '"', '\\', 0xff} {
			b := append([]byte(nil), data...)
			b[i] = c
			out = append(out, b)
		}
	}
	state := uint32(0x7a9451)
	for i := 0; i < 512; i++ {
		b := append([]byte(nil), data...)
		for j := 0; j < 1+i%5; j++ {
			state = 1664525*state + 1013904223
			b[int(state)%len(b)] = byte(state >> 24)
		}
		out = append(out, b)
	}
	for _, n := range []int{MaxPlan - 1, MaxPlan, MaxPlan + 1} {
		out = append(out, []byte(`{"version":1,"unknown":"`+strings.Repeat("x", n)+`"}`+"\n"))
	}
	out = append(out, []byte(`{"version":`+strings.Repeat("[", 66)+`0`+strings.Repeat("]", 66)+"}\n"))
	return out
}

// Marshal independently mutated typed leaves so invalid semantic values stay
// canonical/in-order. Map reserialization alone would only test key ordering.
func canonicalScalarCorpus(seed any) [][]byte {
	var out [][]byte
	var visit func(reflect.Value, []int)
	visit = func(v reflect.Value, path []int) {
		if v.Kind() == reflect.Pointer {
			if !v.IsNil() {
				visit(v.Elem(), path)
			}
			return
		}
		if v.Kind() == reflect.Struct {
			for i := 0; i < v.NumField(); i++ {
				visit(v.Field(i), append(append([]int(nil), path...), i))
			}
			return
		}
		values := []any{}
		switch v.Kind() {
		case reflect.Int, reflect.Int64:
			values = []any{int64(-1), int64(0), int64(1), int64(-1 << (v.Type().Bits() - 1)), int64(1<<(v.Type().Bits()-1) - 1)}
		case reflect.Uint64:
			values = []any{uint64(0), uint64(1), ^uint64(0)}
		case reflect.String:
			values = []any{"", "A", "\x00", "\ufffd", "ſK", string([]byte{0xff}), "<>&"}
		case reflect.Bool:
			values = []any{false, true}
		default:
			panic("test schema kind")
		}
		for _, value := range values {
			copy := cloneCanonicalValue(seed)
			leaf := reflect.ValueOf(copy)
			for _, field := range path {
				if leaf.Kind() == reflect.Pointer {
					leaf = leaf.Elem()
				}
				leaf = leaf.Field(field)
			}
			switch leaf.Kind() {
			case reflect.Int, reflect.Int64:
				leaf.SetInt(value.(int64))
			case reflect.Uint64:
				leaf.SetUint(value.(uint64))
			case reflect.String:
				leaf.SetString(value.(string))
			case reflect.Bool:
				leaf.SetBool(value.(bool))
			}
			out = append(out, encode(copy))
		}
	}
	visit(reflect.ValueOf(seed), nil)
	return out
}
func TestRuntimeWorkCanonicalMatchesIndependentOriginalOnRawForms(t *testing.T) {
	for _, seed := range canonicalRecordSeeds() {
		t.Run(reflect.TypeOf(seed).Name(), func(t *testing.T) {
			for i, data := range append(canonicalRawCorpus(seed), canonicalScalarCorpus(seed)...) {
				old, got := freshCanonicalValue(seed), freshCanonicalValue(seed)
				want, ok := originalCanonicalPredicateCe053(data, old), decodeCanonicalRuntime(data, got)
				if want != ok || ok && !reflect.DeepEqual(old, got) {
					t.Fatal("canonical decision/value differs from original", i, want, ok)
				}
			}
		})
	}
}
func TestRuntimeWorkCanonicalNonzeroTargetsAndOtherSchemasRetainOriginal(t *testing.T) {
	for _, seed := range canonicalRecordSeeds() {
		t.Run(reflect.TypeOf(seed).Name(), func(t *testing.T) {
			data := encode(seed)
			raw := [][]byte{data, []byte("{}\n"), []byte("null\n"), append([]byte("{"), append([]byte(`"unknown":true,`), data[1:]...)...), bytes.Replace(data, []byte(`"version":1`), []byte(`"version":null`), 1)}
			for i, b := range raw {
				old, got := cloneCanonicalValue(seed), cloneCanonicalValue(seed)
				want, ok := originalCanonicalPredicateCe053(b, old), decodeCanonicalRuntime(b, got)
				if want != ok || !reflect.DeepEqual(old, got) {
					t.Fatal("nonzero target behavior differs", i, want, ok)
				}
			}
		})
	}
	// Unknown private schemas keep the EXACT old strict path, not the fast union.
	for _, data := range [][]byte{[]byte("{}\n"), []byte("{\"a\":1}\n"), []byte("{\"a\":1,\"a\":1}\n")} {
		old, got := map[string]any{}, map[string]any{}
		want, ok := originalCanonicalPredicateCe053(data, &old), decodeCanonicalRuntime(data, &got)
		if want != ok || !reflect.DeepEqual(old, got) {
			t.Fatal("fallback changed")
		}
	}
	var nilValue *runtimeCloseIntent
	if decodeCanonicalRuntime([]byte("{}\n"), nilValue) {
		t.Fatal("nil pointer accepted")
	}
}
func TestRuntimeWorkCanonicalFreshRejectionsNeverPublishAndConcurrentReadsAgree(t *testing.T) {
	for _, seed := range canonicalRecordSeeds() {
		data := encode(seed)
		bad := append(append([]byte(nil), data...), byte('x'))
		got := freshCanonicalValue(seed)
		if decodeCanonicalRuntime(bad, got) || !reflect.ValueOf(got).Elem().IsZero() {
			t.Fatal("rejected fresh value escaped")
		}
		var wg sync.WaitGroup
		for n := 0; n < 8; n++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 32; i++ {
					out := freshCanonicalValue(seed)
					if !decodeCanonicalRuntime(data, out) || !reflect.DeepEqual(reflect.ValueOf(out).Elem().Interface(), seed) {
						t.Error("non-deterministic accepted value")
						return
					}
				}
			}()
		}
		wg.Wait()
	}
}

func BenchmarkRuntimeWorkCanonicalDecoding(b *testing.B) {
	for _, seed := range canonicalRecordSeeds() {
		b.Run(reflect.TypeOf(seed).Name(), func(b *testing.B) {
			data := encode(seed)
			for _, kind := range []string{"old-ce053ce", "canonical"} {
				b.Run(kind, func(b *testing.B) {
					b.ReportAllocs()
					for i := 0; i < b.N; i++ {
						out := freshCanonicalValue(seed)
						var ok bool
						if kind == "old-ce053ce" {
							ok = originalCanonicalPredicateCe053(data, out)
						} else {
							ok = decodeCanonicalRuntime(data, out)
						}
						if !ok {
							b.Fatal("decoder refused seed")
						}
					}
				})
			}
		})
	}
}
