package installtxn

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// EXACT pinned98 syntax/canonical expression, not the candidate helper.
func originalIntentCanonical98(data []byte, out any) bool {
	return strictjson.Decode(data, out) == nil && bytes.Equal(data, encode(out))
}
func intentValueSeeds98() []any {
	work, _, _, _ := canonicalWorkSeed()
	d1 := work.Drain
	d1.Version, d1.Maintenance = 1, nil
	values := []any{d1, work.Drain}
	for version := 1; version <= 4; version++ {
		s := work.Stop
		s.Version, s.Work, s.Close = version, "", ""
		if version == 1 {
			s.State = nil
		}
		if version >= 3 {
			s.Work = strings.Repeat("f", 64)
		}
		if version == 4 {
			s.Close = strings.Repeat("a", 64)
		}
		values = append(values, s)
	}
	return values
}
func candidateIntentCanonical(data []byte, out any) bool {
	switch v := out.(type) {
	case *runtimeDrainIntent:
		return canonicalRuntimeIntentValue(data, v)
	case *runtimeStopIntent:
		return canonicalRuntimeIntentValue(data, v)
	default:
		panic("test schema")
	}
}
func compareIntentCanonical98(t *testing.T, seed any, data []byte, nonzero bool) {
	t.Helper()
	old, got := freshCanonicalValue(seed), freshCanonicalValue(seed)
	if nonzero {
		old, got = cloneCanonicalValue(seed), cloneCanonicalValue(seed)
	}
	want, ok := originalIntentCanonical98(data, old), candidateIntentCanonical(data, got)
	if want != ok || !reflect.DeepEqual(old, got) {
		t.Fatal("canonical decision OR partial/nonzero error-return value changed")
	}
}

func TestRuntimeDrainStopIntentCanonicalMatches98IncludingRejectedValues(t *testing.T) {
	for i, seed := range intentValueSeeds98() {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			data := encode(seed)
			corpus := [][]byte{data, nil, []byte("{}\n"), []byte("null\n"), []byte("[]\n"), data[:len(data)-1], append(append([]byte(nil), data...), data...), append([]byte(" "), data...), append(append([]byte(nil), data...), ' ')}
			for _, prefix := range []string{`"unknown":0,`, `"version":1,`, `"Version":1,`, `"ver\u0073ion":1,`, `"verſion":1,`, `"version":null,`} {
				corpus = append(corpus, append([]byte("{"+prefix), data[1:]...))
			}
			for _, value := range []string{"null", "-0", "1.0", "1e0", "true", "[]", "{}", `"1"`, "18446744073709551616", "-9223372036854775809", "NaN"} {
				corpus = append(corpus, bytes.Replace(data, []byte(`"version":`+fmt.Sprint(reflect.ValueOf(seed).Field(0).Int())), []byte(`"version":`+value), 1))
			}
			corpus = append(corpus, canonicalScalarCorpus(seed)...)
			state := uint32(0x9814ea)
			for n := 0; n < 1024; n++ {
				b := append([]byte(nil), data...)
				for k := 0; k < 1+n%5; k++ {
					state = 1664525*state + 1013904223
					b[int(state)%len(b)] = byte(state >> 24)
				}
				corpus = append(corpus, b)
			}
			for _, n := range []int{63, 64, 65, 1000} {
				corpus = append(corpus, []byte(`{"unknown":`+strings.Repeat("[", n)+`0`+strings.Repeat("]", n)+"}\n"))
			}
			for _, size := range []int{MaxPlan - 1, MaxPlan, MaxPlan + 1} {
				head, tail := `{"version":1,"unknown":"`, "\"}\n"
				b := []byte(head + strings.Repeat("x", size-len(head)-len(tail)) + tail)
				if len(b) != size {
					t.Fatal("wrong exact wire-ceiling fixture")
				}
				corpus = append(corpus, b)
			}
			for _, b := range corpus {
				before := append([]byte(nil), b...)
				compareIntentCanonical98(t, seed, b, false)
				// Original nonzero merge behavior is required on accepted AND errors.
				compareIntentCanonical98(t, seed, b, true)
				if !bytes.Equal(before, b) {
					t.Fatal("caller wire mutated")
				}
			}
		})
	}
	var nilDrain *runtimeDrainIntent
	var nilStop *runtimeStopIntent
	if canonicalRuntimeIntentValue([]byte("{}\n"), nilDrain) || canonicalRuntimeIntentValue([]byte("{}\n"), nilStop) {
		t.Fatal("nil target accepted")
	}
}

func TestRuntimeDrainStopIntentClosedSchemaAndFreshReferences(t *testing.T) {
	methods := []reflect.Type{reflect.TypeOf((*json.Marshaler)(nil)).Elem(), reflect.TypeOf((*json.Unmarshaler)(nil)).Elem(), reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem(), reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()}
	// Exact exported field/tag/type shape generated ONCE from pinned98 source.
	shapes := map[reflect.Type][]string{
		reflect.TypeOf(runtimeDrainIntent{}):             {"Version|version|int", "Base|base_commit_sha256|string", "Request|request_id|string", "Process|process|nodecontrol.ProcessIdentity", "Before|before|nodecontrol.State", "Maintenance|maintenance,omitempty|*nodecontrol.MaintenanceRecord"},
		reflect.TypeOf(runtimeStopIntent{}):              {"Version|version|int", "Base|base_commit_sha256|string", "Request|request_id|string", "Drain|drain_intent_sha256|string", "Main|main|nodecontrol.ProcessIdentity", "Ingress|ingress,omitempty|*nodecontrol.ProcessIdentity", "State|state_identity,omitempty|*installtxn.runtimeStateIdentity", "Work|work_completion_sha256,omitempty|string", "Close|runtime_close_sha256,omitempty|string"},
		reflect.TypeOf(runtimeStateIdentity{}):           {"RootDevice|root_device|uint64", "RootInode|root_inode|uint64", "LockDevice|lock_device|uint64", "LockInode|lock_inode|uint64", "LockChangeSeconds|lock_change_seconds|int64", "LockChangeNanos|lock_change_nanos|int64"},
		reflect.TypeOf(nodecontrol.ProcessIdentity{}):    {"PID|pid|int", "BootID|boot_id|string", "StartTicks|start_ticks|uint64"},
		reflect.TypeOf(nodecontrol.State{}):              {"Version|version|int", "Epoch|epoch|string", "Revision|revision|uint64", "Mode|mode|string", "LastRequestID|last_request_id|string", "LastExpectedRevision|last_expected_revision|uint64"},
		reflect.TypeOf(nodecontrol.Command{}):            {"Version|version|int", "Epoch|epoch|string", "ExpectedRevision|expected_revision|uint64", "RequestID|request_id|string"},
		reflect.TypeOf(nodecontrol.MaintenanceOwner{}):   {"Version|version|int", "InstallCommitSHA256|install_commit_sha256|string", "OperationID|operation_id|string"},
		reflect.TypeOf(nodecontrol.MaintenanceRequest{}): {"Version|version|int", "Owner|owner|nodecontrol.MaintenanceOwner", "Command|command|nodecontrol.Command"},
		reflect.TypeOf(nodecontrol.MaintenanceRecord{}):  {"Version|version|int", "Request|request|nodecontrol.MaintenanceRequest", "Before|before|nodecontrol.State"},
	}
	refs := 0
	var inspect func(reflect.Type, int)
	inspect = func(typ reflect.Type, depth int) {
		if depth > 16 || !typ.Comparable() {
			t.Fatal("schema/reference/recursion growth")
		}
		for _, method := range methods {
			if typ.Implements(method) || reflect.PointerTo(typ).Implements(method) {
				t.Fatal("custom normalization needs review", typ)
			}
		}
		switch typ.Kind() {
		case reflect.Pointer:
			refs++
			e := typ.Elem()
			if e != reflect.TypeOf(nodecontrol.MaintenanceRecord{}) && e != reflect.TypeOf(nodecontrol.ProcessIdentity{}) && e != reflect.TypeOf(runtimeStateIdentity{}) {
				t.Fatal("new reference kind")
			}
			inspect(e, depth+1)
		case reflect.Struct:
			want, ok := shapes[typ]
			if !ok || len(want) != typ.NumField() {
				t.Fatal("unpinned wire schema growth", typ)
			}
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				if f.Name+"|"+f.Tag.Get("json")+"|"+f.Type.String() != want[i] {
					t.Fatal("wire field/tag/type changed", typ, f.Name)
				}
			}
			seen := map[string]bool{}
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				tag := strings.Split(f.Tag.Get("json"), ",")[0]
				if f.PkgPath != "" || f.Anonymous || tag == "" || strings.Trim(tag, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" || seen[tag] {
					t.Fatal("not closed ASCII tag schema")
				}
				seen[tag] = true
				inspect(f.Type, depth+1)
			}
		case reflect.Int, reflect.Int64, reflect.Uint64, reflect.String:
		default:
			t.Fatal("new scalar/reference kind", typ)
		}
	}
	inspect(reflect.TypeOf(runtimeDrainIntent{}), 0)
	inspect(reflect.TypeOf(runtimeStopIntent{}), 0)
	if refs != 3 {
		t.Fatal("reference shape changed", refs)
	}
	for _, seed := range intentValueSeeds98() {
		raw := encode(seed)
		first, second := freshCanonicalValue(seed), freshCanonicalValue(seed)
		if !candidateIntentCanonical(raw, first) || !candidateIntentCanonical(raw, second) {
			t.Fatal("seed")
		}
		// Independently allocated nested pointers, never a reusable decoded cache.
		for i := 0; i < reflect.ValueOf(first).Elem().NumField(); i++ {
			a, b := reflect.ValueOf(first).Elem().Field(i), reflect.ValueOf(second).Elem().Field(i)
			if a.Kind() == reflect.Pointer && !a.IsNil() && a.Pointer() == b.Pointer() {
				t.Fatal("shared decoded reference")
			}
		}
		target := cloneCanonicalValue(seed)
		value := reflect.ValueOf(target).Elem()
		originalPointers := map[int]uintptr{}
		for i := 0; i < value.NumField(); i++ {
			f := value.Field(i)
			if f.Kind() == reflect.Pointer && !f.IsNil() {
				originalPointers[i] = f.Pointer()
			}
		}
		if !candidateIntentCanonical(raw, target) {
			t.Fatal("nonzero canonical seed refused")
		}
		for i, ptr := range originalPointers {
			if value.Field(i).Pointer() != ptr {
				t.Fatal("old nonzero pointer merge identity lost")
			}
		}
		copy(raw, bytes.Repeat([]byte{'x'}, len(raw)))
		if !reflect.DeepEqual(first, second) {
			t.Fatal("decoded value aliases caller raw bytes")
		}
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for n := 0; n < 8; n++ {
					data := encode(seed)
					old, got := freshCanonicalValue(seed), freshCanonicalValue(seed)
					if originalIntentCanonical98(data, old) != candidateIntentCanonical(data, got) || !reflect.DeepEqual(old, got) {
						t.Error("concurrent fresh value differs")
						return
					}
				}
			}()
		}
		wg.Wait()
	}
}

var intentBenchmarkBool bool

func BenchmarkRuntimeIntentCanonical98(b *testing.B) {
	for i, seed := range intentValueSeeds98() {
		data := encode(seed)
		for _, mode := range []string{"old-strict98", "fresh-canonical"} {
			b.Run(fmt.Sprintf("%d/%s", i, mode), func(b *testing.B) {
				b.ReportAllocs()
				for n := 0; n < b.N; n++ {
					out := freshCanonicalValue(seed)
					if mode == "old-strict98" {
						intentBenchmarkBool = originalIntentCanonical98(data, out)
					} else {
						intentBenchmarkBool = candidateIntentCanonical(data, out)
					}
				}
			})
		}
	}
}
