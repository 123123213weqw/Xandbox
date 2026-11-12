//go:build linux

package installtxn

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRuntimeWorkCanonicalFileReadsKeepOriginalSizeModeLinkAndScratchGuards(t *testing.T) {
	for index, seed := range canonicalRecordSeeds() {
		t.Run(reflect.TypeOf(seed).Name(), func(t *testing.T) {
			root := t.TempDir()
			dir, e := os.Open(root)
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { dir.Close() })
			f := &filesystem{root: dir}
			namespace, name := runtimeWorkStopRoot, "intent.json"
			if index >= 2 {
				namespace = runtimeCloseRoot
			}
			if index%2 == 1 {
				name = "complete.json"
			}
			if e = os.MkdirAll(root+namespace, 0700); e != nil {
				t.Fatal(e)
			}
			path := root + namespace + "/" + name
			scratch := root + namespace + "/." + name + ".next"
			read := func(out any) (bool, error) {
				if index < 2 {
					return f.readWorkStopRecord(name, out)
				}
				return f.readCloseRecord(name, out)
			}
			// Canonical syntax is independent of semantic policy validity. These padded
			// values remain invalid policy/outcome inputs; the same old MaxPlan file cap
			// must reject BEFORE decoding when exceeded.
			for _, size := range []int{MaxPlan - 1, MaxPlan, MaxPlan + 1} {
				value := cloneCanonicalValue(seed)
				v := reflect.ValueOf(value).Elem()
				field := "Input"
				if index%2 == 0 {
					field = "Policy"
				}
				leaf := v.FieldByName(field)
				n := size - len(encode(value))
				if n < 0 {
					t.Fatal("seed unexpectedly large")
				}
				leaf.SetString(leaf.String() + strings.Repeat("x", n))
				data := encode(value)
				if len(data) != size {
					t.Fatal("wrong boundary input")
				}
				if e = os.WriteFile(path, data, 0600); e != nil {
					t.Fatal(e)
				}
				got := freshCanonicalValue(seed)
				ok, e := read(got)
				if size <= MaxPlan {
					if e != nil || !ok || !bytes.Equal(data, encode(got)) {
						t.Fatal("original boundary changed", size, ok, e)
					}
				} else if e == nil || ok || !reflect.ValueOf(got).Elem().IsZero() {
					t.Fatal("oversize decoded", ok, e)
				}
			}
			data := encode(seed)
			for _, kind := range []string{"final", "full-scratch", "unknown-field", "mode", "symlink", "hardlink", "partial-scratch", "duplicate-scratch"} {
				t.Run(kind, func(t *testing.T) {
					_ = os.Remove(path)
					_ = os.Remove(scratch)
					_ = os.Remove(path + ".alias")
					if e := os.WriteFile(path, data, 0600); e != nil {
						t.Fatal(e)
					}
					var e error
					switch kind {
					case "full-scratch":
						e = os.Rename(path, scratch)
					case "unknown-field":
						e = os.WriteFile(path, append([]byte(`{"unknown":true,`), data[1:]...), 0600)
					case "mode":
						e = os.Chmod(path, 0644)
					case "symlink":
						e = os.Rename(path, path+".alias")
						if e == nil {
							e = os.Symlink(filepath.Base(path+".alias"), path)
						}
					case "hardlink":
						e = os.Link(path, path+".alias")
					case "partial-scratch":
						e = os.Remove(path)
						if e == nil {
							e = os.WriteFile(scratch, []byte("{"), 0600)
						}
					case "duplicate-scratch":
						e = os.WriteFile(scratch, data, 0600)
					}
					if e != nil {
						t.Fatal(e)
					}
					got := freshCanonicalValue(seed)
					ok, e := read(got)
					want := kind == "final" || kind == "full-scratch"
					if (ok && e == nil) != want {
						t.Fatal("file authority decision changed", kind, ok, e)
					}
					if want && !bytes.Equal(data, encode(got)) {
						t.Fatal("accepted bytes changed")
					}
					if !want && !reflect.ValueOf(got).Elem().IsZero() {
						t.Fatal("failed read published a value")
					}
				})
			}
		})
	}
}
