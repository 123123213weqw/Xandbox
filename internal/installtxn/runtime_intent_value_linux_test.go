//go:build linux

package installtxn

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

// Exact pinned98 complete reader flows; never call candidate decode helpers.
func originalDrainReader98(f *filesystem) (runtimeDrainIntent, error) {
	var p runtimeDrainIntent
	b, e := f.read(runtimeDrainRoot+"/intent.json", MaxPlan, 0600)
	if e != nil {
		return p, e
	}
	if strictjson.Decode(b, &p) != nil || !validRuntimeDrain(p) || !bytes.Equal(b, encode(p)) {
		return p, ErrInventory
	}
	return p, nil
}

func originalStopReader98(f *filesystem) (runtimeStopIntent, error) {
	var p runtimeStopIntent
	b, e := f.read(runtimeStopRoot+"/intent.json", MaxPlan, 0600)
	if e != nil {
		return p, e
	}
	if strictjson.Decode(b, &p) != nil || !validRuntimeStop(p) || !bytes.Equal(b, encode(p)) {
		return p, ErrInventory
	}
	return p, nil
}

func originalMaintenanceReader98(f *filesystem) (runtimeDrainIntent, bool, error) {
	p, e := originalDrainReader98(f)
	if e == nil {
		if !validRuntimeMaintenance(p) {
			return p, false, ErrConflict
		}
		return p, true, nil
	}
	if !errors.Is(e, unix.ENOENT) {
		return p, false, e
	}
	b, e := f.read(runtimeDrainRoot+"/.intent.json.next", MaxPlan, 0600)
	if errors.Is(e, unix.ENOENT) {
		return p, false, nil
	}
	if e != nil {
		return p, false, e
	}
	if strictjson.Decode(b, &p) != nil || !validRuntimeDrain(p) || !validRuntimeMaintenance(p) || !bytes.Equal(b, encode(p)) {
		return p, false, ErrInventory
	}
	return p, true, nil
}

func sameIntentReaderFailure98(a, b error) bool {
	if (a == nil) != (b == nil) || errors.Is(a, ErrInventory) != errors.Is(b, ErrInventory) || errors.Is(a, ErrConflict) != errors.Is(b, ErrConflict) {
		return false
	}
	var x, y syscall.Errno
	xok, yok := errors.As(a, &x), errors.As(b, &y)
	return xok == yok && (!xok || x == y)
}
func semanticIntentSeed98(seed any) any {
	if p, ok := seed.(runtimeDrainIntent); ok && p.Maintenance != nil {
		record := *p.Maintenance
		record.Request.Command.RequestID = maintenanceCommandID(p)
		p.Maintenance = &record
		return p
	}
	return seed
}

func TestRuntimeDrainStopIntentRawReadersKeepExactOriginalGuardsAndValues(t *testing.T) {
	for i, original := range intentValueSeeds98() {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			seed := semanticIntentSeed98(original)
			root := t.TempDir()
			if e := os.Chmod(root, 0700); e != nil {
				t.Fatal(e)
			}
			dir, e := os.Open(root)
			if e != nil {
				t.Fatal(e)
			}
			defer dir.Close()
			f := &filesystem{root: dir}
			path := runtimeStopRoot + "/intent.json"
			if _, ok := seed.(runtimeDrainIntent); ok {
				path = runtimeDrainRoot + "/intent.json"
			}
			base := strings.TrimSuffix(path, "/intent.json")
			if e = os.MkdirAll(root+base, 0700); e != nil {
				t.Fatal(e)
			}
			compare := func() (any, error) {
				t.Helper()
				var old, got any
				var oldErr, newErr error
				switch seed.(type) {
				case runtimeDrainIntent:
					old, oldErr = originalDrainReader98(f)
					got, newErr = f.runtimeDrainReadIntent()
				case runtimeStopIntent:
					old, oldErr = originalStopReader98(f)
					got, newErr = f.readRuntimeStop()
				}
				if !sameIntentReaderFailure98(oldErr, newErr) || !reflect.DeepEqual(old, got) {
					t.Fatal("whole raw reader/class/partial output differs", oldErr, newErr)
				}
				return got, newErr
			}
			reset := func() {
				t.Helper()
				for _, p := range []string{root + path, root + path + ".alias", root + base + "/.intent.json.next"} {
					if e := os.Remove(p); e != nil && !errors.Is(e, os.ErrNotExist) {
						t.Fatal(e)
					}
				}
			}
			for _, kind := range []string{"valid", "bad-policy", "unknown", "duplicate-key", "no-LF", "whitespace", "mode", "hardlink", "symlink", "directory", "missing", "scratch"} {
				t.Run(kind, func(t *testing.T) {
					reset()
					data := encode(seed)
					switch kind {
					case "bad-policy":
						data = bytes.Replace(data, []byte(`"version":`+fmt.Sprint(reflect.ValueOf(seed).Field(0).Int())), []byte(`"version":0`), 1)
					case "unknown":
						data = append([]byte(`{"private_unknown":1,`), data[1:]...)
					case "duplicate-key":
						data = append([]byte(`{"version":1,`), data[1:]...)
					case "no-LF":
						data = data[:len(data)-1]
					case "whitespace":
						data = append([]byte(" "), data...)
					}
					if e := os.WriteFile(root+path, data, 0600); e != nil {
						t.Fatal(e)
					}
					var err error
					switch kind {
					case "mode":
						err = os.Chmod(root+path, 0644)
					case "hardlink":
						err = os.Link(root+path, root+path+".alias")
					case "symlink":
						if err = os.Rename(root+path, root+path+".alias"); err == nil {
							err = os.Symlink(root+path+".alias", root+path)
						}
					case "directory", "missing":
						if err = os.Remove(root + path); err == nil && kind == "directory" {
							err = os.Mkdir(root+path, 0700)
						}
					case "scratch":
						err = os.WriteFile(root+base+"/.intent.json.next", data, 0600)
					}
					if err != nil {
						t.Fatal(err)
					}
					got, err := compare()
					positive := kind == "valid" || kind == "scratch"
					if (err == nil) != positive {
						t.Fatal("wrong real reader expectation", kind, got, err)
					}
					if kind == "scratch" {
						if drain, ok := got.(runtimeDrainIntent); ok && f.runtimeDrainInventory(&drain) == nil {
							t.Fatal("canonical raw input bypassed ORIGINAL scratch inventory veto")
						}
					}
				})
			}
			for _, size := range []int{MaxPlan - 1, MaxPlan, MaxPlan + 1} {
				reset()
				copy := cloneCanonicalValue(seed)
				v := reflect.ValueOf(copy).Elem().FieldByName("Base")
				v.SetString("")
				v.SetString(strings.Repeat("x", size-len(encode(copy))))
				data := encode(copy)
				if len(data) != size {
					t.Fatal("wrong exact raw file boundary")
				}
				if e := os.WriteFile(root+path, data, 0600); e != nil {
					t.Fatal(e)
				}
				got, err := compare()
				if err == nil || size > MaxPlan && !reflect.DeepEqual(got, reflect.Zero(reflect.TypeOf(seed)).Interface()) {
					t.Fatal("oversized file decoded before original cap or invalid SHA accepted", err)
				}
			}
		})
	}
}

func TestRuntimeDrainIntentMaintenanceScratchKeepsOriginalWholeFlow(t *testing.T) {
	v := semanticIntentSeed98(intentValueSeeds98()[1]).(runtimeDrainIntent)
	oldV1 := semanticIntentSeed98(intentValueSeeds98()[0]).(runtimeDrainIntent)
	for _, kind := range []string{"absent", "final-v2", "scratch-v2", "scratch-v1", "scratch-unknown", "scratch-partial", "scratch-mode", "scratch-hardlink", "scratch-symlink", "bad-final-valid-scratch", "v1-final-v2-scratch", "both-v2"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if e := os.Chmod(root, 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.MkdirAll(root+runtimeDrainRoot, 0700); e != nil {
				t.Fatal(e)
			}
			file, e := os.Open(root)
			if e != nil {
				t.Fatal(e)
			}
			defer file.Close()
			f := &filesystem{root: file}
			final, scratch := root+runtimeDrainRoot+"/intent.json", root+runtimeDrainRoot+"/.intent.json.next"
			put := func(path string, data []byte) {
				t.Helper()
				if e := os.WriteFile(path, data, 0600); e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "final-v2":
				put(final, encode(v))
			case "scratch-v2", "scratch-mode", "scratch-hardlink", "scratch-symlink":
				put(scratch, encode(v))
			case "scratch-v1":
				put(scratch, encode(oldV1))
			case "scratch-unknown":
				put(scratch, append([]byte(`{"unknown":1,`), encode(v)[1:]...))
			case "scratch-partial":
				put(scratch, []byte(`{"version":2`))
			case "bad-final-valid-scratch":
				put(final, []byte(`{"version":0}`+"\n"))
				put(scratch, encode(v))
			case "v1-final-v2-scratch":
				put(final, encode(oldV1))
				put(scratch, encode(v))
			case "both-v2":
				put(final, encode(v))
				put(scratch, encode(v))
			}
			switch kind {
			case "scratch-mode":
				e = os.Chmod(scratch, 0644)
			case "scratch-hardlink":
				e = os.Link(scratch, scratch+".alias")
			case "scratch-symlink":
				if e = os.Rename(scratch, scratch+".alias"); e == nil {
					e = os.Symlink(scratch+".alias", scratch)
				}
			}
			if e != nil {
				t.Fatal(e)
			}
			before := coreTree(t, root)
			old, oldPending, oldErr := originalMaintenanceReader98(f)
			got, pending, err := f.readMaintenanceIntent()
			if oldPending != pending || !sameIntentReaderFailure98(oldErr, err) || !reflect.DeepEqual(old, got) || !reflect.DeepEqual(before, coreTree(t, root)) {
				t.Fatal("maintenance flow/error values changed or repaired files", oldErr, err)
			}
			positive := kind == "absent" || kind == "final-v2" || kind == "scratch-v2" || kind == "both-v2"
			if (err == nil) != positive || pending != (positive && kind != "absent") {
				t.Fatal("wrong independent whole-flow expectation", pending, err)
			}
		})
	}
}
