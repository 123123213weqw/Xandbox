//go:build linux

package firecracker

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func blockInventory(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	disk := filepath.Join(root, "devices/pci/block/disk")
	for _, dir := range []string{disk + "/slaves", disk + "/queue", disk + "/disk3", root + "/dev/block"} {
		if e := os.MkdirAll(dir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	for file, value := range map[string]string{disk + "/dev": "8:0\n", disk + "/disk3/partition": "3\n", disk + "/disk3/dev": "8:3\n"} {
		if e := os.WriteFile(file, []byte(value), 0600); e != nil {
			t.Fatal(e)
		}
	}
	for id, path := range map[string]string{"8:0": disk, "8:3": disk + "/disk3"} {
		if e := os.Symlink(path, filepath.Join(root, "dev/block", id)); e != nil {
			t.Fatal(e)
		}
	}
	return root, disk
}

func TestIOBackingQueueRejectsUnknownStackedAndEscapedInventory(t *testing.T) {
	for _, kind := range []string{"valid", "loop", "dm", "md", "slave", "missing-queue", "outside"} {
		t.Run(kind, func(t *testing.T) {
			root, disk := blockInventory(t)
			switch kind {
			case "loop", "dm", "md":
				if e := os.Mkdir(filepath.Join(disk, kind), 0700); e != nil {
					t.Fatal(e)
				}
			case "slave":
				if e := os.WriteFile(disk+"/slaves/unknown", nil, 0600); e != nil {
					t.Fatal(e)
				}
			case "missing-queue":
				if e := os.Remove(disk + "/queue"); e != nil {
					t.Fatal(e)
				}
			case "outside":
				if e := os.Remove(root + "/dev/block/8:3"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(t.TempDir(), root+"/dev/block/8:3"); e != nil {
					t.Fatal(e)
				}
			}
			device, e := directBlockQueue(root, "8:3")
			if kind == "valid" {
				if e != nil || device != "8:0" {
					t.Fatalf("%s %v", device, e)
				}
				if direct, e := directBlockQueue(root, "8:0"); e != nil || direct != "8:0" {
					t.Fatal(direct, e)
				}
			} else if e == nil {
				t.Fatal("unsupported queue accepted")
			}
		})
	}
}

func TestMissingIOControlFileNeverCreatedByDriver(t *testing.T) {
	dir := t.TempDir()
	if applyKernelIO(dir, ioPolicy()) == nil {
		t.Fatal("missing delegation accepted")
	}
	if _, e := os.Stat(filepath.Join(dir, "io.max")); !os.IsNotExist(e) {
		t.Fatal("created fake IO controller file")
	}
	if e := os.WriteFile(filepath.Join(dir, "io.max"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e := applyKernelIO(dir, ioPolicy()); e != nil {
		t.Fatal(e)
	}
}

func ioConfigJSON(t *testing.T, p IOPolicy) []byte {
	t.Helper()
	raw, e := json.Marshal(map[string]any{"drives": []any{workspaceDrive(&p)}, "unrelated": "pinned API field"})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

func TestFrontendReadbackRequiresExactDriveAndSteadyBuckets(t *testing.T) {
	p := ioPolicy()
	good := ioConfigJSON(t, p)
	if e := p.verifyFrontendConfig(good); e != nil {
		t.Fatal(e)
	}
	for _, raw := range [][]byte{nil, []byte(`{"drives":[]}`), []byte(`{"drives":[{"drive_id":"workspace"}]}`),
		[]byte(strings.Replace(string(good), "workspace", "another", 1)), []byte(strings.Replace(string(good), "8388608", "8388609", 1)),
		[]byte(strings.Replace(string(good), `"size":8388608`, `"size":8388608,"one_time_burst":1`, 1)), append(append([]byte{}, good...), []byte(`{}`)...)} {
		if p.verifyFrontendConfig(raw) == nil {
			t.Fatalf("bad readback accepted: %s", raw)
		}
	}
}

func TestSnapshotIOLimitPatchVerifiedBeforeCallerMayResume(t *testing.T) {
	for _, mode := range []string{"success", "patch-failure", "wrong-readback", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "api.sock")
			listener, e := net.Listen("unix", socket)
			if e != nil {
				t.Fatal(e)
			}
			calls := []string{}
			var callsMu sync.Mutex
			p := ioPolicy()
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				callsMu.Lock()
				calls = append(calls, r.Method+" "+r.URL.Path)
				callsMu.Unlock()
				if r.Method == "PATCH" {
					if mode == "patch-failure" {
						w.WriteHeader(400)
						return
					}
					w.WriteHeader(204)
					return
				}
				if mode == "redirect" {
					w.Header().Set("Location", "http://127.0.0.1:1/escape")
					w.WriteHeader(307)
					return
				}
				if mode == "wrong-readback" {
					w.Write([]byte(`{"drives":[]}`))
					return
				}
				w.Write(ioConfigJSON(t, p))
			})}
			go server.Serve(listener)
			defer server.Close()
			e = configureSnapshotIO(context.Background(), socket, p)
			if (e == nil) != (mode == "success") {
				t.Fatal(e)
			}
			want := "PATCH /drives/workspace,GET /vm/config"
			if mode == "patch-failure" {
				want = "PATCH /drives/workspace"
			}
			callsMu.Lock()
			defer callsMu.Unlock()
			if strings.Join(calls, ",") != want {
				t.Fatal(calls)
			}
		})
	}
}
