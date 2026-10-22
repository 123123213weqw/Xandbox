package firecracker

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func policy() Config {
	a := Asset{Path: "/opt/xandbox/firecracker", SHA256: strings.Repeat("a", 64)}
	return Config{Version: 1, RuntimeRoot: "/run/xb-test", CgroupRoot: "/sys/fs/cgroup/xb-test", UIDStart: 400000,
		UIDCount: 2, ReservedUIDRange: true, Firecracker: a, Jailer: a, Warden: a, Kernel: a, Initrd: a, Workspace: a}
}

func reference(n string) sandbox.Ref {
	return sandbox.Ref{ID: strings.Repeat(n, 32), Generation: strings.Repeat("f", 32)}
}

func ledger(ref sandbox.Ref) sandbox.Record {
	return sandbox.Record{Ref: ref, Backend: "firecracker", State: sandbox.Creating}
}

func TestOwnershipDurableBeforeResourceAndLeaseSurvivesRestart(t *testing.T) {
	dir, cfg := t.TempDir(), policy()
	r, err := newRegistry(dir, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := r.reserve(reference("1"))
	if err != nil {
		t.Fatal(err)
	}
	// No runtime allocation is needed for the registry to recover a reserved UID.
	r, err = newRegistry(dir, cfg, []sandbox.Record{ledger(first.Ref)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.reserve(reference("2"))
	if err != nil || first.UID == second.UID {
		t.Fatalf("UID reused before cleanup: %+v %v", second, err)
	}
	if _, err := r.reserve(reference("3")); !errors.Is(err, sandbox.ErrCapacity) {
		t.Fatalf("unreclaimed lease did not count: %v", err)
	}
	if _, err := r.reserve(first.Ref); err == nil {
		t.Fatal("prepared the same generation twice")
	}
	k, _ := key(first.Ref)
	if err := r.release(k); err != nil {
		t.Fatal(err)
	}
	third, err := r.reserve(reference("3"))
	if err != nil || third.UID != first.UID {
		t.Fatalf("reclaimed UID not returned: %+v %v", third, err)
	}
}

func TestRegistryRefusesChangedLocatorsAndLostLedger(t *testing.T) {
	dir, cfg := t.TempDir(), policy()
	r, err := newRegistry(dir, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := r.reserve(reference("1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.RuntimeRoot = "/run/xb-other" },
		func(c *Config) { c.CgroupRoot += "-other" },
		func(c *Config) { c.UIDStart++ },
		func(c *Config) { c.Warden.SHA256 = strings.Repeat("b", 64) },
	} {
		changed := cfg
		change(&changed)
		if _, err := newRegistry(dir, changed, []sandbox.Record{ledger(owner.Ref)}); err == nil {
			t.Fatal("accepted changed backend binding")
		}
	}
	if _, err := newRegistry(dir, cfg, nil); err == nil {
		t.Fatal("silently ignored ownership without ledger")
	}
	record := ledger(owner.Ref)
	record.State = sandbox.Destroyed
	if _, err := newRegistry(dir, cfg, []sandbox.Record{record}); err == nil {
		t.Fatal("destroyed ledger still owns a UID")
	}
}

func TestRegistryRejectsCorruptionAndDuplicateUIDs(t *testing.T) {
	for _, mode := range []string{"duplicate", "symlink", "unknown", "corrupt", "uid", "filename", "missing-binding"} {
		t.Run(mode, func(t *testing.T) {
			dir, cfg := t.TempDir(), policy()
			r, err := newRegistry(dir, cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			one, err := r.reserve(reference("1"))
			if err != nil {
				t.Fatal(err)
			}
			k, _ := key(one.Ref)
			p := filepath.Join(dir, k+".json")
			switch mode {
			case "duplicate":
				two := one
				two.Ref = reference("2")
				k, _ := key(two.Ref)
				err = durableJSON(filepath.Join(dir, k+".json"), two)
			case "symlink":
				err = os.Symlink(p, filepath.Join(dir, "other.json"))
			case "unknown":
				err = os.WriteFile(p, []byte(`{"version":1,"mystery":true}`), 0600)
			case "corrupt":
				err = os.WriteFile(p, []byte(`{"version":1`), 0600)
			case "uid":
				one.UID = cfg.UIDStart - 1
				err = durableJSON(p, one)
			case "filename":
				err = os.Rename(p, filepath.Join(dir, "wrong.json"))
			case "missing-binding":
				err = os.Remove(filepath.Join(dir, "config.json"))
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := newRegistry(dir, cfg, []sandbox.Record{ledger(reference("1")), ledger(reference("2"))}); err == nil {
				t.Fatal("invalid registry accepted")
			}
		})
	}
}

func TestPolicyRejectsUnsafePathsAndIdentities(t *testing.T) {
	if err := policy().validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.ReservedUIDRange = false },
		func(c *Config) { c.UIDStart = 0 },
		func(c *Config) { c.UIDStart = int(^uint(0) >> 1) },
		func(c *Config) { c.UIDCount = 10001 },
		func(c *Config) { c.Version = 2 },
		func(c *Config) { c.RuntimeRoot = "/tmp/xb" },
		func(c *Config) { c.RuntimeRoot = "/run/" + strings.Repeat("a", 40) },
		func(c *Config) { c.CgroupRoot = "/sys/fs/cgroup/../other" },
		func(c *Config) { c.CgroupRoot = "/sys/fs/cgroup" },
		func(c *Config) { c.Kernel.SHA256 = "unknown" },
		func(c *Config) { c.Firecracker.Path = "/opt/firecracker-other" },
	} {
		c := policy()
		change(&c)
		if c.validate() == nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
	for _, ref := range []sandbox.Ref{{}, {ID: "../escape", Generation: strings.Repeat("a", 32)}} {
		if _, err := key(ref); err == nil {
			t.Fatal("invalid resource identity accepted")
		}
	}
}

func TestOwnershipReadersDoNotWaitForOtherGenerationPersistence(t *testing.T) {
	r, err := newRegistry(t.TempDir(), policy(), nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := r.reserve(reference("1"))
	if err != nil {
		t.Fatal(err)
	}
	one, _ := key(first.Ref)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	r.persist = func(path string, value any) error { close(entered); <-release; return durableJSON(path, value) }
	result := make(chan error, 1)
	go func() { _, err := r.reserve(reference("2")); result <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("persist barrier not entered")
	}
	lookup := make(chan bool, 1)
	go func() { lookup <- r.owns(one) }()
	select {
	case ok := <-lookup:
		if !ok {
			t.Fatal("lost existing ownership")
		}
	case <-time.After(time.Second):
		t.Fatal("ownership reader waited on fsync")
	}
	once.Do(func() { close(release) })
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestUIDRemainsReservedDuringDeletionFsyncWithoutBlockingReaders(t *testing.T) {
	cfg := policy()
	cfg.UIDCount = 3
	r, err := newRegistry(t.TempDir(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := r.reserve(reference("1"))
	if err != nil {
		t.Fatal(err)
	}
	one, _ := key(first.Ref)
	second, err := r.reserve(reference("2"))
	if err != nil {
		t.Fatal(err)
	}
	two, _ := key(second.Ref)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	r.syncDirectory = func(path string) error { close(entered); <-release; return syncDir(path) }
	result := make(chan error, 1)
	go func() { result <- r.release(one) }()
	<-entered
	lookup := make(chan bool, 1)
	go func() { lookup <- r.owns(one) && r.owns(two) }()
	select {
	case ok := <-lookup:
		if !ok {
			t.Fatal("UID released before fsync")
		}
	case <-time.After(time.Second):
		t.Fatal("stop lookup blocked behind deletion fsync")
	}
	third, err := r.reserve(reference("3"))
	if err != nil || third.UID == first.UID || third.UID == second.UID {
		t.Fatalf("early UID reuse / blocked admission: %+v %v", third, err)
	}
	once.Do(func() { close(release) })
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
