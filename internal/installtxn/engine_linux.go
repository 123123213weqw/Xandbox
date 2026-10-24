//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sort"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

type serviceManager interface {
	fresh(context.Context) error
	reconcile(context.Context) error
	current(context.Context) (bool, error)
}

var directories = []struct {
	path string
	mode uint32
}{{DataRoot, 0700}, {assetDir, 0700}, {stateDir, 0700}, {runtimeDir, 0700}, {policyDir, 0700}, {DataRoot + "/g", 0700}, {childRoot, 0700}}
var configNames = []string{"auth.json", "backend.json", "gateway.json", "ingress.json", "launch.json", "readiness.json", "tls.key", "tls.pem"}

func (f *filesystem) rootInventory(committed bool) error {
	names, e := f.names(Root)
	if e != nil {
		return e
	}
	allowed := map[string]bool{".lock": true, "intent.json": true, ".intent.next": true, "commit.json": true, ".commit.next": true}
	for _, name := range configNames {
		allowed[name] = true
	}
	for _, name := range names {
		if !allowed[name] {
			return ErrInventory
		}
		if committed && (name == ".intent.next" || name == ".commit.next") {
			return ErrInventory
		}
	}
	return nil
}
func validFileList(t transaction) bool {
	if t.Version != 1 || t.Revision != 1 || !requestPattern.MatchString(t.RequestID) {
		return false
	}
	p, e := Decode(encode(t.Plan))
	if e != nil || !bytes.Equal(encode(p), encode(t.Plan)) {
		return false
	}
	expected := map[string]uint32{SelfPath: 0555, childRoot + "/gateway": 0555, UnitDir + "/" + MainUnit: 0600, UnitDir + "/" + IngressUnit: 0600}
	for _, name := range configNames {
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
		sourcePins := map[string]string{Root + "/backend.json": t.Plan.Backend.SHA256, Root + "/auth.json": t.Plan.Auth.SHA256, Root + "/gateway.json": t.Plan.Gateway.SHA256, Root + "/tls.pem": t.Plan.Certificate.SHA256, Root + "/tls.key": t.Plan.PrivateKey.SHA256}
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
func (f *filesystem) readTransaction(name string) (transaction, error) {
	var t transaction
	raw, e := f.read(Root+"/"+name+".json", 65536, 0600)
	if e != nil {
		return t, e
	}
	if strictjson.Decode(raw, &t) != nil || !validFileList(t) || !bytes.Equal(raw, encode(t)) {
		return t, ErrInventory
	}
	return t, nil
}
func (f *filesystem) verifyTransaction(ctx context.Context, t transaction) error {
	return f.verifyTargets(ctx, t, true)
}
func (f *filesystem) verifyTargets(ctx context.Context, t transaction, committed bool) error {
	if !validFileList(t) {
		return ErrInventory
	}
	if e := f.rootInventory(committed); e != nil {
		return e
	}
	for _, v := range t.Files {
		if e := f.verify(ctx, v); e != nil {
			return e
		}
	}
	if e := f.verifyGenerated(t); e != nil {
		return e
	}
	// Immutable artifact and child-executable inventories are closed. Mutable
	// ledger/runtime/policy subtrees remain the ordinary driver's responsibility.
	names, e := f.names(assetDir)
	if e != nil {
		return e
	}
	expected := []string{}
	for _, r := range roles {
		if filepath.Dir(rolePath(r)) == assetDir {
			expected = append(expected, filepath.Base(rolePath(r)))
		}
	}
	sort.Strings(expected)
	if !sameNames(names, expected) {
		return ErrInventory
	}
	names, e = f.names(childRoot)
	if e != nil || !sameNames(names, []string{"gateway"}) {
		return ErrInventory
	}
	for _, v := range []struct {
		path string
		mode uint32
	}{{Root, 0700}, {DataRoot, 0700}, {assetDir, 0700}, {DataRoot + "/g", 0700}, {childRoot, 0555}} {
		dir, e := f.directory(v.path)
		if e != nil {
			return e
		}
		e = trustedStat(int(dir.Fd()), true, v.mode)
		dir.Close()
		if e != nil {
			return e
		}
	}
	if pending, e := f.readTransaction("intent"); e == nil {
		if !bytes.Equal(encode(pending), encode(t)) {
			return ErrInventory
		}
	} else if !errors.Is(e, unix.ENOENT) {
		return e
	}
	return f.syncDir(Root)
}
func sameNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func (f *filesystem) initialInventory(p *prepared) error {
	if e := f.rootInventory(false); e != nil {
		return e
	}
	names, e := f.names(Root)
	if e != nil {
		return e
	}
	for _, name := range names {
		if name != ".lock" && name != ".intent.next" {
			return ErrInventory
		}
	}
	for _, v := range p.targets {
		yes, e := f.exists(v.file.Path)
		if e != nil {
			return e
		}
		if yes {
			// A bootstrap may already be installed at the FINAL self path, but no
			// different or merely same-content preexisting service asset is adopted.
			if v.file.Path != SelfPath || p.plan.Self.Path != SelfPath {
				return ErrInventory
			}
			if e = f.verify(context.Background(), v.file); e != nil {
				return e
			}
		}
	}
	for _, d := range directories {
		yes, e := f.exists(d.path)
		if e != nil {
			return e
		}
		if yes {
			dir, e := f.directory(d.path)
			if e != nil {
				return e
			}
			e = trustedStat(int(dir.Fd()), true, d.mode)
			dir.Close()
			if e != nil {
				return e
			}
			names, e := f.names(d.path)
			if e != nil || len(names) != 0 {
				return ErrInventory
			}
		}
	}
	for _, path := range []string{unitRoot, "/sys/fs/cgroup/system.slice/" + IngressUnit, inputDir, UnitDir + "/" + MainUnit + ".d", UnitDir + "/" + IngressUnit + ".d"} {
		yes, e := f.exists(path)
		if e != nil {
			return e
		}
		if yes {
			return ErrInventory
		}
	}
	return nil
}
func (f *filesystem) commitPrepared(ctx context.Context, p *prepared, request string, pending bool) (transaction, error) {
	t := p.transaction(request)
	var zero transaction
	if !validFileList(t) {
		return zero, ErrPolicy
	}
	if pending {
		old, e := f.readTransaction("intent")
		if e != nil {
			return zero, e
		}
		if !bytes.Equal(encode(old), encode(t)) {
			return zero, ErrConflict
		}
	}
	if e := f.record("intent", encode(t)); e != nil {
		return zero, e
	}
	for _, d := range directories {
		mode := d.mode
		if d.path == childRoot {
			yes, e := f.exists(childRoot)
			if e != nil {
				return zero, e
			}
			if yes {
				dir, e := f.directory(childRoot)
				if e != nil {
					return zero, e
				}
				st, e := dir.Stat()
				dir.Close()
				if e != nil {
					return zero, e
				}
				if st.Mode().Perm() == 0555 {
					mode = 0555
				}
			}
		}
		if e := f.mkdir(d.path, mode); e != nil {
			return zero, e
		}
	}
	for _, v := range p.targets {
		if e := f.materialize(ctx, v); e != nil {
			return zero, e
		}
	}
	child, e := f.directory(childRoot)
	if e != nil {
		return zero, e
	}
	e = child.Chmod(0555)
	if e == nil {
		e = child.Sync()
	}
	child.Close()
	if e != nil {
		return zero, e
	}
	if e = f.syncDir(filepath.Dir(childRoot)); e != nil {
		return zero, e
	}
	// For validation before commit, the private intent is authoritative for this
	// exact request only; verifyTransaction never starts a manager or a guest.
	if e = f.verifyTargets(ctx, t, false); e != nil {
		return zero, e
	}
	if e = f.record("commit", encode(t)); e != nil {
		return zero, e
	}
	if e = f.point("commit-confirmed"); e != nil {
		return zero, e
	}
	if e = f.removeIntent(t); e != nil {
		return zero, e
	}
	return t, nil
}
func (f *filesystem) installLocked(ctx context.Context, plan Plan, request string, manager serviceManager, load func(context.Context, Plan, bool) (*prepared, func(), error)) (transaction, error) {
	var zero transaction
	if !requestPattern.MatchString(request) {
		return zero, ErrPolicy
	}
	if e := f.rootInventory(false); e != nil {
		return zero, e
	}
	if t, e := f.readTransaction("commit"); e == nil {
		if t.RequestID != request || !bytes.Equal(encode(t.Plan), encode(plan)) {
			return zero, ErrConflict
		}
		if e = f.verifyTransaction(ctx, t); e != nil {
			return zero, e
		}
		if e = f.removeIntent(t); e != nil {
			return zero, e
		}
		return t, nil
	} else if !errors.Is(e, unix.ENOENT) {
		return zero, e
	}
	pending := false
	if t, e := f.readTransaction("intent"); e == nil {
		if t.RequestID != request || !bytes.Equal(encode(t.Plan), encode(plan)) {
			return zero, ErrConflict
		}
		pending = true
	} else if !errors.Is(e, unix.ENOENT) {
		return zero, e
	}
	p, close, e := load(ctx, plan, pending)
	if e != nil {
		return zero, e
	}
	defer close()
	if !pending {
		if e = f.initialInventory(p); e != nil {
			return zero, e
		}
		if e = manager.fresh(ctx); e != nil {
			return zero, e
		}
	}
	return f.commitPrepared(ctx, p, request, pending)
}
func fileCommitted(t transaction) Result {
	return Result{Version: 1, Revision: t.Revision, FilesCommitted: true}
}

func (f *filesystem) privateDirectory(path string, mode uint32) error {
	dir, e := f.directory(path)
	if e != nil {
		return e
	}
	defer dir.Close()
	return trustedStat(int(dir.Fd()), true, mode)
}
func (f *filesystem) verifyGenerated(t transaction) error {
	raw, e := f.read(Root+"/backend.json", 16384, 0600)
	if e != nil {
		return e
	}
	var cfg firecracker.Config
	if strictjson.Decode(raw, &cfg) != nil || cfg.Version != 3 || cfg.Snapshot != nil || cfg.RuntimeRoot != runtimeDir || cfg.CgroupRoot != unitRoot+"/node/instances" || cfg.IO == nil || cfg.Node == nil || cfg.Quota == nil {
		return ErrInventory
	}
	art, e := descriptor(t.Release)
	if e != nil {
		return e
	}
	n := nodeManifest(t.Plan, art)
	if n.CheckServiceBackend(cfg) != nil {
		return ErrInventory
	}
	for role, a := range map[string]firecracker.Asset{"firecracker": cfg.Firecracker, "jailer": cfg.Jailer, "warden": cfg.Warden, "kernel": cfg.Kernel, "initrd": cfg.Initrd, "workspace": cfg.Workspace} {
		if a.Path != rolePath(role) || a.SHA256 != art[role].SHA256 {
			return ErrInventory
		}
	}
	generated, e := render(t.Plan, cfg.IO.Device, art)
	if e != nil {
		return e
	}
	for path, data := range generated {
		if e = f.exact(path, data, 0600); e != nil {
			return e
		}
	}
	return nil
}
