//go:build linux

package installtxn

import (
	"context"
	"os"
	"sort"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

type prepared struct {
	plan    Plan
	release Release
	targets []target
	close   func()
}

func (p prepared) transaction(request string) transaction {
	t := transaction{Version: 1, Revision: 1, RequestID: request, Plan: p.plan, Release: p.release}
	for _, v := range p.targets {
		t.Files = append(t.Files, v.file)
	}
	return t
}
func (f *filesystem) pinned(ctx context.Context, a firecracker.Asset, max int64, private bool) (*os.File, []byte, error) {
	in, e := f.open(a.Path, unix.O_RDONLY, 0)
	if e != nil {
		return nil, nil, e
	}
	ok := false
	defer func() {
		if !ok {
			in.Close()
		}
	}()
	st, e := in.Stat()
	if e != nil || st.Size() <= 0 || st.Size() > max || private && st.Mode().Perm()&0077 != 0 {
		return nil, nil, ErrPolicy
	}
	sum, e := hashFile(ctx, in, st.Size())
	if e != nil {
		return nil, nil, e
	}
	if sum != a.SHA256 {
		return nil, nil, ErrPolicy
	}
	if _, e = in.Seek(0, 0); e != nil {
		return nil, nil, e
	}
	var data []byte
	if private {
		data = make([]byte, st.Size())
		if _, e = in.ReadAt(data, 0); e != nil {
			return nil, nil, e
		}
	}
	ok = true
	return in, data, nil
}
func (f *filesystem) prepare(ctx context.Context, p Plan, release *releaseView) (*prepared, error) {
	sources := []*os.File{}
	out := &prepared{plan: p, release: release.description}
	out.close = func() {
		for _, s := range sources {
			s.Close()
		}
	}
	ok := false
	defer func() {
		if !ok {
			out.close()
		}
	}()
	input := map[string][]byte{}
	for _, v := range []struct {
		name string
		a    firecracker.Asset
		max  int64
	}{{"backend.json", p.Backend, 16384}, {"auth.json", p.Auth, 65536}, {"gateway.json", p.Gateway, gateway.MaxSnapshotBytes}, {"tls.pem", p.Certificate, 65536}, {"tls.key", p.PrivateKey, 65536}} {
		fd, raw, e := f.pinned(ctx, v.a, v.max, true)
		if e != nil {
			return nil, e
		}
		sources = append(sources, fd)
		input[v.name] = raw
	}
	self, _, e := f.pinned(ctx, p.Self, 64<<20, false)
	if e != nil {
		return nil, e
	}
	sources = append(sources, self)
	if e = validateInputs(p, input, release.artifact, time.Now(), p.Backend.Path); e != nil {
		return nil, e
	}
	var cfg firecracker.Config
	if strictjson.Decode(input["backend.json"], &cfg) != nil {
		return nil, ErrPolicy
	}
	generated, e := render(p, cfg.IO.Device, release.artifact)
	if e != nil {
		return nil, e
	}
	appendTarget := func(path string, raw []byte, mode uint32) {
		out.targets = append(out.targets, target{file: File{Path: path, SHA256: digest(raw), Bytes: int64(len(raw)), Mode: mode}, data: raw})
	}
	for _, name := range []string{"backend.json", "auth.json", "gateway.json", "tls.pem", "tls.key"} {
		appendTarget(Root+"/"+name, input[name], 0600)
	}
	for path, raw := range generated {
		appendTarget(path, raw, 0600)
	}
	for _, role := range roles {
		a := release.artifact[role]
		mode := uint32(0444)
		if executable(role) {
			mode = 0555
		}
		out.targets = append(out.targets, target{file: File{Path: rolePath(role), SHA256: a.SHA256, Bytes: a.Bytes, Mode: mode}, source: release.sources[role]})
	}
	info, e := self.Stat()
	if e != nil {
		return nil, e
	}
	out.targets = append(out.targets, target{file: File{Path: SelfPath, SHA256: p.Self.SHA256, Bytes: info.Size(), Mode: 0555}, source: self})
	g := release.artifact["gateway"]
	out.targets = append(out.targets, target{file: File{Path: childRoot + "/gateway", SHA256: g.SHA256, Bytes: g.Bytes, Mode: 0555}, source: release.sources["gateway"]})
	// The main guarded unit precedes ingress; no unguarded daemon candidate is
	// ever written, even if an external root issues start during materialization.
	orderTargets(out.targets)
	ok = true
	return out, nil
}
func validateInputs(p Plan, input map[string][]byte, art map[string]Artifact, now time.Time, backendPath string) error {
	n := nodeManifest(p, art)
	var b firecracker.Config
	var auth access.Config
	var g gateway.Config
	if strictjson.Decode(input["backend.json"], &b) != nil || strictjson.Decode(input["auth.json"], &auth) != nil || strictjson.Decode(input["gateway.json"], &g) != nil {
		return ErrPolicy
	}
	// Initial cold deployment only. Snapshot/catalog bootstrap and immutable
	// binding migration require their own operator transaction, not an implicit fallback.
	if b.Version != 3 || b.Snapshot != nil || b.RuntimeRoot != runtimeDir || b.CgroupRoot != unitRoot+"/node/instances" || b.Node == nil || b.Quota == nil || b.IO == nil || n.CheckServiceBackend(b) != nil {
		return ErrPolicy
	}
	for role, a := range map[string]firecracker.Asset{"firecracker": b.Firecracker, "jailer": b.Jailer, "warden": b.Warden, "kernel": b.Kernel, "initrd": b.Initrd, "workspace": b.Workspace} {
		if a.Path != rolePath(role) || a.SHA256 != art[role].SHA256 {
			return ErrPolicy
		}
	}
	authority, e := access.New(auth)
	if e != nil {
		return ErrPolicy
	}
	if g.Version != 1 || g.PolicyRevision != 1 || g.StateDir != policyDir || g.EmptyRoot != childRoot || g.TenantSocket != stateDir+"/api.sock" || g.BackendAuthFile != inputDir+"/auth.json" || g.CertificateFile != Root+"/tls.pem" || g.PrivateKeyFile != Root+"/tls.key" {
		return ErrPolicy
	}
	snapshot := gateway.Snapshot{Version: 1, Epoch: 1, UID: g.UID, GID: g.GID, Listen: g.Listen, ServerName: g.ServerName, CertificatePEM: string(input["tls.pem"]), PrivateKeyPEM: string(input["tls.key"]), Keys: g.Keys}
	if _, e = gateway.NewPolicy(snapshot, authority, now); e != nil {
		return ErrPolicy
	}
	// This validation is read-only and repeats the ordinary source policy rules.
	// Startup independently validates the installed bytes before binding a node.
	if e = firecracker.ValidateAdmissionConfig(backendPath, n.Admission()); e != nil {
		return ErrPolicy
	}
	return nil
}
func (f *filesystem) self(ctx context.Context, p Plan) error {
	// A root-selected different ELF is not an installer self pin.
	in, e := os.Open("/proc/self/exe")
	if e != nil {
		return e
	}
	defer in.Close()
	st, e := in.Stat()
	if e != nil || st.Size() <= 0 || st.Size() > 64<<20 {
		return ErrPolicy
	}
	sum, e := hashFile(ctx, in, st.Size())
	if e != nil {
		return e
	}
	if sum != p.Self.SHA256 {
		return ErrPolicy
	}
	// The launcher's exported static ELF validator is used by the public entry
	// before this function; test-only shadow files never call that entry point.
	return nil
}

func orderTargets(targets []target) {
	sort.Slice(targets, func(i, j int) bool {
		rank := func(path string) int {
			if path == UnitDir+"/"+MainUnit {
				return 1
			}
			if path == UnitDir+"/"+IngressUnit {
				return 2
			}
			return 0
		}
		a, b := rank(targets[i].file.Path), rank(targets[j].file.Path)
		if a != b {
			return a < b
		}
		return targets[i].file.Path < targets[j].file.Path
	})
}
