//go:build linux

package installtxn

import (
	"context"
	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"os"
	"time"
)

// Distinct cold producer. Every config source stays freshly pinned/open; the
// SAME full Config4 (never a serialized legacy projection) supplies retention.
func (f *filesystem) prepareResults(ctx context.Context, p Plan, release *releaseView) (*prepared, error) {
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
	for _, v := range planInputs(p) {
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
	if e = validateResultInputs(p, input, release.artifact, time.Now(), p.Backend.Path); e != nil {
		return nil, e
	}
	var cfg firecracker.Config
	if strictjson.Decode(input["backend.json"], &cfg) != nil {
		return nil, ErrPolicy
	}
	generated, e := renderResults(p, cfg.IO.Device, release.artifact, *cfg.Results)
	if e != nil {
		return nil, e
	}
	appendTarget := func(path string, raw []byte, mode uint32) {
		out.targets = append(out.targets, target{file: File{Path: path, SHA256: digest(raw), Bytes: int64(len(raw)), Mode: mode}, data: raw})
	}
	for _, v := range planInputs(p) {
		appendTarget(Root+"/"+v.name, input[v.name], 0600)
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
func validateResultInputs(p Plan, input map[string][]byte, art map[string]Artifact, now time.Time, backendPath string) error {
	n := nodeManifest(p, art)
	var b firecracker.Config
	var auth access.Config
	var g gateway.Config
	if strictjson.Decode(input["backend.json"], &b) != nil || strictjson.Decode(input["auth.json"], &auth) != nil || strictjson.Decode(input["gateway.json"], &g) != nil {
		return ErrPolicy
	}
	// Initial cold deployment only. Snapshot/catalog bootstrap and immutable
	// binding migration require their own operator transaction, not an implicit fallback.
	if b.Version != 4 || b.Results == nil || !b.Results.Valid() || b.Snapshot != nil || b.RuntimeRoot != runtimeDir || b.CgroupRoot != unitRoot+"/node/instances" || b.Node == nil || b.Quota == nil || b.IO == nil {
		return ErrPolicy
	}
	contract, contractErr := launch.NewResultContract(n, *b.Results)
	if contractErr != nil || contract.CheckServiceBackend(b) != nil {
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
	if g.Version != p.Version || g.ValidateShape() != nil || g.PolicyRevision != 1 || g.StateDir != policyDir || g.EmptyRoot != childRoot || g.TenantSocket != stateDir+"/api.sock" || g.BackendAuthFile != inputDir+"/auth.json" {
		return ErrPolicy
	}
	var snapshot gateway.Snapshot
	if p.Version == 1 {
		if g.CertificateFile != Root+"/tls.pem" || g.PrivateKeyFile != Root+"/tls.key" {
			return ErrPolicy
		}
		snapshot = gateway.Snapshot{Version: 1, Epoch: 1, UID: g.UID, GID: g.GID, Listen: g.Listen, ServerName: g.ServerName, CertificatePEM: string(input["tls.pem"]), PrivateKeyPEM: string(input["tls.key"]), Keys: g.Keys}
	} else {
		if p.Policy == nil || g.InitialPolicySHA256 != p.Policy.SHA256 {
			return ErrPolicy
		}
		snapshot, e = gateway.ValidateManagedSnapshot(g, input["gateway-policy.json"], "", authority, now)
		if e != nil || snapshot.Epoch != 1 {
			return ErrPolicy
		}
	}
	if _, e = gateway.NewPolicy(snapshot, authority, now); e != nil {
		return ErrPolicy
	}
	// This validation is read-only and repeats the ordinary source policy rules.
	// Startup independently validates the installed bytes before binding a node.
	if e = firecracker.ValidateAdmissionConfig(backendPath, n.Admission()); e != nil {
		return ErrPolicy
	}
	if e = firecracker.ValidateResultAdmissionConfig(backendPath, b.Results.Limits()); e != nil {
		return ErrPolicy
	}
	return nil
}
