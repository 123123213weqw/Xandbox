//go:build linux

package installtxn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Opt-in fixed administrative trust locations. No TOFU, embedded default key,
// public key/path override, provisioning, signing, repair or deployment here.
const runtimeProgramAuthorityPath = "/etc/xandbox-artifact-authorities.json"
const runtimeProgramCertificateRoot = "/srv/xandbox-runtime-approvals"

type runtimeProgramInput struct {
	file   File
	source *os.File // BORROWED original producer FD; never seek, duplicate or close.
}
type runtimeApprovalParent struct {
	Device, Inode  uint64
	Mode, UID, GID uint32
}
type runtimeApprovalRecord struct {
	file   stateEntryIdentity
	parent runtimeApprovalParent
	sha    string
}
type runtimeProgramEvidence struct {
	authority, certificate runtimeApprovalRecord
	sources                [9]stateEntryIdentity
}

func runtimeProgramPaths() map[string]string {
	m := map[string]string{SelfPath: "installer", childRoot + "/gateway": "gateway"}
	for _, role := range []string{"daemon", "gateway", "ingress", "launcher", "node", "ready", "template"} {
		m[rolePath(role)] = role
	}
	return m
}
func runtimeProgramInputs(inputs []runtimeProgramInput) ([]runtimeApprovedProgram, error) {
	paths := runtimeProgramPaths()
	if len(inputs) != 9 || len(paths) != 9 {
		return nil, ErrPolicy
	}
	byRole := map[string]runtimeApprovedProgram{}
	last := ""
	for _, in := range inputs {
		role, ok := paths[in.file.Path]
		if !ok || in.file.Path <= last || in.source == nil || in.file.Mode != 0555 || in.file.Bytes < 1 || in.file.Bytes > 64<<20 || !digestPattern.MatchString(in.file.SHA256) {
			return nil, ErrPolicy
		}
		p := runtimeApprovedProgram{role, in.file.SHA256, in.file.Bytes}
		if prior, ok := byRole[role]; ok && prior != p {
			return nil, ErrPolicy // Chroot gateway MUST be the same approved bytes.
		}
		byRole[role], last = p, in.file.Path
		delete(paths, in.file.Path)
	}
	if len(paths) != 0 {
		return nil, ErrPolicy
	}
	var programs []runtimeApprovedProgram
	for _, role := range runtimeProgramRoles() {
		programs = append(programs, byRole[role])
	}
	if !validRuntimeApprovedPrograms(programs) {
		return nil, ErrPolicy
	}
	return programs, nil
}

// Complete bounded trusted record read, with linked-file and parent reproof.
// Cross-stage parent pins intentionally exclude child-count/time/size: the
// coordinator may legitimately add sibling journals. WITHIN a read all parent
// metadata except atime must remain unchanged. The record inode/ctime/hash
// itself is pinned across stages; a same-content replacement revokes a pin.
func (f *filesystem) runtimeApprovalRecord(ctx context.Context, path string, private bool) ([]byte, runtimeApprovalRecord, error) {
	var zero runtimeApprovalRecord
	if e := ctx.Err(); e != nil {
		return nil, zero, e
	}
	parent, e := f.directory(filepath.Dir(path))
	if e != nil {
		return nil, zero, e
	}
	defer parent.Close()
	mode := uint32(0)
	if private {
		mode = 0700
	}
	if e = trustedStat(int(parent.Fd()), true, mode); e != nil {
		return nil, zero, e
	}
	var beforeParent, afterParent, linkedParent, before, after, linked unix.Stat_t
	if e = unix.Fstat(int(parent.Fd()), &beforeParent); e != nil {
		return nil, zero, e
	}
	fd, e := unix.Openat(int(parent.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, zero, e
	}
	in := os.NewFile(uintptr(fd), "runtime-program-approval-record")
	defer in.Close()
	if e = trustedStat(fd, false, 0600); e != nil {
		return nil, zero, e
	}
	if e = unix.Fstat(fd, &before); e != nil {
		return nil, zero, e
	}
	if before.Size < 1 || before.Size > MaxPlan {
		return nil, zero, ErrInventory
	}
	raw, e := io.ReadAll(contextReader{ctx, io.LimitReader(in, MaxPlan+1)})
	if e != nil {
		return nil, zero, e
	}
	if int64(len(raw)) != before.Size {
		return nil, zero, ErrInventory
	}
	if e = unix.Fstat(fd, &after); e != nil {
		return nil, zero, e
	}
	if e = unix.Fstatat(int(parent.Fd()), filepath.Base(path), &linked, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return nil, zero, e
	}
	if e = unix.Fstat(int(parent.Fd()), &afterParent); e != nil {
		return nil, zero, e
	}
	current, e := f.directory(filepath.Dir(path))
	if e != nil {
		return nil, zero, e
	}
	defer current.Close()
	if e = unix.Fstat(int(current.Fd()), &linkedParent); e != nil {
		return nil, zero, e
	}
	if stateEntry(before) != stateEntry(after) || stateEntry(after) != stateEntry(linked) || stateEntry(beforeParent) != stateEntry(afterParent) || stateEntry(afterParent) != stateEntry(linkedParent) {
		return nil, zero, ErrInventory
	}
	if e = ctx.Err(); e != nil {
		return nil, zero, e
	}
	return raw, runtimeApprovalRecord{stateEntry(before), runtimeApprovalParent{uint64(beforeParent.Dev), beforeParent.Ino, beforeParent.Mode, beforeParent.Uid, beforeParent.Gid}, digest(raw)}, nil
}

func runtimeProgramSource(ctx context.Context, in runtimeProgramInput) (stateEntryIdentity, error) {
	var zero stateEntryIdentity
	if e := ctx.Err(); e != nil {
		return zero, e
	}
	if in.source == nil || in.file.Bytes < 1 || in.file.Bytes > 64<<20 || !digestPattern.MatchString(in.file.SHA256) {
		return zero, ErrPolicy
	}
	var before, after unix.Stat_t
	if e := unix.Fstat(int(in.source.Fd()), &before); e != nil {
		return zero, e
	}
	if e := trustedStat(int(in.source.Fd()), false, 0); e != nil {
		return zero, e
	}
	if before.Size != in.file.Bytes {
		return zero, ErrInventory
	}
	h := sha256.New()
	// ReaderAt preserves the BORROWED original description's offset. Every
	// byte and the exact size are checked; no cached hash or Stat-only success.
	n, e := io.CopyBuffer(h, contextReader{ctx, io.NewSectionReader(in.source, 0, in.file.Bytes+1)}, make([]byte, hashScratchSize(in.file.Bytes)))
	if e != nil {
		return zero, e
	}
	if n != in.file.Bytes || hex.EncodeToString(h.Sum(nil)) != in.file.SHA256 {
		return zero, ErrInventory
	}
	if e = unix.Fstat(int(in.source.Fd()), &after); e != nil {
		return zero, e
	}
	if stateEntry(before) != stateEntry(after) {
		return zero, ErrInventory
	}
	if e = ctx.Err(); e != nil {
		return zero, e
	}
	return stateEntry(before), nil
}

// Administrative signature + actual original FD bytes ONLY. This does NOT
// parse/execute an ELF, inspect ABI/formats/budgets or grant file selection.
func (f *filesystem) inspectRuntimeProgramApproval(ctx context.Context, inputs []runtimeProgramInput) (runtimeProgramEvidence, error) {
	var zero, out runtimeProgramEvidence
	if _, bounded := ctx.Deadline(); !bounded {
		return zero, ErrPolicy
	}
	if e := ctx.Err(); e != nil {
		return zero, e
	}
	programs, e := runtimeProgramInputs(inputs)
	if e != nil {
		return zero, e
	}
	policyRaw, authority, e := f.runtimeApprovalRecord(ctx, runtimeProgramAuthorityPath, false)
	if e != nil {
		return zero, e
	}
	policy, e := decodeRuntimeProgramAuthority(policyRaw)
	if e != nil {
		return zero, e
	}
	path := runtimeProgramCertificateRoot + "/" + digest(encode(programs)) + ".json"
	certRaw, certificate, e := f.runtimeApprovalRecord(ctx, path, true)
	if e != nil {
		return zero, e
	}
	if _, e = decodeRuntimeProgramCertificate(certRaw, policy, programs); e != nil {
		return zero, e
	}
	// NO original source FD is accessed until the trusted signature passed.
	for i, in := range inputs {
		out.sources[i], e = runtimeProgramSource(ctx, in)
		if e != nil {
			return zero, e
		}
	}
	// Reprove trust/revocation after all program IO, then every original FD.
	_, finalAuthority, e := f.runtimeApprovalRecord(ctx, runtimeProgramAuthorityPath, false)
	if e != nil {
		return zero, e
	}
	_, finalCertificate, e := f.runtimeApprovalRecord(ctx, path, true)
	if e != nil {
		return zero, e
	}
	if authority != finalAuthority || certificate != finalCertificate {
		return zero, ErrConflict
	}
	for i, in := range inputs {
		var st unix.Stat_t
		if e = unix.Fstat(int(in.source.Fd()), &st); e != nil {
			return zero, e
		}
		if stateEntry(st) != out.sources[i] {
			return zero, ErrInventory
		}
	}
	out.authority, out.certificate = authority, certificate
	if e = ctx.Err(); e != nil {
		return zero, e
	}
	return out, nil
}
