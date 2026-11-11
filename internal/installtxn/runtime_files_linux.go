//go:build linux

package installtxn

// Internal, incomplete coordinator component. No public entry point calls this
// engine. In particular, it does NOT establish compatibility, stop services,
// activate a release or remove the legacy startup fence. A future lifecycle
// adapter must prove those prerequisites independently. All effects below are
// tested only in anchored, test-owned shadow filesystems.
import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const runtimeFilesRoot = "/etc/xandbox-runtime-files"
const runtimeFilesFence = Root + "/runtime-files-pending.json"
const runtimeFilesMaxRecord = 65536

type runtimeFileHead struct {
	Version   int    `json:"version"`
	Revision  uint64 `json:"revision"`
	Base      string `json:"base_commit_sha256"`
	Request   string `json:"request_id"`
	Input     string `json:"input_sha256"`
	Direction string `json:"direction"`
	Current   []File `json:"current"`
	Previous  []File `json:"previous"`
}
type runtimeFileInput struct {
	Base      string `json:"base_commit_sha256"`
	Expected  uint64 `json:"expected_revision"`
	Request   string `json:"request_id"`
	Direction string `json:"direction"`
	After     []File `json:"after"`
}
type runtimeFileIntent struct {
	Version int              `json:"version"`
	Input   runtimeFileInput `json:"input"`
	Prior   runtimeFileHead  `json:"prior"`
}
type runtimeFence struct {
	Version  int    `json:"version"`
	Base     string `json:"base_commit_sha256"`
	Revision uint64 `json:"revision"`
	Input    string `json:"input_sha256"`
}
type runtimeFileResult struct {
	Revision       uint64
	FilesSelected  bool
	StartupBlocked bool
	// Always false: file selection is not an activation/rollback certificate.
	ActivationAllowed bool
}

// Credentials, genesis commit, policy/ledger/session/node/catalog/owner/quota
// state, backend config and the six backend assets are NEVER writable here.
func runtimeFileModes() map[string]uint32 {
	m := map[string]uint32{SelfPath: 0555, childRoot + "/gateway": 0555,
		Root + "/launch.json": 0600, Root + "/ingress.json": 0600, Root + "/readiness.json": 0600,
		UnitDir + "/" + MainUnit: 0600, UnitDir + "/" + IngressUnit: 0600}
	for _, role := range []string{"daemon", "gateway", "ingress", "launcher", "node", "ready", "template"} {
		m[rolePath(role)] = 0555
	}
	return m
}
func validRuntimeFiles(files []File) bool {
	modes := runtimeFileModes()
	if len(files) != len(modes) {
		return false
	}
	last := ""
	for _, v := range files {
		mode, ok := modes[v.Path]
		max := int64(64 << 20)
		if mode == 0600 {
			max = MaxPlan
		}
		if !ok || v.Path <= last || v.Mode != mode || v.Bytes < 1 || v.Bytes > max || !digestPattern.MatchString(v.SHA256) {
			return false
		}
		last = v.Path
		delete(modes, v.Path)
	}
	return len(modes) == 0
}
func runtimeSubset(t transaction) []File {
	modes := runtimeFileModes()
	var out []File
	for _, v := range t.Files {
		if _, ok := modes[v.Path]; ok {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
func validRuntimeHead(h runtimeFileHead, zero bool) bool {
	if h.Version != 1 || !digestPattern.MatchString(h.Base) || !validRuntimeFiles(h.Current) {
		return false
	}
	if h.Revision == 0 {
		return zero && h.Request == "" && h.Input == "" && h.Direction == "" && len(h.Previous) == 0
	}
	if !requestPattern.MatchString(h.Request) || !digestPattern.MatchString(h.Input) || (h.Direction != "forward" && h.Direction != "rollback") || h.Direction == "forward" && h.Revision == ^uint64(0) || !validRuntimeFiles(h.Previous) || bytes.Equal(encode(h.Current), encode(h.Previous)) {
		return false
	}
	// Decode is an authority boundary, not just a shape check. Reconstruct the
	// exact committed request; a domain-valid but unrelated input hash refuses.
	i := runtimeFileInput{Base: h.Base, Expected: h.Revision - 1, Request: h.Request, Direction: h.Direction, After: h.Current}
	return h.Input == digest(encode(i))
}
func validRuntimeIntent(p runtimeFileIntent) bool {
	i := p.Input
	if p.Version != 1 || !validRuntimeHead(p.Prior, true) || i.Base != p.Prior.Base || i.Expected != p.Prior.Revision || i.Expected == ^uint64(0) || !requestPattern.MatchString(i.Request) || i.Request == p.Prior.Request || !validRuntimeFiles(i.After) || bytes.Equal(encode(i.After), encode(p.Prior.Current)) {
		return false
	}
	if i.Direction == "rollback" {
		return p.Prior.Revision > 0 && bytes.Equal(encode(i.After), encode(p.Prior.Previous))
	}
	return i.Direction == "forward" && i.Expected < ^uint64(0)-1
}
func nextRuntimeHead(p runtimeFileIntent) runtimeFileHead {
	return runtimeFileHead{Version: 1, Revision: p.Input.Expected + 1, Base: p.Input.Base, Request: p.Input.Request, Input: digest(encode(p.Input)), Direction: p.Input.Direction, Current: p.Input.After, Previous: p.Prior.Current}
}
func runtimeFenceBytes(h runtimeFileHead) []byte {
	return encode(runtimeFence{Version: 1, Base: h.Base, Revision: h.Revision, Input: h.Input})
}
func (f *filesystem) runtimeHead() (runtimeFileHead, error) {
	var h runtimeFileHead
	b, e := f.read(runtimeFilesRoot+"/head.json", runtimeFilesMaxRecord, 0600)
	if e != nil {
		return h, e
	}
	if strictjson.Decode(b, &h) != nil || !validRuntimeHead(h, false) || !bytes.Equal(b, encode(h)) {
		return h, ErrInventory
	}
	return h, nil
}
func (f *filesystem) runtimeIntent() (runtimeFileIntent, error) {
	var p runtimeFileIntent
	b, e := f.read(runtimeFilesRoot+"/intent.json", runtimeFilesMaxRecord, 0600)
	if e != nil {
		return p, e
	}
	if strictjson.Decode(b, &p) != nil || !validRuntimeIntent(p) || !bytes.Equal(b, encode(p)) {
		return p, ErrInventory
	}
	return p, nil
}
func (f *filesystem) runtimeBase(base string) (transaction, error) {
	t, e := f.readTransaction("commit")
	if e != nil {
		return t, e
	}
	if digest(encode(t)) != base {
		return t, ErrConflict
	}
	return t, nil
}

func (f *filesystem) runtimeProtected(ctx context.Context, t transaction) error {
	allowed := map[string]bool{".lock": true, "commit.json": true, filepath.Base(runtimeFilesFence): true, "." + filepath.Base(runtimeFilesFence) + ".next": true}
	for _, name := range configNamesFor(t.Plan.Version) {
		allowed[name] = true
	}
	names, e := f.names(Root)
	if e != nil {
		return e
	}
	for _, name := range names {
		if !allowed[name] {
			return ErrInventory
		}
	}
	var policy File
	if t.Plan.Version == 2 {
		policy, _, e = f.effectivePolicy(t, true)
		if e != nil {
			return e
		}
	}
	writable := runtimeFileModes()
	for _, v := range t.Files {
		if _, ok := writable[v.Path]; ok {
			continue
		}
		if v.Path == gateway.ManagedPolicyPath {
			v = policy
		}
		if e = f.verify(ctx, v); e != nil {
			return e
		}
	}
	return nil
}
func (f *filesystem) runtimeRecord(path string, previous, next []byte, stage string) error {
	scratch := filepath.Dir(path) + "/." + filepath.Base(path) + ".next"
	// Exactly matching retries still sync both descriptor and directory.
	if e := f.exact(path, next, 0600); e == nil {
		if yes, err := f.exists(scratch); err != nil || yes {
			return ErrInventory
		}
		in, e := f.open(path, unix.O_RDONLY, 0600)
		if e != nil {
			return e
		}
		e = in.Sync()
		in.Close()
		if e != nil {
			return e
		}
		return f.syncDir(filepath.Dir(path))
	}
	old, e := f.read(path, runtimeFilesMaxRecord, 0600)
	if len(previous) == 0 {
		if !errors.Is(e, unix.ENOENT) {
			return ErrInventory
		}
	} else if e != nil || !bytes.Equal(old, previous) {
		return ErrInventory
	}
	if e = f.putPrefix(scratch, next, 0600, stage); e != nil {
		return e
	}
	dir, e := f.directory(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	// Repeat the expected visible authority immediately before replacement.
	if len(previous) == 0 {
		if yes, err := f.exists(path); err != nil || yes {
			return ErrInventory
		}
	} else if e = f.exact(path, previous, 0600); e != nil {
		return e
	}
	if e = unix.Renameat(int(dir.Fd()), filepath.Base(scratch), int(dir.Fd()), filepath.Base(path)); e != nil {
		return e
	}
	if e = f.point(stage + "-renamed"); e != nil {
		return e
	}
	if e = dir.Sync(); e != nil {
		return e
	}
	return f.point(stage + "-durable")
}
func (f *filesystem) runtimeInventory(ctx context.Context, head *runtimeFileHead, pending *runtimeFileIntent) error {
	names, e := f.names(runtimeFilesRoot)
	if e != nil {
		return e
	}
	allowed := map[string]bool{"objects": true, "head.json": true}
	if pending != nil {
		allowed["intent.json"] = true
		allowed[".intent.json.next"] = true
		allowed[".head.json.next"] = true
	}
	for _, n := range names {
		if !allowed[n] {
			return ErrInventory
		}
	}
	objects, e := f.names(runtimeFilesRoot + "/objects")
	if e != nil {
		return e
	}
	pins := map[string]File{}
	add := func(items []File) error {
		for _, v := range items {
			if old, ok := pins[v.SHA256]; ok && old.Bytes != v.Bytes {
				return ErrInventory
			}
			pins[v.SHA256] = v
		}
		return nil
	}
	if head != nil {
		if e = add(head.Current); e != nil {
			return e
		}
		if e = add(head.Previous); e != nil {
			return e
		}
	}
	if pending != nil {
		if e = add(pending.Prior.Current); e != nil {
			return e
		}
		if e = add(pending.Prior.Previous); e != nil {
			return e
		}
		if e = add(pending.Input.After); e != nil {
			return e
		}
	}
	// At most current + retained + one in-flight candidate, with shared bytes
	// deduplicated. Unknown objects are not adopted, overwritten or deleted.
	if len(objects) > 3*len(runtimeFileModes()) {
		return ErrInventory
	}
	sealed := map[string]bool{}
	for _, name := range objects {
		pin, ok := pins[name]
		if !ok {
			return ErrInventory
		}
		in, e := f.open(runtimeFilesRoot+"/objects/"+name, unix.O_RDONLY, 0)
		if e != nil {
			return e
		}
		st, e := in.Stat()
		in.Close()
		if e != nil || st.Size() > pin.Bytes {
			return ErrInventory
		}
		if st.Mode().Perm() == 0400 {
			pin.Path = runtimeFilesRoot + "/objects/" + name
			pin.Mode = 0400
			if e = f.verify(ctx, pin); e != nil {
				return e
			}
			sealed[name] = true
		} else if st.Mode().Perm() != 0600 || pending == nil {
			return ErrInventory
		}
	}
	if head != nil {
		for _, list := range [][]File{head.Current, head.Previous} {
			for _, v := range list {
				if !sealed[v.SHA256] {
					return ErrInventory
				}
			}
		}
	}
	return nil
}
func (f *filesystem) runtimeObject(ctx context.Context, pin File, source *target) error {
	object := File{Path: runtimeFilesRoot + "/objects/" + pin.SHA256, SHA256: pin.SHA256, Bytes: pin.Bytes, Mode: 0400}
	if e := f.verify(ctx, object); e == nil {
		return nil
	}
	if source == nil {
		return ErrInventory
	}
	copy := *source
	copy.file = object
	return f.materialize(ctx, copy)
}
func (f *filesystem) runtimeCapture(ctx context.Context, files []File) error {
	for _, v := range files {
		object := v
		object.Path = runtimeFilesRoot + "/objects/" + v.SHA256
		object.Mode = 0400
		if e := f.verify(ctx, object); e == nil {
			continue
		}
		if e := f.verify(ctx, v); e != nil {
			return e
		}
		in, e := f.open(v.Path, unix.O_RDONLY, v.Mode)
		if e != nil {
			return e
		}
		source := target{file: v, source: in}
		e = f.runtimeObject(ctx, v, &source)
		in.Close()
		if e != nil {
			return e
		}
	}
	return nil
}
func (f *filesystem) runtimeReplace(ctx context.Context, old, next File) error {
	if next.Path == childRoot+"/gateway" && old.Path == next.Path {
		return f.runtimeGatewayReplace(ctx, old, next)
	}
	return f.runtimeReplaceFile(ctx, old, next)
}

func (f *filesystem) runtimeReplaceFile(ctx context.Context, old, next File) error {
	if old.Path != next.Path || old.Mode != next.Mode {
		return ErrPolicy
	}
	if e := f.verify(ctx, next); e == nil {
		// A crash after rename may leave the complete sealed scratch as well only
		// if the namespace drifted. Never silently remove that unknown second file.
		yes, e := f.exists(filepath.Dir(next.Path) + "/." + filepath.Base(next.Path) + ".runtime-next")
		if e != nil {
			return e
		}
		if yes {
			return ErrInventory
		}
		return nil
	}
	if e := f.verify(ctx, old); e != nil {
		return e
	}
	before, e := f.open(old.Path, unix.O_RDONLY, old.Mode)
	if e != nil {
		return e
	}
	defer before.Close()
	id, e := before.Stat()
	if e != nil {
		return e
	}
	object, e := f.open(runtimeFilesRoot+"/objects/"+next.SHA256, unix.O_RDONLY, 0400)
	if e != nil {
		return e
	}
	defer object.Close()
	scratch := next
	scratch.Path = filepath.Dir(next.Path) + "/." + filepath.Base(next.Path) + ".runtime-next"
	if e = f.materialize(ctx, target{file: scratch, source: object}); e != nil {
		return e
	}
	current, e := f.open(old.Path, unix.O_RDONLY, old.Mode)
	if e != nil {
		return e
	}
	now, e := current.Stat()
	current.Close()
	if e != nil || !os.SameFile(id, now) {
		return ErrInventory
	}
	if e = f.verify(ctx, old); e != nil {
		return e
	}
	dir, e := f.directory(filepath.Dir(next.Path))
	if e != nil {
		return e
	}
	defer dir.Close()
	if e = unix.Renameat(int(dir.Fd()), filepath.Base(scratch.Path), int(dir.Fd()), filepath.Base(next.Path)); e != nil {
		return e
	}
	label := "runtime-swap-" + filepath.Base(next.Path)
	if e = f.point(label + "-renamed"); e != nil {
		return e
	}
	if e = dir.Sync(); e != nil {
		return e
	}
	return f.point(label + "-durable")
}
func (f *filesystem) runtimeGC(ctx context.Context, prior, next runtimeFileHead) error {
	keep := map[string]bool{}
	for _, list := range [][]File{next.Current, next.Previous} {
		for _, v := range list {
			keep[v.SHA256] = true
		}
	}
	remove := map[string]File{}
	for _, v := range prior.Previous {
		if !keep[v.SHA256] {
			remove[v.SHA256] = v
		}
	}
	for sha, v := range remove {
		v.Path = runtimeFilesRoot + "/objects/" + sha
		v.Mode = 0400
		if e := f.verify(ctx, v); errors.Is(e, unix.ENOENT) {
			continue
		} else if e != nil {
			return e
		}
		dir, e := f.directory(runtimeFilesRoot + "/objects")
		if e != nil {
			return e
		}
		e = unix.Unlinkat(int(dir.Fd()), sha, 0)
		if e == nil {
			e = dir.Sync()
		}
		dir.Close()
		if e != nil {
			return e
		}
		if e = f.point("runtime-object-reclaimed"); e != nil {
			return e
		}
	}
	return nil
}

// runtimeFileExchange deliberately keeps the legacy installer fail-closed by
// retaining runtimeFilesFence even after all file effects and CAS are durable.
// It MUST NOT become a public command until source-bound compatibility, real
// stop/reclaim, a genesis-preserving startup overlay/self-pin and same-PID
// health/reboot adapters are implemented and qualified. observeStopped is an
// internal effect boundary, NOT a caller-supplied boolean or CLI override.
func (f *filesystem) runtimeFileExchange(ctx context.Context, base string, expected uint64, request, direction string, targets []target, observeStopped func(context.Context) error) (runtimeFileResult, error) {
	var zero runtimeFileResult
	if !digestPattern.MatchString(base) || expected == ^uint64(0) || direction == "forward" && expected == ^uint64(0)-1 || !requestPattern.MatchString(request) || (direction != "forward" && direction != "rollback") || observeStopped == nil {
		return zero, ErrPolicy
	}
	if e := ctx.Err(); e != nil {
		return zero, e
	}
	done, e := f.operationLock(ctx, true)
	if e != nil {
		return zero, e
	}
	defer done()
	unlock, e := f.existingLock(ctx, true)
	if e != nil {
		return zero, e
	}
	defer unlock()
	// The standalone drain component is not a Stop/reclaim proof. Composing
	// these engines requires the future owned operation scope + lifecycle adapter.
	for _, root := range []string{runtimeDrainRoot, runtimeStopRoot, runtimeWorkStopRoot, runtimeWorkStopAnchor, runtimeWorkStopAnchorScratch, runtimeCloseRoot, runtimeCloseAnchor, runtimeCloseAnchorScratch, runtimeResultsCloseRoot, runtimeResultsCloseAnchor, runtimeResultsCloseAnchorScratch, runtimeResultsStopRoot} {
		if yes, err := f.exists(root); err != nil {
			return zero, err
		} else if yes {
			return zero, ErrInventory
		}
	}
	genesis, e := f.runtimeBase(base)
	if e != nil {
		return zero, e
	}
	if e = f.runtimeProtected(ctx, genesis); e != nil {
		return zero, e
	}
	h, e := f.runtimeHead()
	hasHead := e == nil
	if e != nil && !errors.Is(e, unix.ENOENT) {
		return zero, e
	}
	p, e := f.runtimeIntent()
	pending := e == nil
	if e != nil && !errors.Is(e, unix.ENOENT) {
		return zero, e
	}
	var after []File
	sources := map[string]target{}
	if direction == "rollback" {
		if len(targets) != 0 || !hasHead {
			return zero, ErrPolicy
		}
		after = h.Previous
		if h.Revision == expected+1 && h.Request == request {
			after = h.Current
		}
	} else {
		for _, v := range targets {
			after = append(after, v.file)
			if _, ok := sources[v.file.Path]; ok {
				return zero, ErrPolicy
			}
			sources[v.file.Path] = v
		}
		sort.Slice(after, func(i, j int) bool { return after[i].Path < after[j].Path })
	}
	if !validRuntimeFiles(after) {
		return zero, ErrPolicy
	}
	input := runtimeFileInput{Base: base, Expected: expected, Request: request, Direction: direction, After: after}
	same := hasHead && h.Revision == expected+1 && h.Request == request && h.Input == digest(encode(input)) && h.Base == base
	if !pending && !same {
		if hasHead {
			if h.Revision != expected || h.Request == request || h.Base != base {
				return zero, ErrConflict
			}
			if e = f.runtimeRecord(runtimeFilesFence, runtimeFenceBytes(h), runtimeFenceBytes(h), "runtime-startup-fence"); e != nil {
				return zero, e
			}
			// Only recovery of a bound durable intent may adopt a mixed vector.
			// A new request must find the exact current selected images, even if
			// an unrecognized replacement already equals its desired new bytes.
			for _, v := range h.Current {
				if e = f.runtimeReplace(ctx, v, v); e != nil {
					return zero, e
				}
			}
		} else {
			if expected != 0 {
				return zero, ErrConflict
			}
			// Payload objects are created only AFTER a durable intent. Their
			// survival without either intent or head is lost authority, not a
			// fresh installation: never reset the monotonic revision to zero.
			objects, err := f.names(runtimeFilesRoot + "/objects")
			if err != nil && !errors.Is(err, unix.ENOENT) {
				return zero, err
			}
			if len(objects) != 0 {
				return zero, ErrInventory
			}
			if e = f.verifyTransaction(ctx, genesis); e != nil {
				return zero, e
			}
			h = runtimeFileHead{Version: 1, Base: base, Current: runtimeSubset(genesis)}
		}
		p = runtimeFileIntent{Version: 1, Input: input, Prior: h}
		if !validRuntimeIntent(p) {
			return zero, ErrPolicy
		}
	}
	if pending {
		if !bytes.Equal(encode(p.Input), encode(input)) {
			return zero, ErrConflict
		}
		next := nextRuntimeHead(p)
		if hasHead && !bytes.Equal(encode(h), encode(p.Prior)) && !bytes.Equal(encode(h), encode(next)) {
			return zero, ErrInventory
		}
		if !hasHead && p.Prior.Revision != 0 {
			return zero, ErrInventory
		}
		if p.Prior.Revision == 0 && !bytes.Equal(encode(p.Prior.Current), encode(runtimeSubset(genesis))) {
			return zero, ErrInventory
		}
	}
	if e = observeStopped(ctx); e != nil {
		return zero, e
	}
	// Bootstrap only while holding BOTH original installer locks; never create,
	// replace or unlink those permanent lock inodes.
	if e = f.mkdir(runtimeFilesRoot, 0700); e != nil {
		return zero, e
	}
	if e = f.mkdir(runtimeFilesRoot+"/objects", 0700); e != nil {
		return zero, e
	}
	var currentHead *runtimeFileHead
	if hasHead {
		currentHead = &h
	}
	var currentIntent *runtimeFileIntent
	if pending || !same {
		currentIntent = &p
	}
	if e = f.runtimeInventory(ctx, currentHead, currentIntent); e != nil {
		return zero, e
	}
	if same && !pending {
		if e = f.runtimeRecord(runtimeFilesFence, runtimeFenceBytes(h), runtimeFenceBytes(h), "runtime-startup-fence"); e != nil {
			return zero, e
		}
		for i, v := range h.Current {
			if e = f.runtimeReplace(ctx, h.Previous[i], v); e != nil {
				return zero, e
			}
		}
		if _, e = f.runtimeBase(base); e != nil {
			return zero, e
		}
		if e = f.syncDir(runtimeFilesRoot); e != nil {
			return zero, e
		}
		return runtimeFileResult{Revision: h.Revision, FilesSelected: true, StartupBlocked: true}, nil
	}
	if !pending {
		// Bind an interrupted pre-rename scratch to these exact bytes, never to a
		// different request or a user-selected journal target.
		if e = f.runtimeRecord(runtimeFilesRoot+"/intent.json", nil, encode(p), "runtime-intent"); e != nil {
			return zero, e
		}
	}
	next := nextRuntimeHead(p)
	// The complete old and new immutable bytes must be durable BEFORE any final
	// target changes. Recovery after the first target rename needs no producer.
	if e = f.runtimeCapture(ctx, p.Prior.Current); e != nil {
		return zero, e
	}
	if e = f.point("runtime-old-objects-durable"); e != nil {
		return zero, e
	}
	for _, v := range p.Input.After {
		var source *target
		if s, ok := sources[v.Path]; ok {
			copy := s
			source = &copy
		}
		if e = f.runtimeObject(ctx, v, source); e != nil {
			return zero, e
		}
	}
	if e = f.point("runtime-new-objects-durable"); e != nil {
		return zero, e
	}
	var previousFence []byte
	if p.Prior.Revision > 0 {
		previousFence = runtimeFenceBytes(p.Prior)
	}
	if e = f.runtimeRecord(runtimeFilesFence, previousFence, runtimeFenceBytes(next), "runtime-startup-fence"); e != nil {
		return zero, e
	}
	if e = observeStopped(ctx); e != nil {
		return zero, e
	}
	if _, e = f.runtimeBase(base); e != nil {
		return zero, e
	}
	if e = f.runtimeProtected(ctx, genesis); e != nil {
		return zero, e
	}
	for i, v := range p.Input.After {
		if e = f.runtimeReplace(ctx, p.Prior.Current[i], v); e != nil {
			return zero, e
		}
	}
	for _, v := range next.Current {
		if e = f.verify(ctx, v); e != nil {
			return zero, e
		}
	}
	if e = f.point("runtime-files-durable"); e != nil {
		return zero, e
	}
	if _, e = f.runtimeBase(base); e != nil {
		return zero, e
	}
	if e = f.runtimeProtected(ctx, genesis); e != nil {
		return zero, e
	}
	var priorRaw []byte
	if p.Prior.Revision > 0 {
		priorRaw = encode(p.Prior)
	}
	if e = f.runtimeRecord(runtimeFilesRoot+"/head.json", priorRaw, encode(next), "runtime-head"); e != nil {
		return zero, e
	}
	if e = f.runtimeGC(ctx, p.Prior, next); e != nil {
		return zero, e
	}
	if _, e = f.runtimeBase(base); e != nil {
		return zero, e
	}
	if e = f.exact(runtimeFilesFence, runtimeFenceBytes(next), 0600); e != nil {
		return zero, e
	}
	dir, e := f.directory(runtimeFilesRoot)
	if e != nil {
		return zero, e
	}
	defer dir.Close()
	if e = unix.Unlinkat(int(dir.Fd()), "intent.json", 0); e != nil {
		return zero, e
	}
	if e = f.point("runtime-intent-unlinked"); e != nil {
		return zero, e
	}
	if e = dir.Sync(); e != nil {
		return zero, e
	}
	if e = f.point("runtime-intent-removed"); e != nil {
		return zero, e
	}
	return runtimeFileResult{Revision: next.Revision, FilesSelected: true, StartupBlocked: true}, nil
}
