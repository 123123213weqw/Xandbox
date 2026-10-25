//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: hold the first exact Creating session journal file Sync, before
// Broker.mutate can call Core. No successful Sync result is emulated.
import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

const sessionTicketMax = 128 << 10

var sessionTicketTempPattern = regexp.MustCompile(`^\.session-[0-9]+$`)

func sessionTicketPath(path string) bool {
	return filepath.Clean(path) == path && filepath.Dir(path) == "/srv/state/sessions" && sessionTicketTempPattern.MatchString(filepath.Base(path))
}

type sessionTicketBoundary struct {
	KeyHash, SpecHash, ExistingID string
	ID                            string
	Payload                       []byte
}

func sessionTicketHashes(key string) (string, string, error) {
	if !hashPattern.MatchString(key) {
		return "", "", errors.New("fixed private ticket key required")
	}
	req, e := sandbox.NormalizeCreate(nodeSpec())
	if e != nil {
		return "", "", e
	}
	data, e := json.Marshal(struct {
		Kind     string
		Expected uint64
		Create   sandbox.CreateRequest
	}{"create", 0, req})
	if e != nil {
		return "", "", e
	}
	kh, sh := sha256.Sum256([]byte("create\x00"+key)), sha256.Sum256(data)
	return hex.EncodeToString(kh[:]), hex.EncodeToString(sh[:]), nil
}
func sessionTicketInitial(data []byte, key, spec string) (session.Record, error) {
	var env struct {
		Version int            `json:"version"`
		Record  session.Record `json:"record"`
	}
	if len(data) == 0 || len(data) > sessionTicketMax || !hashPattern.MatchString(key) || !hashPattern.MatchString(spec) {
		return session.Record{}, errors.New("ticket envelope/key bound")
	}
	if e := strictjson.Decode(data, &env); e != nil {
		return session.Record{}, e
	}
	canonical, e := json.MarshalIndent(env, "", "  ")
	if e != nil || !bytes.Equal(data, append(canonical, '\n')) {
		return session.Record{}, errors.New("ticket payload is not the complete ordinary envelope")
	}
	r := env.Record
	if env.Version != 1 || !hex32Pattern(r.ID) || r.TenantID != "nested-fixture" || r.CreateKeyHash != key || r.CreateSpecHash != spec || r.State != session.Creating || r.Revision != 0 || r.Current != (sandbox.Ref{}) || len(r.Attempts) != 1 || r.CreatedAt.IsZero() || r.UpdatedAt.Before(r.CreatedAt) || r.UpdatedAt.Sub(r.CreatedAt) > 40*time.Second {
		return session.Record{}, errors.New("not exact initial pre-Core session journal")
	}
	a := r.Attempts[0]
	if a.KeyHash != key || a.SpecHash != spec || a.State != session.Preparing || a.ExpectedRevision != 0 || a.ResultRevision != 1 || a.From != (sandbox.Ref{}) || a.Target != (sandbox.Ref{}) || !a.StartedAt.Equal(r.CreatedAt) || !a.ReadyAt.IsZero() || !a.FencedAt.IsZero() || !a.CommitStartedAt.IsZero() || a.Timings != (session.Timings{}) {
		return session.Record{}, errors.New("ticket attempt already progressed or mismatched")
	}
	return r, nil
}
func sessionTicketPrivateDirectory(path string) (os.FileInfo, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || st.Uid != 0 || st.Gid != 0 {
		return nil, errors.New("fixed private ticket directory required")
	}
	return info, nil
}
func (o *operatorStoreObserver) armSessionTicket(key, existingID string) error {
	if e := requireNode(); e != nil {
		return e
	}
	kh, sh, e := sessionTicketHashes(key)
	if e != nil {
		return e
	}
	if !hex32Pattern(existingID) {
		return errors.New("known existing session required")
	}
	root, e := sessionTicketPrivateDirectory("/srv/state")
	if e != nil {
		return e
	}
	dir, e := sessionTicketPrivateDirectory("/srv/state/sessions")
	if e != nil {
		return e
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.armed || o.ticket != nil || o.mode != "" || o.snapshotValue.HeldID != 0 {
		return errors.New("one fixed observer selector only")
	}
	o.rootInfo, o.dirInfo = root, dir
	o.ticket = &sessionTicketBoundary{KeyHash: kh, SpecHash: sh, ExistingID: existingID}
	o.armed = true
	return nil
}
func (o *operatorStoreObserver) matchSessionTicket(q quotaNotif) (bool, error) {
	target, info, owned, e := o.descriptor(q)
	if e != nil || !owned {
		return false, e
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	t := o.ticket
	if t == nil || o.mode != "" || o.snapshotValue.FileEntries != 0 {
		return false, errors.New("ticket selector not initial")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Nlink != 1 || info.Size() <= 0 || info.Size() > sessionTicketMax {
		return false, errors.New("ticket temporary file identity/bound")
	}
	root, e := sessionTicketPrivateDirectory("/srv/state")
	if e != nil || !os.SameFile(root, o.rootInfo) {
		return false, errors.New("ticket root changed")
	}
	dir, e := sessionTicketPrivateDirectory("/srv/state/sessions")
	if e != nil || !os.SameFile(dir, o.dirInfo) {
		return false, errors.New("ticket journal directory changed")
	}
	data, e := privatefile.Read(target, sessionTicketMax)
	if e != nil {
		return false, e
	}
	// Other genuine session writes are not targets; never alter their result.
	var peek struct {
		Version int            `json:"version"`
		Record  session.Record `json:"record"`
	}
	if e = strictjson.Decode(data, &peek); e != nil {
		return false, e
	}
	if peek.Version != 1 {
		return false, errors.New("unexpected session envelope version")
	}
	if peek.Record.CreateKeyHash != t.KeyHash {
		return false, nil
	}
	r, e := sessionTicketInitial(data, t.KeyHash, t.SpecHash)
	if e != nil {
		return false, e
	}
	if r.ID == t.ExistingID {
		return false, errors.New("new ticket reused an existing session ID")
	}
	if _, e = os.Lstat("/srv/state/sessions/" + r.ID + ".json"); !os.IsNotExist(e) {
		return false, errors.New("pre-rename ticket final name exists")
	}
	o.tempPath, o.tempInfo = target, info
	t.ID, t.Payload = r.ID, append([]byte(nil), data...)
	o.snapshotValue.FileEntries++
	return true, nil
}
func (o *operatorStoreObserver) sessionTicketIdentity() (string, string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ticket == nil {
		return "", ""
	}
	return o.ticket.ID, filepath.Base(o.tempPath)
}
func (o *operatorStoreObserver) validateSessionTicketHeld(q quotaNotif) error {
	if e := o.heldValid(); e != nil {
		return e
	}
	path, info, owned, e := o.descriptor(q)
	if e != nil {
		return e
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !owned || o.ticket == nil || o.mode != "" || path != o.tempPath || o.tempInfo == nil || !os.SameFile(info, o.tempInfo) || o.snapshotValue.FileEntries != 1 || o.snapshotValue.TicketContinued != 0 {
		return errors.New("held initial ticket changed")
	}
	data, e := privatefile.Read(path, sessionTicketMax)
	if e != nil {
		return e
	}
	if !bytes.Equal(data, o.ticket.Payload) {
		return errors.New("held ticket payload changed")
	}
	if _, e = sessionTicketInitial(data, o.ticket.KeyHash, o.ticket.SpecHash); e != nil {
		return e
	}
	if _, e = os.Lstat("/srv/state/sessions/" + o.ticket.ID + ".json"); !os.IsNotExist(e) {
		return errors.New("held ticket renamed before Sync")
	}
	root, e := sessionTicketPrivateDirectory("/srv/state")
	if e != nil || !os.SameFile(root, o.rootInfo) {
		return errors.New("held ticket root changed")
	}
	dir, e := sessionTicketPrivateDirectory("/srv/state/sessions")
	if e != nil || !os.SameFile(dir, o.dirInfo) {
		return errors.New("held ticket directory changed")
	}
	return nil
}
