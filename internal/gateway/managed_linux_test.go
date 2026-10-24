//go:build linux

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/policycontrol"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

// Only the observation receiver/ACK producer is modeled. policyState persistence,
// sealed descriptors and inherited socketpair frames below are real Linux I/O.
// This is not a RunRoot/root fixed-path/real TLS child or installed CLI proof.
type managedObservationTest struct {
	value       policycontrol.PolicyStatus
	transitions []string
}

func (m *managedObservationTest) Status() policycontrol.PolicyStatus { return m.value }
func (m *managedObservationTest) Publish(s policycontrol.PolicyStatus) error {
	if !s.Valid() {
		return errors.New("invalid TEST observation")
	}
	m.value = s
	m.transitions = append(m.transitions, s.Phase)
	return nil
}

func managedTestConfig(t *testing.T) (Config, PolicyEnvelope, []byte) {
	t.Helper()
	s, _ := testSnapshot(t)
	p := PolicyEnvelope{Version: 1, Revision: 1, Snapshot: s}
	raw, e := EncodePolicyEnvelope(p)
	if e != nil {
		t.Fatal(e)
	}
	c := Config{Version: 2, PolicyRevision: 1, StateDir: "/srv/xi/p", UID: s.UID, GID: s.GID, Listen: s.Listen, ServerName: s.ServerName, EmptyRoot: "/srv/xi/g/root", TenantSocket: "/srv/xi/s/api.sock", BackendAuthFile: "/run/xandbox-inputs/auth.json", ManagedPolicyFile: ManagedPolicyPath, InitialPolicySHA256: policyBytesDigest(raw)}
	return c, p, raw
}
func rotatedEnvelope(t *testing.T, c Config, p PolicyEnvelope) PolicyEnvelope {
	t.Helper()
	p.Revision = 2
	p.ExpectedRevision = 1
	p.RequestID = strings.Repeat("a", 32)
	p.BaseCommitSHA256 = strings.Repeat("b", 64)
	p.ConfigSHA256, _ = ManagedConfigDigest(c)
	p.InitialPolicySHA256 = c.InitialPolicySHA256
	p.Source = PolicySource{Path: "/bootstrap/new-policy.json", SHA256: strings.Repeat("c", 64)}
	p.Snapshot.Epoch = 2
	return p
}

func TestManagedEnvelopeSingleAuthorityAndImmutableBinding(t *testing.T) {
	c, initial, raw := managedTestConfig(t)
	if _, e := DecodeManagedEnvelope(c, raw, ""); e != nil {
		t.Fatal(e)
	}
	p := rotatedEnvelope(t, c, initial)
	next, _ := EncodePolicyEnvelope(p)
	if _, e := DecodeManagedEnvelope(c, next, p.BaseCommitSHA256); e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(*PolicyEnvelope){
		"version": func(p *PolicyEnvelope) { p.Version = 2 }, "revision": func(p *PolicyEnvelope) { p.Revision = 3 }, "base": func(p *PolicyEnvelope) { p.BaseCommitSHA256 = strings.Repeat("d", 64) }, "config": func(p *PolicyEnvelope) { p.ConfigSHA256 = strings.Repeat("d", 64) }, "initial": func(p *PolicyEnvelope) { p.InitialPolicySHA256 = strings.Repeat("d", 64) }, "request": func(p *PolicyEnvelope) { p.RequestID = "" }, "uid": func(p *PolicyEnvelope) { p.Snapshot.UID++ }, "gid": func(p *PolicyEnvelope) { p.Snapshot.GID++ }, "listen": func(p *PolicyEnvelope) { p.Snapshot.Listen = "127.0.0.1:9444" }, "sni": func(p *PolicyEnvelope) { p.Snapshot.ServerName = "other.test" }, "source": func(p *PolicyEnvelope) { p.Source.Path = ManagedPolicyPath }, "time": func(p *PolicyEnvelope) {
			p.Snapshot.Keys = append([]ClientKey(nil), p.Snapshot.Keys...)
			p.Snapshot.Keys[0].ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := p
			mutate(&bad)
			b, e := EncodePolicyEnvelope(bad)
			if e == nil {
				if _, e = DecodeManagedEnvelope(c, b, p.BaseCommitSHA256); e == nil {
					t.Fatal("invalid envelope accepted")
				}
			}
		})
	}
	for _, b := range [][]byte{append(next, []byte("{}")...), bytes.TrimSpace(next), append([]byte(" "), next...), append(bytes.TrimSuffix(next, []byte("}\n")), []byte(`,"extra":1}`)...)} {
		if _, e := DecodeManagedEnvelope(c, b, p.BaseCommitSHA256); e == nil {
			t.Fatal("noncanonical/unknown payload accepted")
		}
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.CertificateFile = "/legacy" }, func(c *Config) { c.PrivateKeyFile = "/legacy" }, func(c *Config) { c.Keys = []ClientKey{} }, func(c *Config) { c.PolicyRevision = 2 }, func(c *Config) { c.ManagedPolicyFile = "/elsewhere" }, func(c *Config) { c.InitialPolicySHA256 = "" }} {
		bad := c
		mutate(&bad)
		if bad.ValidateShape() == nil {
			t.Fatal("mixed configuration accepted")
		}
	}
	legacy := c
	legacy.Version = 1
	if legacy.ValidateShape() == nil {
		t.Fatal("legacy adopted managed fields")
	}
	legacy.ManagedPolicyFile = ""
	legacy.InitialPolicySHA256 = ""
	if legacy.ValidateShape() != nil {
		t.Fatal("legacy shape changed")
	}
	old := digestJSON(struct {
		UID, GID                                                                                uint32
		Listen, ServerName, EmptyRoot, TenantSocket, BackendAuthFile, StateDir, AuthoritySHA256 string
	}{legacy.UID, legacy.GID, legacy.Listen, legacy.ServerName, legacy.EmptyRoot, legacy.TenantSocket, legacy.BackendAuthFile, legacy.StateDir, digestJSON(json.RawMessage(`{"version":1}`))})
	if gatewayBinding(legacy, []byte(`{"version":1}`)) != old || gatewayBinding(c, []byte(`{"version":1}`)) == old {
		t.Fatal("legacy binding reinterpreted")
	}
	changed := c
	changed.InitialPolicySHA256 = strings.Repeat("f", 64)
	if c.sameBinding(changed) || gatewayBinding(c, []byte(`{"version":1}`)) == gatewayBinding(changed, []byte(`{"version":1}`)) {
		t.Fatal("initial authority retargeted")
	}
}

func TestManagedIntentFencesOldPolicyBeforeAtomicAuthorityAndAcceptsExactVisibleNew(t *testing.T) {
	c, p, old := managedTestConfig(t)
	p = rotatedEnvelope(t, c, p)
	raw, _ := EncodePolicyEnvelope(p)
	i := PolicyIntent{Version: 1, ExpectedRevision: 1, RequestID: p.RequestID, BaseCommitSHA256: p.BaseCommitSHA256, ConfigSHA256: p.ConfigSHA256, InitialPolicySHA256: p.InitialPolicySHA256, OldPayloadSHA256: policyBytesDigest(old), NewPayloadSHA256: policyBytesDigest(raw), Source: p.Source}
	b, _ := json.Marshal(i)
	b = append(b, '\n')
	if _, e := DecodePolicyIntent(c, p.BaseCommitSHA256, b); e != nil {
		t.Fatal(e)
	}
	if _, e := ValidateVisiblePolicyIntent(c, p.BaseCommitSHA256, old, b); e == nil {
		t.Fatal("pending restart could revive old payload")
	}
	if _, e := ValidateVisiblePolicyIntent(c, p.BaseCommitSHA256, raw, b); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*PolicyIntent){func(i *PolicyIntent) { i.ExpectedRevision = 0 }, func(i *PolicyIntent) { i.ExpectedRevision = ^uint64(0) }, func(i *PolicyIntent) { i.NewPayloadSHA256 = i.OldPayloadSHA256 }, func(i *PolicyIntent) { i.RequestID = strings.Repeat("f", 32) }, func(i *PolicyIntent) { i.Source.SHA256 = strings.Repeat("e", 64) }, func(i *PolicyIntent) { i.NewPayloadSHA256 = strings.Repeat("d", 64) }} {
		bad := i
		mutate(&bad)
		b, _ := json.Marshal(bad)
		if _, e := ValidateVisiblePolicyIntent(c, p.BaseCommitSHA256, raw, append(b, '\n')); e == nil {
			t.Fatal("unmatched intent accepted")
		}
	}
}

func TestManagedRealPolicyStoreSealedTransferExactRetryAndSeparateACK(t *testing.T) {
	s, _ := testSnapshot(t)
	state, e := openPolicyState(t.TempDir(), strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	if state.Commit(s) != nil {
		t.Fatal("initial commit")
	}
	d1, _ := SnapshotDigest(s)
	view := &managedObservationTest{value: policycontrol.PolicyStatus{Version: 1, DurableEpoch: 1, SnapshotSHA256: d1, ActiveEpoch: 1, ActiveSHA256: d1, Phase: "active"}}
	p, c, e := packetPair()
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	defer c.Close()
	next := s
	next.Epoch = 2
	next.Keys = append([]ClientKey(nil), s.Keys...)
	next.Keys[0].TokenSHA256 = tokenHash(strings.Repeat("d", 40))
	d2, _ := SnapshotDigest(next)
	command := policycontrol.PolicyCommand{Version: 1, Operation: "activate", ExpectedEpoch: 1, TargetEpoch: 2, SnapshotSHA256: d2}
	if commitManaged(state, p, next, command, view) != nil {
		t.Fatal("actual store/transfer failed")
	}
	if state.record.Revision != 2 || view.value.Phase != "waiting" || view.value.ActiveEpoch != 1 || strings.Join(view.transitions, ",") != "committing,waiting" {
		t.Fatal("durable commit falsely became active")
	}
	f, fd, e := readFrame(c)
	if e != nil || fd < 0 || f.op != opPolicy || f.request != 2 {
		t.Fatal("real policy capability transfer")
	}
	file := os.NewFile(uintptr(fd), "test-transferred-policy")
	defer file.Close()
	seals, e := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if e != nil || seals != snapshotSeals {
		t.Fatal("unsealed transfer")
	}
	info, _ := file.Stat()
	raw := make([]byte, info.Size())
	if _, e = file.ReadAt(raw, 0); e != nil {
		t.Fatal(e)
	}
	var transferred Snapshot
	if strictjson.Decode(raw, &transferred) != nil {
		t.Fatal("transferred snapshot syntax")
	}
	if got, _ := SnapshotDigest(transferred); got != d2 {
		t.Fatal("transferred different snapshot")
	}
	foreign := filepath.Join(state.dir, "unknown")
	if os.WriteFile(foreign, []byte("do not collect"), 0600) != nil {
		t.Fatal("foreign fixture")
	}
	if commitManaged(state, p, Snapshot{}, command, view) != nil || len(view.transitions) != 2 {
		t.Fatal("exact retry recommitted")
	}
	if _, e = os.Stat(foreign); e != nil {
		t.Fatal("retry changed state inventory")
	}
	os.Remove(foreign)
	if acknowledgeManaged(view, 1) == nil || view.value.ActiveEpoch != 1 {
		t.Fatal("wrong ACK accepted")
	}
	if writeFrame(c, frame{op: opReady, request: 2}, -1) != nil {
		t.Fatal("TEST ACK send")
	}
	ack, fd, e := readFrame(p)
	if e != nil || fd != -1 || ack.op != opReady || acknowledgeManaged(view, ack.request) != nil {
		t.Fatal("TEST ACK observation")
	}
	if view.value.Phase != "active" || view.value.ActiveSHA256 != d2 || acknowledgeManaged(view, 2) == nil {
		t.Fatal("duplicate ACK accepted")
	}
	if commitManaged(state, p, Snapshot{}, command, view) != nil {
		t.Fatal("active exact retry")
	}
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, fd, e := readFrame(c); e == nil || fd != -1 {
		t.Fatal("retry transferred again")
	}
	state.Close()
	cold, e := openPolicyState(state.dir, state.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer cold.Close()
	if cold.Commit(next) != nil || cold.Commit(s) == nil {
		t.Fatal("cold durable CAS/rollback failed")
	}
}

func TestManagedPostCommitTransferFailureFencesDurableNewEpoch(t *testing.T) {
	s, _ := testSnapshot(t)
	state, e := openPolicyState(t.TempDir(), strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	state.Commit(s)
	d1, _ := SnapshotDigest(s)
	view := &managedObservationTest{value: policycontrol.PolicyStatus{Version: 1, DurableEpoch: 1, SnapshotSHA256: d1, ActiveEpoch: 1, ActiveSHA256: d1, Phase: "active"}}
	p, c, e := packetPair()
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	c.Close()
	s.Epoch = 2
	d2, _ := SnapshotDigest(s)
	if commitManaged(state, p, s, policycontrol.PolicyCommand{Version: 1, Operation: "activate", ExpectedEpoch: 1, TargetEpoch: 2, SnapshotSHA256: d2}, view) == nil {
		t.Fatal("transfer failure hidden")
	}
	if state.record.Revision != 2 || view.value.Phase != "fenced" || view.value.DurableEpoch != 2 || view.value.ActiveEpoch != 1 {
		t.Fatal("postcommit fence lost confirmed facts")
	}
}

func TestSnapshotMarshalFailureNeverCollectsOrCommits(t *testing.T) {
	s, _ := testSnapshot(t)
	state, e := openPolicyState(t.TempDir(), strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	if state.Commit(s) != nil {
		t.Fatal("initial commit")
	}
	before := state.record
	orphan := filepath.Join(state.dir, ".policy-123")
	if os.WriteFile(orphan, []byte("uncollected"), 0600) != nil {
		t.Fatal("fixture")
	}
	s.Epoch = 2
	s.Keys[0].ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, e := SnapshotDigest(s); e == nil || state.Commit(s) == nil {
		t.Fatal("marshal failure ignored")
	}
	if state.record != before {
		t.Fatal("marshal failure committed")
	}
	if _, e = os.Stat(orphan); e != nil {
		t.Fatal("marshal failure mutated inventory")
	}
}
