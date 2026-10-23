//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"strings"
	"testing"
)

func tlsSavedForTest() tlsGatewaySaved {
	old := storeTestReceipt(operatorStorePre)
	return tlsGatewaySaved{Version: 1, L1Boot: old.L1Boot, Config: strings.Repeat("a", 64), Auth: strings.Repeat("b", 64), Policy: strings.Repeat("c", 64), CA: strings.Repeat("d", 64), IngressConfig: strings.Repeat("e", 64), Before: old.Before, Raw: old.Raw, OldSession: old.Session.Current, Binding: session.Result{ID: old.Session.ID, Revision: 2, Previous: old.Session.Current, Current: sandbox.Ref{ID: strings.Repeat("b", 32), Generation: strings.Repeat("c", 32)}}, RawKey: strings.Repeat("1", 64), SessionKey: strings.Repeat("2", 64), SwitchKey: strings.Repeat("3", 64), AlphaOld: strings.Repeat("4", 64), AlphaNew: strings.Repeat("5", 64), BetaExternal: strings.Repeat("6", 64), Boots: [3]string{old.RawBoot, old.SessionBoot, "44444444-4444-4444-8444-444444444444"}}
}
func TestTLSGatewayFixtureNoL0OrArbitraryProtocol(t *testing.T) {
	ctx := context.Background()
	n := &node{nodeBudget: true, quotaDriver: true}
	if _, e := n.nodeTLSGatewayCheckpoint(ctx); e == nil {
		t.Fatal("L0 checkpoint")
	}
	if _, e := n.nodeTLSGatewayRecover(ctx); e == nil {
		t.Fatal("L0 recovery")
	}
	if gatewayLoopback() == nil || gatewayNegativeTLS(ctx, nil) == nil || gatewaySecret("server1.key", []byte("TEST")) == nil || gatewayRoles(&gatewayProcess{}) == nil || gatewayAbsentListener() == nil {
		t.Fatal("helper escaped ownedL1")
	}
	if _, e := gatewayChild(1); e == nil {
		t.Fatal("L0 process inspection")
	}
	if _, e := gatewayConfigRead(); e == nil {
		t.Fatal("L0 private config")
	}
	if _, e := startGateway(ctx, 1); e == nil {
		t.Fatal("L0 root program")
	}
	if _, _, e := gatewayPrepare("", "", "", ""); e == nil {
		t.Fatal("L0 provisioning")
	}
	if _, _, e := gatewayAPI(nil, ""); e == nil {
		t.Fatal("L0 TLS client")
	}
	for _, op := range []string{"node-tls-gateway-checkpoint", "node-tls-gateway-recover"} {
		q := nodeRequest{Version: 1, Operation: op}
		if q.validate() != nil {
			t.Fatal("fixed protocol")
		}
		q.Phase = "custom"
		if q.validate() == nil {
			t.Fatal("arbitrary phase")
		}
		q.Phase = ""
		q.Receipt = []byte(`{}`)
		if q.validate() == nil {
			t.Fatal("arbitrary certificate/path/receipt")
		}
	}
}
func TestTLSGatewayColdReceiptRejectsConfigDriftKeyRollbackOrGuestAliasing(t *testing.T) {
	s := tlsSavedForTest()
	const boot = "55555555-5555-4555-8555-555555555555"
	if e := validateTLSGatewaySaved(s, boot); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*tlsGatewaySaved){func(s *tlsGatewaySaved) { s.Version++ }, func(s *tlsGatewaySaved) { s.L1Boot = boot }, func(s *tlsGatewaySaved) { s.Policy = "bad" }, func(s *tlsGatewaySaved) { s.IngressConfig = "bad" }, func(s *tlsGatewaySaved) { s.Before.Mode = nodecontrol.ModeDrained }, func(s *tlsGatewaySaved) { s.Before.Revision++ }, func(s *tlsGatewaySaved) { s.Binding.Revision = 1 }, func(s *tlsGatewaySaved) { s.Binding.Previous = s.Raw }, func(s *tlsGatewaySaved) { s.Binding.Current = s.OldSession }, func(s *tlsGatewaySaved) { s.Raw = s.OldSession }, func(s *tlsGatewaySaved) { s.AlphaNew = s.AlphaOld }, func(s *tlsGatewaySaved) { s.SwitchKey = s.RawKey }, func(s *tlsGatewaySaved) { s.Boots[2] = s.Boots[1] }} {
		bad := s
		mutate(&bad)
		if validateTLSGatewaySaved(bad, boot) == nil {
			t.Fatal("forged cold receipt accepted")
		}
	}
}
