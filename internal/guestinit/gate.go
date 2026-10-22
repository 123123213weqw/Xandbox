package guestinit

import (
	"net"
	"sync"
	"time"

	"github.com/123123213weqw/Xandbox/internal/guestwire"
)

// Gate has no execution capability. initialize is trusted guest bootstrap code;
// it is called once, after an irreversible in-memory claim, outside the mutex.
// It must also install a guest-local permanent marker before privileged work so
// process respawn cannot reopen initialization. Successful exec never returns.
type Gate struct {
	mu            sync.Mutex
	phase, digest string
	initialize    func(Request) error
}

func New(initialize func(Request) error) *Gate { return &Gate{phase: Waiting, initialize: initialize} }

func (g *Gate) ServeConn(conn net.Conn, peerIsHost bool) {
	defer conn.Close()
	if !peerIsHost || g.initialize == nil {
		return
	}
	if conn.SetDeadline(time.Now().Add(5*time.Second)) != nil {
		return
	}
	var req Request
	if guestwire.Read(conn, MaxRequest, &req) != nil || !req.Valid() {
		req.WipeEntropy()
		return
	}
	defer req.WipeEntropy()
	apply := false
	g.mu.Lock()
	if req.Operation == "initialize" && g.phase == Waiting {
		g.phase, g.digest = Claimed, req.Digest()
		apply = true
	}
	response := Response{Version: Version, Phase: g.phase, Digest: g.digest}
	if g.phase == Failed {
		response.Error = "initialization failed"
	}
	g.mu.Unlock()
	// CLAIMED is NOT READY. Even a lost acknowledgement never rolls back a
	// consumed request. Host must verify the normal agent's exact epoch hash.
	_ = guestwire.Write(conn, MaxResponse, response)
	conn.Close()
	if apply {
		_ = g.initialize(req)
		// Returning, even nil, is a failed sealed handoff. Never reopen the gate.
		g.mu.Lock()
		g.phase = Failed
		g.mu.Unlock()
	}
}
