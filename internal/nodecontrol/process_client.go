package nodecontrol

import (
	"context"
	"errors"
	"os"
	"regexp"
)

var ErrProcessPin = errors.New("live Linux operator process pin required")
var bootID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ProcessIdentity is an incarnation identifier, NOT proof of an executable,
// systemd ownership, placement, compatibility, stop or resource reclamation.
type ProcessIdentity struct {
	PID        int    `json:"pid"`
	BootID     string `json:"boot_id"`
	StartTicks uint64 `json:"start_ticks"`
}

func (p ProcessIdentity) Valid() bool {
	return p.PID > 1 && bootID.MatchString(p.BootID) && p.StartTicks > 0
}

// PinnedClient permits only status and drain, never resume. The expected PID
// comes from an independently verified manager incarnation, not a tenant token.
// Its private kernel lease must remain live before dial and after response read.
// A lost reply never undoes a mutation; retain/retry its original CAS command.
type PinnedClient struct {
	client  *Client
	id      ProcessIdentity
	release func()
}

func (c *PinnedClient) Identity() ProcessIdentity {
	if c == nil {
		return ProcessIdentity{}
	}
	return c.id
}

// VerifyDirectory binds the already validated private socket root to the
// caller's independently anchored directory FD; it never selects another path.
func (c *PinnedClient) VerifyDirectory(dir *os.File) error {
	if c == nil || c.client == nil || dir == nil {
		return ErrProcessPin
	}
	st, e := dir.Stat()
	if e != nil {
		return e
	}
	if !st.IsDir() || !os.SameFile(st, c.client.root) {
		return ErrProcessPin
	}
	return c.client.live()
}
func (c *PinnedClient) Close() {
	if c != nil && c.client != nil {
		c.release()
		c.client.Close()
	}
}
func (c *PinnedClient) Status(ctx context.Context) (Reply, error) {
	if c == nil || c.client == nil {
		return Reply{}, ErrProcessPin
	}
	r, e := c.client.Status(ctx)
	if e != nil {
		return Reply{}, e
	}
	return r, nil
}
func (c *PinnedClient) Drain(ctx context.Context, command Command) (Reply, error) {
	if c == nil || c.client == nil || !command.Valid() || command.ExpectedRevision == ^uint64(0) {
		return Reply{}, ErrProcessPin
	}
	r, e := c.client.Change(ctx, ModeDrained, command)
	if e != nil {
		return Reply{}, e
	}
	want := State{Version: 1, Epoch: command.Epoch, Revision: command.ExpectedRevision + 1, Mode: ModeDrained, LastRequestID: command.RequestID, LastExpectedRevision: command.ExpectedRevision}
	if r.Control.Phase != "ready" || r.Control.Committed != want || r.Control.DesiredMode != ModeDrained || r.Control.AdmissionOpen || r.Control.PendingRequestID != "" {
		return Reply{}, ErrProcessPin
	}
	// Pending reservations and resource stats are NOT quiescence certificates.
	return r, nil
}
