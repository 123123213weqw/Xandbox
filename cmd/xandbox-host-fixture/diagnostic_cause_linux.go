//go:build linux && xandbox_host_fixture

package main

// TEST ONLY operator observations: exact private sockets for fixed owned cases.
// Reads process-local primitive counters, never the failed state filesystem.
import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type prepareClasses struct{ IO, Quota, Other uint64 }

// Fixed launchers must reject by ordinary exit1 and one exact closed line,
// never an arbitrary crash/signal, diagnostic substring or inherited output.
func exactStartupRefusal(err error, output []byte, message string) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == 1 && string(output) == "sandboxd: "+message+"\n"
}

func causeSocketAllowed(socket string) bool {
	switch socket {
	case "/srv/state/metrics.sock", "/srv/nq/block/s/metrics.sock", "/srv/nq/inode/s/metrics.sock", "/srv/sq/reserve-barrier-hang/s/metrics.sock":
		return true
	}
	return false
}
func parsePrepareClasses(text string) (prepareClasses, error) {
	var out prepareClasses
	names := map[string]*uint64{`xandbox_prepare_failed_total{reason="io"}`: &out.IO, `xandbox_prepare_failed_total{reason="quota"}`: &out.Quota, `xandbox_prepare_failed_total{reason="other"}`: &out.Other}
	seen := map[string]bool{}
	if len(text) > 65536 {
		return out, errors.New("bounded private cause metrics required")
	}
	for _, line := range strings.Split(text, "\n") {
		p := strings.Fields(line)
		if len(p) == 0 || !strings.HasPrefix(p[0], "xandbox_prepare_failed_total") {
			continue
		}
		if len(p) != 2 {
			return out, errors.New("invalid cause metric row")
		}
		ptr, ok := names[p[0]]
		if !ok || seen[p[0]] {
			return out, errors.New("unknown/duplicate cause metric")
		}
		seen[p[0]] = true
		n, e := strconv.ParseUint(p[1], 10, 64)
		if e != nil {
			return out, e
		}
		*ptr = n
	}
	if len(seen) != 3 {
		return out, errors.New("missing closed cause metrics")
	}
	return out, nil
}
func fixedPrepareClasses(ctx context.Context, socket string) (prepareClasses, error) {
	if e := requireNode(); e != nil {
		return prepareClasses{}, e
	}
	if !causeSocketAllowed(socket) {
		return prepareClasses{}, errors.New("fixed private cause socket required")
	}
	c := newSwitchAPI(socket, "")
	defer c.close()
	req, e := http.NewRequestWithContext(ctx, "GET", "http://fixture.local/metrics", nil)
	if e != nil {
		return prepareClasses{}, e
	}
	r, e := c.http.Do(req)
	if e != nil {
		return prepareClasses{}, e
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, 65537))
	if e != nil || r.StatusCode != 200 {
		return prepareClasses{}, errors.New("private cause metrics unavailable")
	}
	return parsePrepareClasses(string(b))
}

// Preconnect before a whole-filesystem fault, keep the SAME authenticated UDS
// connection active below the server's two-second idle timeout, and prohibit
// reconnect/path lookup. Only socket I/O and primitive counter reads follow.
type prepareSampler struct {
	mu     sync.Mutex
	latest prepareClasses
	err    error
	api    *switchAPI
	conn   net.Conn
	cancel context.CancelFunc
	done   chan struct{}
}

func startPrepareSampler(ctx context.Context, socket string) (*prepareSampler, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !causeSocketAllowed(socket) {
		return nil, errors.New("fixed preconnected cause socket required")
	}
	conn, e := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if e != nil {
		return nil, e
	}
	return samplePreopenedPrepareConnection(ctx, conn)
}

// Consumes an already opened connection; this helper cannot open/reopen a path.
// Only startPrepareSampler may acquire a fixture socket, after the L1 guard.
func samplePreopenedPrepareConnection(ctx context.Context, conn net.Conn) (*prepareSampler, error) {
	var dialed atomic.Bool
	tr := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		if !dialed.CompareAndSwap(false, true) {
			return nil, errors.New("cause sampler reconnect forbidden")
		}
		return conn, nil
	}, MaxConnsPerHost: 1}
	c := &switchAPI{http: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	life, cancel := context.WithCancel(ctx)
	s := &prepareSampler{api: c, conn: conn, cancel: cancel, done: make(chan struct{})}
	call, end := context.WithTimeout(life, time.Second)
	initial, e := readPrepareClasses(call, c)
	end()
	if e != nil {
		cancel()
		c.close()
		conn.Close()
		return nil, e
	}
	s.latest = initial
	go func() {
		defer close(s.done)
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-life.Done():
				return
			case <-tick.C:
				call, end := context.WithTimeout(life, time.Second)
				v, e := readPrepareClasses(call, c)
				end()
				s.mu.Lock()
				s.latest, s.err = v, e
				s.mu.Unlock()
				if e != nil {
					return
				}
			}
		}
	}()
	return s, nil
}
func (s *prepareSampler) snapshot() (prepareClasses, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.latest, s.err
}
func (s *prepareSampler) close() {
	if s == nil {
		return
	}
	s.cancel()
	s.conn.Close()
	<-s.done
	s.api.close()
}
func readPrepareClasses(ctx context.Context, c *switchAPI) (prepareClasses, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", "http://fixture.local/metrics", nil)
	if e != nil {
		return prepareClasses{}, e
	}
	r, e := c.http.Do(req)
	if e != nil {
		return prepareClasses{}, e
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, 65537))
	if e != nil || r.StatusCode != 200 {
		return prepareClasses{}, errors.New("private cause metrics unavailable")
	}
	return parsePrepareClasses(string(b))
}
