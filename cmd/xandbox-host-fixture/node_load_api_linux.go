//go:build linux && xandbox_host_fixture

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
)

// Only these two ordinary admission responses are workload refusals. Metadata,
// authentication, job-history, journal-fence and server errors FAIL the run.
func nodeLoadReply(status int, body []byte, want int, out any) (string, error) {
	if len(body) > 1<<20 {
		return "", errors.New("bounded load API reply required")
	}
	if status == want {
		if out != nil {
			if e := json.Unmarshal(body, out); e != nil {
				return "", e
			}
		}
		return "completed", nil
	}
	var failure struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if e := json.Unmarshal(body, &failure); e != nil {
		return "", errors.New("invalid closed load error projection")
	}
	if status == 429 && failure.Error.Code == "TENANT_QUOTA" {
		return "tenant_quota", nil
	}
	if status == 503 && failure.Error.Code == "UNAVAILABLE" {
		return "service_unavailable503", nil
	}
	return "", fmt.Errorf("unexpected fixed load API status %d", status)
}

func nodeLoadCall(ctx context.Context, c *switchAPI, method, path, key string, body, out any, want int) (string, error) {
	var data []byte
	var e error
	if body != nil {
		data, e = json.Marshal(body)
		if e != nil {
			return "", e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, "http://fixture.local"+path, bytes.NewReader(data))
	if e != nil {
		return "", e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	r, e := c.http.Do(req)
	if e != nil {
		return "", e
	}
	defer r.Body.Close()
	data, e = io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if e != nil {
		return "", e
	}
	return nodeLoadReply(r.StatusCode, data, want, out)
}

func nodeLoadDomainEmpty(ref sandbox.Ref) (bool, error) {
	if !switchRefValid(ref) {
		return false, errors.New("exact load execution ref required")
	}
	return nodeOOMEmpty(nodeBudgetInstances + "/" + ref.ID + ref.Generation)
}

func nodeLoadFreshCommand() []string {
	return []string{"sh", "-c", "set -e; test ! -e load-marker; test ! -e load-data; test ! -e /tmp/load-memory; test ! -e /tmp/load-seq; test ! -e /tmp/load-release; id -u; cat /proc/sys/kernel/random/boot_id"}
}

func nodeLoadWorkCommand() []string {
	return []string{"sh", "-c", "set -e; test ! -e load-marker; printf load > load-marker; dd if=/dev/zero of=/tmp/load-memory bs=1048576 count=16 2>/dev/null; dd if=/dev/zero of=load-data bs=1048576 count=1 2>/dev/null; test $(wc -c < /tmp/load-memory) -eq 16777216; test $(wc -c < load-data) -eq 1048576; sync; sha256sum load-data >/dev/null; id -u; cat /proc/sys/kernel/random/boot_id"}
}

func nodeLoadBusyCommand() []string {
	return []string{"sh", "-c", `set -e; rm -f /tmp/load-release /tmp/load-seq; i=0; while [ ! -e /tmp/load-release ]; do i=$((i+1)); printf '%s\n' "$i" > /tmp/load-seq.new; mv /tmp/load-seq.new /tmp/load-seq; sleep 0.05; done`}
}

func nodeLoadProgressCommand() []string {
	return []string{"sh", "-c", `set -e; i=0; while [ ! -s /tmp/load-seq ]; do i=$((i+1)); test $i -le 200; sleep 0.05; done; first=$(cat /tmp/load-seq); case $first in ''|*[!0-9]*) exit 1;; esac; i=0; while :; do next=$(cat /tmp/load-seq); case $next in ''|*[!0-9]*) exit 1;; esac; if [ "$next" -gt "$first" ]; then break; fi; i=$((i+1)); test $i -le 200; sleep 0.05; done`}
}

func nodeLoadBusy(ctx context.Context, c *switchAPI, ref sandbox.Ref, binding *session.Result) (sandbox.Job, time.Time, error) {
	deadline := time.Now().Add(60 * time.Second)
	var j sandbox.Job
	var e error
	if binding != nil {
		j, e = c.sessionJob(ctx, *binding, nodeLoadBusyCommand())
	} else {
		e = c.call(ctx, "POST", switchPath(ref)+"/exec", "", sandbox.ExecRequest{Generation: ref.Generation, Argv: nodeLoadBusyCommand(), TimeoutMS: 60000}, &j, 202)
		if e == nil && (!hex32Pattern(j.ID) || j.Generation != ref.Generation) {
			return j, deadline, errors.New("raw busy response generation mismatch")
		}
		j.Ref = ref
	}
	if e != nil {
		return j, deadline, e
	}
	if !hex32Pattern(j.ID) || j.Ref != ref || j.Generation != ref.Generation {
		return j, deadline, errors.New("load busy execution binding mismatch")
	}
	if binding != nil {
		_, e = c.sessionExec(ctx, *binding, nodeLoadProgressCommand())
	} else {
		_, e = c.executeVM(ctx, ref, nodeLoadProgressCommand())
	}
	if e != nil {
		return j, deadline, e
	}
	j, e = c.job(ctx, ref, j)
	if e != nil || j.Status != "RUNNING" || !time.Now().Before(deadline) {
		return j, deadline, errors.New("actual load busy progress before original timeout required")
	}
	return j, deadline, nil
}

func nodeLoadReleaseBusy(ctx context.Context, c *switchAPI, b session.Result, j sandbox.Job) error {
	if _, e := c.sessionExec(ctx, b, []string{"sh", "-c", "printf release > /tmp/load-release"}); e != nil {
		return e
	}
	_, e := c.finish(ctx, b.Current, j)
	return e
}

func nodeLoadRevoke(ctx context.Context, c *switchAPI, b session.Result) error {
	if !hex32Pattern(b.ID) || !switchRefValid(b.Current) || b.Revision == 0 {
		return errors.New("fixed load session binding required")
	}
	var out struct {
		Revoked   bool `json:"admission_revoked"`
		Durable   bool `json:"durable"`
		Stopped   bool `json:"stop_confirmed"`
		Reclaimed bool `json:"reclamation_confirmed"`
	}
	if e := c.call(ctx, "POST", "/v1/sessions/"+b.ID+"/revoke", "", map[string]uint64{"expected_revision": b.Revision}, &out, 200); e != nil {
		return e
	}
	if !out.Revoked || out.Durable || out.Stopped || out.Reclaimed {
		return errors.New("session revoke is not durable Stop/GC proof")
	}
	return budgetDestroyed(ctx, c, b.Current)
}
