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
	return "", fmt.Errorf("unexpected fixed load API status %d code=%s", status, nodeLoadClosedAPICode(failure.Error.Code))
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
	nodeLoadCaptureServer(ctx, r)
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

// Reset is an ordinary synchronous guest exec BEFORE the async heartbeat job.
// Never delete a sequence file after a concurrent progress reader has started.
func nodeLoadPrepareHeartbeatCommand() []string {
	return []string{"sh", "-c", `set -e; rm -f /tmp/load-release /tmp/load-seq /tmp/load-seq.new; test ! -e /tmp/load-release; test ! -e /tmp/load-seq; test ! -e /tmp/load-seq.new`}
}

func nodeLoadBusyCommand() []string {
	return []string{"sh", "-c", `set -e; i=0; while [ ! -e /tmp/load-release ]; do i=$((i+1)); printf '%s\n' "$i" > /tmp/load-seq.new; mv /tmp/load-seq.new /tmp/load-seq; sleep 0.05; done`}
}

func nodeLoadProgressCommand() []string {
	return []string{"sh", "-c", `set -e; i=0; while [ ! -s /tmp/load-seq ]; do i=$((i+1)); test $i -le 200; sleep 0.05; done; first=$(cat /tmp/load-seq) || exit 42; case $first in ''|*[!0-9]*) exit 1;; esac; i=0; while :; do next=$(cat /tmp/load-seq) || exit 44; case $next in ''|*[!0-9]*) exit 1;; esac; if [ "$next" -gt "$first" ]; then break; fi; i=$((i+1)); test $i -le 200; sleep 0.05; done`}
}

func nodeLoadBusy(ctx context.Context, c *switchAPI, ref sandbox.Ref, binding *session.Result) (sandbox.Job, time.Time, error) {
	if _, e := nodeLoadTraced(ctx, loadActorBusyPrepare, func() (sandbox.Output, error) {
		return nodeLoadHeartbeatExec(ctx, c, ref, binding, nodeLoadPrepareHeartbeatCommand(), "prepare")
	}); e != nil {
		return sandbox.Job{}, time.Time{}, e
	}
	deadline := time.Now().Add(60 * time.Second)
	var j sandbox.Job
	var e error
	if binding != nil {
		j, e = nodeLoadTraced(ctx, loadActorBusyStart, func() (sandbox.Job, error) { return c.sessionJob(ctx, *binding, nodeLoadBusyCommand()) })
	} else {
		e = nodeLoadTraceError(ctx, loadActorBusyStart, func() error {
			return c.call(ctx, "POST", switchPath(ref)+"/exec", "", sandbox.ExecRequest{Generation: ref.Generation, Argv: nodeLoadBusyCommand(), TimeoutMS: 60000}, &j, 202)
		})
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
	if _, e = nodeLoadTraced(ctx, loadActorBusyProgress, func() (sandbox.Output, error) {
		return nodeLoadHeartbeatExec(ctx, c, ref, binding, nodeLoadProgressCommand(), "progress")
	}); e != nil {
		return j, deadline, e
	}
	j, e = nodeLoadTraced(ctx, loadActorBusyVerify, func() (sandbox.Job, error) { return c.job(ctx, ref, j) })
	if e != nil || j.Status != "RUNNING" || !time.Now().Before(deadline) {
		return j, deadline, errors.New("actual load busy progress before original timeout required")
	}
	return j, deadline, nil
}

// Preserve closed numeric failure evidence instead of discarding the actual
// guest exit status behind the generic switch helper error. Never log output.
func nodeLoadHeartbeatExec(ctx context.Context, c *switchAPI, ref sandbox.Ref, binding *session.Result, argv []string, stage string) (sandbox.Output, error) {
	var out sandbox.Output
	var e error
	if binding != nil {
		out, e = c.sessionExec(ctx, *binding, argv)
	} else {
		out, e = c.executeVM(ctx, ref, argv)
	}
	if e != nil {
		return out, fmt.Errorf("load heartbeat %s exit=%d truncated=%t stdout_bytes=%d stderr_bytes=%d: %w", stage, out.ExitCode, out.Truncated, len(out.Stdout), len(out.Stderr), e)
	}
	if out.Truncated {
		return out, errors.New("heartbeat observation output was truncated")
	}
	return out, nil
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

func nodeLoadClosedAPICode(code string) string {
	switch code {
	case "INTERNAL", "INVALID_JSON", "INVALID_REQUEST", "UNAUTHORIZED", "NOT_FOUND", "STALE_SESSION", "SESSION_BUSY", "SESSION_GONE", "SESSION_HISTORY_LIMIT", "TENANT_SESSION_QUOTA", "SESSION_CAPACITY", "SESSION_UNAVAILABLE", "STALE_GENERATION", "NOT_READY", "IDEMPOTENCY_CONFLICT", "IDEMPOTENCY_GONE", "JOB_LIMIT", "TENANT_QUOTA", "METADATA_CAPACITY", "TENANT_METADATA_QUOTA", "NODE_DRAINING", "UNAVAILABLE":
		return code
	}
	return "UNCLASSIFIED"
}
