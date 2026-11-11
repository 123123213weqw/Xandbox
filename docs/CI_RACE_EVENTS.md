# Streaming whole-race test evidence (diagnostic only)

The ordinary CI race step now runs:

```sh
umask 077
go test -race -timeout=20m -count=3 -json ./...
```

Only the native `-json` output flag is added. The entire package set, test
selection/order, repetitions, race instrumentation, Go 20-minute package timeout,
25-minute job limit, compatibility matrix and every preceding/following gate
remain unchanged. There is no new test run, manual experiment, retry, budget
extension, split, case drop, race suppression, pipeline or status override.
This is **not** a runtime/performance fix, native-host acceptance or production
qualification. It does not change the application's source or any test body.

## Why native JSON, not an observer wrapper

The Go project's [test2json documentation](https://pkg.go.dev/cmd/test2json)
describes live, unbuffered test events and recommends `go test -json` for multiple
packages. Events identify package, test and action, and separate interleaved
package streams. An observed `run` with no terminal event can therefore locate
an unfinished test prefix when a job stops. It does **not** by itself identify a
CPU/IO/deadlock cause, prove that test was executing at cancellation, or measure
which operation is responsible. Compiler/helper/background time is not a
per-test CPU profile. Event output can perturb timing; do not use this change
as a speed comparison or reclassify an earlier failure from a later green run.

Go also emits build events and can emit non-JSON early errors on stderr; see
[the native command specification](https://pkg.go.dev/cmd/go#hdr-Build__json_encoding).
`Output` carries test stdout/stderr, including race warnings and failures. CI
writes the native stream directly to the job log: no parser/filter hides output,
no `tee`/shell pipeline loses the original Go status, and no wrapper can return
success after a Go failure. The consumed optional CPU-diagnostic job is unchanged
and must not be redispatched as part of this change.

## Preserve raw evidence and distinguish scopes

Retain the original workflow archive, exact job and step logs, source SHA, attempt,
job/step outcomes and hashes. A valid complete prefix at job cancellation is
**incomplete evidence**, not success. Missing package/test terminal events,
malformed/truncated records, unknown schemas, build failures or stderr errors
must never be projected into a passing run. Even an apparently complete JSON
stream cannot override a failed/cancelled Go step or job, or prove every selected
package was observed without source/command/outcome binding.

The new whole-race stream contains verbose test output inside JSON `Output`
fields. Do not count those strings together with the independent CGO-free gates:
that would double-count their `--- PASS` / `--- SKIP` lines. For a dedicated-gate
case proof, use the actual step bytes, or a bounded derived view excluding only
validated native JSON event lines in the identified whole-race step. Keep the
original raw bytes and hash them, not the derived view. Verify the whole-race
step's actual exit, event sequence and package/test scope separately. Never
remove JSON events from the stored log, silence race/errors, loosen an old
assertion or infer missing cases from source text or another matrix job.

For public summaries, use source-bound package/top-level test names and bounded
counts/times, not arbitrary `Output`, dynamic subtest labels, exception strings,
private paths, credentials or record payloads. Preserve full originals privately
for exact diagnosis. No current or prior KVM, reclaim, rollback or long-load
qualification is inferred from this observability change.

## Retained predecessor failure

The original `61383ec` PR/push CI ended cancelled: ten normal jobs passed, two
Linux Go 1.27 jobs hit the 25-minute job limit during whole-package race tests,
and two optional diagnostic jobs skipped. Four matrix jobs completed; the
cancelled jobs' later steps did not run. Quiet logs did not expose the unfinished
test within `internal/installtxn`; absence of a completed package line was not
an active-case or root-cause diagnosis. Those original logs, authoritative
annotations, partial coverage and failed/cancelled outcomes remain unchanged.
The P0 installation/state-preserving rollback and original sustained-load gates
remain incomplete, and the production Goal remains active.
