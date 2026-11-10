# Metadata process-stop failure evidence (not a shutdown fix)

The original `404bd45` PR CI failed in `metadata_smoke.py`, after the
2048-record interrupted migration, resumed migration, explicit operator resume
and metadata-cap check. Its clean-exit assertion failed, but the actual daemon
exit status and private diagnostic log were not exported before temporary
fixture cleanup. **The exact runtime cause remains unknown.** This change must
not retroactively diagnose that failure, or the twelve older sustained-load
failures, from later success or resemblance alone.

## Exact original controls, better failure evidence

All nine owned-process stop sites keep their original order, terminate versus
kill action, **15-second** wait, clean-zero versus crash-nonzero requirement,
fixture counts, actual partial SIGKILL, migration/retry checks, schema rejection,
tenant/node metadata caps and operator CAS/resume controls. No assertion or
timeout is weakened. The helper uses explicit checks, and optimized Python
refuses before main starts process work rather than disabling its assertions.

Each site has a fixed source-level phase and **explicit actual owned state
directory**. In particular, the imported 2048-record and historical fixtures
must never inspect an earlier primary root's diagnostic tail. No phase, root,
process selector or diagnostic path is added to the command line.

Normal clean-zero exits and expected crash-nonzero exits do **no additional
diagnostic IO**. Signal errors, wait errors, timeout and invalid statuses fail
closed without another diagnostic wait while the owned process might be live;
the existing `main` finally still kills/reaps its own exact handle. Only an
already-exited **unexpected status** uses the existing bounded read-only
`process_exit.failure_summary` query (10-second failure-only subprocess bound).
That is additional failure evidence, not more execution time, a normal-path
budget increase, a retry, or permission to accept an unsuccessful shutdown.

## Closed payload, no attribution shortcut

The assertion payload contains only fixed schema/phase/category/expected-policy
values, a bounded integer exit status, the wait limit, and at most six validated
kind/reason enum pairs. Unknown/malformed/oversized tails, extra fields and
collector errors cannot leak a partial prefix or turn failure into success.
No exception text, raw console/log, argv, tenant data, path, timestamp, absolute
sequence, identity or token is copied into that payload. Normal Python source
traceback locations are not hidden, and are not the daemon's failure cause.

The persisted tail is explicitly **not current-process proof**: it may include
records from earlier starts in the same directory. A previous `collector_closed`
record does not make a nonzero exit clean, prove this process reached shutdown,
or identify its cause. Diagnostic-view unavailability does not waive the exit
assertion. No old failure is reclassified and no logger/shutdown runtime budget
is changed to obtain a passing test.

Pure unit tests use fake owned handles and closed synthetic snapshots; they
launch no Go daemon, VM, real quota or tenant workload. Existing process-exit
unit classes remain unchanged. A local mock smoke run is separate from Linux
CI, original-node/KVM qualification and the original 40-minute load gate. This
test-observability improvement does not enable runtime activation/rollback or
make the full production Goal complete.
