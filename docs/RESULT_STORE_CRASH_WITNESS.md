# Selected-cut SIGKILL test witness

The Linux/Darwin results-store crash test still executes the original eight
`reserve`/`complete` × `written`/`synced`/`renamed`/`durable` cuts in the original
order. Whole-package race repetition, CI limits, all fresh-store assertions and
all unknown-prefix/name/byte-preservation checks are unchanged. This is test-only
instrumentation; the result-store implementation and its persistence operations
are unchanged.

## Why strengthen the witness

In original CI for `c3f0f2a`, one macOS `complete-durable` repetition ended with
normal exit 12 rather than SIGKILL. The original assertion correctly failed;
the other two repetitions passed. The helper ignored the return from self-Kill
and could execute later operations or its normal exit after the request. That
source property does **not** establish whether the observed failure was a missed
hook, a Kill error, delayed delivery, or another cause. The failed run is retained.

## Required evidence, not a timeout workaround

Each fresh owned child receives only its parent's dedicated pipe at FD 3. At the
selected fixed cut the helper writes exactly one fixed byte, checks the write
and close, checks the self-SIGKILL request, then parks without returning to any
result-store operation. Failure paths have distinct normal exit codes and cannot
pass the original exact `syscall.WaitStatus` SIGKILL assertion. An unvisited cut
still reaches the original exit 12 and fails.

The parent adds a **stricter 10-second per-child deadline**, closes its own writer
after Start, reaps the child, and reads at most two bytes with the same deadline.
Missing, wrong, excess or unreadable acknowledgment fails. Cancellation or deadline
expiry fails **even when the child was acknowledged and died from SIGKILL**: a
watchdog's kill is never accepted as successful crash injection. Start failures
have no child; after a successful Start all error paths first wait/reap. Both pipe
ends and the context are closed on subtest exit. There is no polling or hot loop.

The acknowledgment alone is not death or durability authority. The original
exact SIGKILL check and the entire subsequent fresh-open/recovery/refusal and
file-name/byte-preservation tail are still required. Pure negative controls
cover deadline, cancellation and malformed/missing/error acknowledgments. An
additional owned-child negative control writes a valid ACK and deliberately
does not self-Kill: after confirming ACK before the deadline, its parent cancels,
reaps, requires actual SIGKILL, and requires the witness to refuse it. This tests
the real command-context/pipe binding, not just a synthetic error value. The
control cannot replace any of the actual eight result-store publication cuts.

No case, repetition, race check, CI 25-minute / Go 20-minute limit, host resource,
IO or acceptance limit is raised or removed. This does not resolve the separate
installtxn timeout, certify the original Linux/KVM or long-load gates, qualify
installation/rollback, or requalify the published preview. There is no original
host load, deployment or production-readiness claim.
