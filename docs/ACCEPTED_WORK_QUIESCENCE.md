# Finish-only accepted-work maintenance stage

Status: **internal, incomplete lifecycle component; NOT an operational updater**.
No merge/release/deployment or real KVM/long-load qualification is implied.

## Policy and actual linearization

Ordinary drain and maintenance BEGIN retain their old behavior: fence NEW
lifecycle/session reservations, preserve accepted tickets and permit existing
instance/session execution. A separate same-owner `/v1/node/maintenance/quiesce`
POST installs an irreversible, process-local **finish-only** fence. It rejects
fresh creates, session Open/Switch reservations and execution at Core's actual
admission point. A request queued before the fence is not already accepted.
Existing read/replay, Stop and Cleanup remain available; no new cancel/force mode
or resume/release shortcut is provided.

Every accepted Core create, Core execution and session Open/Switch has a real
single-use completion obligation registered under the SAME gate mutex as the
fence. This is not a poll of `Stats`, VM count, idle counts or process absence.
A create releases its obligation only after its terminal persistence path. An
execution releases only after Driver.Exec returns, context/output checks and
terminal Job publication. Success requires no error AND exit code zero.
A session's parent obligation remains after its single-use creation ticket is
consumed, through candidate creation, final journal persistence and route
publication. The accepted child can finish after the fence without a false-zero
interval. The broker reports the actual mutation result, not ticket consumption.
The ordinary pending-reservation observation retains its original meaning.

Only work still in flight at the fence (and its accepted children) belongs to
this finish cohort. Failures completed BEFORE the fence are not retroactively
made in-flight failures. Once frozen, failures/cancellation/timeouts/nonzero exit
are sticky and NEVER become successful completion simply because pending is
zero. The fence does not cancel work; an uncooperative backend that ignores its
context keeps its obligation pending until its terminal call actually returns.
All waits are bounded by the coordinator's required caller deadline. An expired
wait/disconnected caller leaves the maintenance owner and admission fence held.

## Owner, process and crash boundaries

The private node endpoint requires the exact ready durable maintenance request;
foreign, absent, pending or fenced ownership refuses. Only the Linux
incarnation-pinned client exposes this operation. It checks live pidfd/root/
socket/peer authority before and after every bounded reply, strict JSON schema,
complete original maintenance record and exact after-state; there is no unpinned
or ordinary-drain fallback. The endpoint is nonblocking: each request freezes and
observes bounded memory only; no worker or controller mutex waits on work/I/O.

This live work API persists/accepts no success receipt across a restart.
The separate [work-bound Stop coordinator](WORK_BOUND_STOP.md) can record a
known original-live cohort result BEFORE Stop; it does not infer lost outcomes
from a dead/restarted node or clear the node's uncertainty rule. Loading a durable
maintenance record conservatively freezes execution and marks work uncertain;
loading non-destroyed old Core ownership also marks history uncertain. Cleanup,
replacement-process zero counts or retrying the same BEGIN cannot clear it.
The current ledger does NOT durably retain job outcomes. Therefore this version
intentionally refuses to certify old accepted-work success after such a crash;
a future explicit durable outcome/recovery policy is still required. It must
not guess that terminated or reclaimed jobs completed successfully.

## Original installer scope integration

`runtimeScope.quiesceAcceptedWork` requires a bounded context and the complete
original v2 maintenance WAL and drain receipt. It retains the ORIGINAL installer
OFD operation EX throughout. The original file flock is held only for source/WAL
proof, never during manager, process or operator calls. Production manager and
executable/argv/placement checks are fixed; no caller-supplied success callback,
resource count or arbitrary target process can substitute for them.

It polls the exact original peer, refuses failed/uncertain results, rechecks
installed/protected bytes, complete WAL/receipt and stable manager/process, then
requeries the original peer before returning a private opaque scope/WAL/process-
bound proof. It writes no additional success certificate, does not Stop either
unit, and does not acquire/rebind the daemon's state lock. Existing maintenance
BEGIN/ordinary drain and physical Stop result flags stay unchanged.

This proof is ONLY current accepted-work completion. It is NOT full journal or
resource quiescence, backend reclaim, service Stop, compatibility, file-selection
or activation authority. Administrative CloseSession and lifecycle cleanup can
still write state; those must be joined under the later original state lease.
The separate internal [work-bound Stop stage](WORK_BOUND_STOP.md) now consumes
the live proof to durably bind known completion before actual Stop/state
exclusion. No current updater CLI or file engine consumes either proof. The existing startup
and lifecycle-namespace rejection fences remain intact.

## Test scope and remaining P0

Tests exercise actual Core/broker admission and terminal paths, blocked Prepare,
context-ignoring execution, nonzero/backend/cancel outcomes, queued admission,
ticket single use, pre-Core and final session-journal barriers, exact owner,
uncertain persistence/restart, strict requests/replies and dead/replacement peers.
Linux installer tests use real OFD/BSD/Unix/pidfd and owned Go TEST subprocesses;
a test helper hosts a real Core controlled mock execution so a deadline cannot
be mistaken for completion. Manager/image/cgroup positive proofs are models.
No host shell, ordinary daemon/systemctl, VMM/VM/GPU, actual backend quota call,
privileged host setting, offered load or service deployment is performed.

Still required: durable lost-job outcome policy; full session/lifecycle/backend
reclaim under the original lease; typed runtime file selection in that SAME
scope; source-bound health/maintenance release/restoration; state-preserving
failure/reboot rollback; bounded real owned-L1 KVM acceptance and the original
long-load workload. Historical failed qualifications and unknown long-load cause
remain failed/unknown. No narrower software-green completion claim is made.
