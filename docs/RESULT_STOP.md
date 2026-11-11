# Result-bound physical Stop (experimental, internal only)

This is the next stage after the [actual V2 result-close WAL](RESULT_CLOSE_WAL.md):
known successful accepted work and anchored Broker/Core/FileResultStore closure,
then physical ingress/main service Stop and original retained state ownership.
It is **not** an operational installer, whole-backend reclaim certificate,
activation/release/rollback permission or current original-node KVM acceptance.
There is no public command, constructor, mode flag or environment bypass.

## One physical algorithm, separate authority

`finishCloseAndStopResults` requires a bounded context and the SAME original OFD
operation scope. A typed Stop intent at `/etc/xandbox-runtime-results-stop/`
binds all four original work-intent/work-completion/V2-close-intent/V2-close-
completion hashes and the original v2 process/state plan. The plan is only a
projection of original incarnation and inode identity: **no** new type is
converted into an old v4 work/closure Stop receipt. Old wire validators, the
four-type canonical fast path, old test bodies, budgets and policy stay intact.
New records use ordinary strict canonical decoding.

The physical-effect body is extracted intact behind a closed private journal
choice, not duplicated or replaced by a report callback. The old caller keeps
its original wire/root/cuts. The new caller first verifies actual anchored
closure and makes its distinct intent final and durable, then uses the SAME
original main/ingress pidfd watches, image/argv/placement proof, state inode and
live daemon BSD owner, fixed `--job-mode=ignore-dependencies` Stop ingress BEFORE
main, exact exit and whole-subtree empty/unfrozen checks, presignal source and
peer rechecks and final domain rechecks. No file flock spans manager or RPC
callbacks. All original stages/order/conditions/deadlines remain; source
restoration must prove the complete old body byte-exact after journal dispatch.

The new inventory always re-reads the original source/immutable transaction,
drain/maintenance owner+Before, work records/anchor and V2 result-close records/
anchor. Unknown, partial, foreign, mixed, missing, extra and duplicate scratch
prefixes refuse without repair. Complete known canonical scratches can be
promoted/resynced. A Stop receipt cannot create an unknown work/close outcome.
Even if both old processes died, their known anchored closure is required and
old numeric PIDs must actually be absent, not reused or adopted from zero
manager counts. Original child-process death does not prove full backend reclaim.

Old physical-only Stop additionally refuses any result-close or result-Stop
prefix, preventing an internal legacy caller from silently downgrading semantics.
Old record-only close, raw file engine, startup and update inspection additionally
refuse an orphan new Stop root with all older journals absent. These changes
ONLY add refusals, never remove the old cap0 self/startup/file compatibility fence.

## Original retained BSD state FD, not a cached boolean

After exact Stop receipt and fresh manager/kernel/incarnation absence, the
operator opens only the original existing `controller.lock`, compares the saved
root/lock inode/device/ctime/private/type/link identity and acquires its original
nonblocking BSD exclusive flock. A foreign holder is an error; no waiting out,
breaking, truncation, deletion, creation or new identity is permitted. Reprove
source/close/Stop/absence and path/FD identity after acquiring; close the FD on
any failure. Keep the same FD in the original operation scope across subsequent
inspection. Closing the scope or coordinator death releases it.

New `runtimeResultsStoppedWorkProof` is opaque and bound to this scope, all known
actor/work fields, Stop digest and original state identity. A receipt lookup
re-reads the complete source/WAL/anchors and current physical absence, checks the
retained BSD flock from the actual FD-local process kernel record (unique matching
FD, exclusive BSD WRITE, exact PID/device/inode/whole-file; global rows are only a
negative veto including waiters), and repeats the source/raw link AFTER model
callbacks. Unlocked/shared/aliased/rebound/closed FDs or fresh/released scopes
refuse ZERO, without reacquiring a lock or trusting the cached proof. No callback
runs after the final raw/source join. This does not interrupt blocked kernel IO
or create a hard wall-clock SLO; extra bounded rechecks intentionally add IO.

## Evidence boundary and unfinished P0

New tests require actual private Unix/pidfd/BSD/OFD owners and actual accepted
work/Broker/Core/FileResultStore. Fixed TEST manager/image/placement/cgroup
positives are MODELS/MockDriver, not systemd, Firecracker/KVM, real quotas or a
shared-host load test. Only the parent terminates/reaps its own TEST helpers;
coordinator SIGKILL uses a bounded inherited fixed manager protocol. No ordinary
daemon, backend constructor, systemctl or VM is launched. The production entry
must reject those model fixtures. Own CI/current original-node acceptance must
be inspected, not inferred from a parent green run or test source.

This stage does not re-read the entire current retained result/ledger/session/
backend namespace as one post-Stop authority. A historical sealed result digest
is not proof that current disk bytes remain intact or that a client received them.
Next integrate that complete bounded join using this SAME original state FD,
then require source/candidate/retained-self/startup-overlay format and managed
byte/record/FD/IO budget compatibility BEFORE any protected mutation (including
ordinary install/reconcile/policy/recovery). Typed file consumer, same-FD handoff,
same-PID health, durable prior-admission/ingress release and candidate-failure/
reboot-safe rollback, unknown-prefix administration/ack/V1 integrity migration
and complete original software/owned KVM/ORIGINAL sustained-load gates remain.
`ResourcesReclaimed` and `ActivationAllowed` remain false. Earlier failures stay
failed; no timing/root-cause/performance/production/lossless/SLO claim is enabled.
