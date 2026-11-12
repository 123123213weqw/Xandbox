# Known-work completion before update-only Stop

Status: **internal, incomplete lifecycle coordinator; NOT an operational updater**.
No CLI or file-selection engine consumes this result. No real service/systemd/
KVM/quota/rollback/long-load acceptance is implied by the shadow software tests.

## Explicit order and authority

`runtimeScope.finishAndStop` composes actual work admission/terminal paths, the
bound runtime closure, original physical Stop protocol and original BSD state
lease. See [durable runtime close](DURABLE_RUNTIME_CLOSE.md) for the v4 composition. It retains
ONE original installer operation OFD lease throughout; file flocks cover file
reads/persistence only, NEVER process/manager/operator RPC. Each stage revalidates
its original scope, installed/protected source, complete recorded input and
fixed process/manager authority. There is no caller-supplied successful-work or
stopped boolean, arbitrary PID/root, backend constructor or forced adoption.

1. Require the exact ready v2 maintenance WAL/receipt. While the ORIGINAL daemon
   is alive, capture its original BSD state-file/root identity and kernel lock
   ownership, plus the original ingress incarnation (or observed absence).
   Persist the immutable `finish-only-v1` work intent before the work fence.
2. Run the separate finish-only work stage. Only its original live pinned peer
   can produce terminal success. New create/session/Exec stays fenced; failures,
   timeouts, cancellation, unknown outcomes and unreturned calls cannot succeed.
3. Reprove the exact original source, live processes, state identity/holder,
   owner and terminal work. Persist/sync a complete canonical terminal receipt,
   then a separate SHA-256 root anchor. The receipt is the known-success
   observation of this ONE frozen cohort, not per-job history or saved outputs.
4. Journal and run the bound runtime-close protocol; require its exact known
   receipt plus independent anchor. Publish **v4 physical Stop** bound to close
   AND the exact work completion
   digest and the EARLIER recorded Stop/state/process plan. Only then may the
   existing fixed manager Stop jobs run, ingress before main. Original v1/v2
   bytes and independent physical-only semantics remain unchanged.
5. Repeat the original kernel/manager exit and whole-domain absence proofs,
   acquire/retain the ORIGINAL daemon BSD state lease, and rejoin source, WAL,
   work/close completions/anchors, v4 Stop intent/receipt and current state identity. Return
   only an opaque current-scope work/Stop/state proof. Scope close releases state
   before operation ownership. No ownership is created/rebound/broken or adopted.

The original physical Stop API still never reports accepted-work success. v3
adds a strict read-only completion link; it does not reinterpret v1/v2 receipts
or let ordinary Stop turn an unfinished/killed job into successful work.

## Known outcomes versus lost outcomes

The live work API itself remains volatile. This separate coordinator records a
positive result ONLY after observing the original source-pinned live gate and
its real terminal paths. After complete receipt AND independent anchor exist,
that known WORK outcome can survive coordinator or original-daemon process
death. It alone no longer initiates Stop: the v4 path ALSO requires known
anchored runtime closure before original-daemon death.
A fresh scope syncs/joins the exact existing records and earlier identities,
requires live originals to confirm the SAME frozen terminal status, or requires
the original numeric PIDs to be absent. A replacement incarnation is never
adopted, even with empty counters or an equal ordinary admission state.

No-anchor/missing/unknown partial intent, completion or anchor is NOT positive
recovery authority. A full canonical receipt without an anchor can be completed
only by reproving the SAME original live process; a dead/restarted process
cannot manufacture old outcomes. Complete canonical original scratches can be
resynced/published under the recorded input; unknown prefixes, duplicates,
unknown fields/paths/links/modes or changed identities refuse without repair.
The anchor detects independent completion changes; v3 additionally binds its
exact digest before any Stop effect. Nothing guesses a new Before/process/state
identity from current paths, deletes a side namespace, or resets an orphan.
This is process-crash recovery with honest fsync, NOT arbitrary media/power-loss
attestation or resistance to a malicious root rewriting every authority.

General job-outcome/output durability is still missing. The receipt does not
retroactively include jobs finished before the fence, provide their output
history, make failed jobs successful, or reconstruct outcomes lost BEFORE any
known-success record. The node's restart-uncertainty rule stays intact.

## Deliberately not full reclaim or activation

Known work completion is independent of physical termination and full resource
reclaim. Administrative session close, broker journals and lifecycle cleanup
may write until original process absence and state exclusion are established.
The retained state lease closes that writer boundary; it does NOT prove every
backend jail/cgroup/owner/project/quota/catalog pin/backing or all mutable/version
authority is reclaimed/compatible. Current backend counts remain observations.
The opaque result does not authorize files, maintenance release or activation.

The work namespace and separate anchor/scratch now also fail the ACTUAL cap0
startup verifier and raw file-selection guard, even when otherwise empty or
orphaned. Existing startup and lifecycle fences are never removed. Source-bound
candidate/retained startup health, prior admission/ingress restoration, complete
failure/reboot state-preserving rollback and an operational updater remain open.

## Test scope

Shadow tests use actual files/OFD/BSD locks, kernel original-holder observations,
private Unix/pidfd and actual Core controlled mock calls, not an idle count or
VM exit as task completion. The original manager pipe allows ONLY parents to
terminate/reap their own TEST helpers; coordinator cuts use actual self-SIGKILL.
New mode composes the real internal entry; all original helper vectors/modes,
test cases/counts/budgets remain unchanged. Manager/image/placement/cgroup/
mount/IO/quota positive proofs remain explicit models. No ordinary daemon,
systemctl, VM/GPU, actual quota query/mutation, offered load, privileged host
setting or deployment runs during native software qualification.

Full original owned-L1 Linux/KVM/systemd/reclaim/activation/rollback and original
long-load acceptance are still required, with the existing safety/asset/time/IO
budgets and historical failures intact. The old metadata-exit cause remains
unknown. Software-green evidence is not production readiness or a substitute
for the complete Goal.
