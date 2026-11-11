# Pinned result-close WAL (experimental, internal only)

This connects the actual V2 Broker/Core/FileResultStore close protocol to a
write-ahead installed-operation journal. It does **not** implement a result-aware
physical Stop, post-Stop original BSD state lease, installed file activation,
startup unfencing, maintenance release, operational update/rollback or production
qualification. There is no public CLI/flag/env bypass. Neither Stats, a supplied
format report, an old work-only Stop nor the disk reader can replace this path.
`ResourcesReclaimed` and `ActivationAllowed` remain false.

## Original source and actual actuator, not a caller report

The scope uses the original OFD exclusive operation lock across the full stage.
The extracted `finishKnownAcceptedWork` is the exact original finish-only
preamble: same original source commit/immutable files, maintenance owner and
Before, original main/ingress process incarnations, original daemon-owned state
identity and BSD flock, durable work intent/completion/anchor, actual successful
frozen accepted work. No original old-path condition, order, case or deadline is
removed. The legacy caller still follows its original V1 close/v4 Stop path;
only the new typed adapter selects V2 results closure.

New fixed paths, separate from the old record-only closure:

- `/etc/xandbox-runtime-results-close/intent.json`
- `/etc/xandbox-runtime-results-close/complete.json`
- `/etc/xandbox-runtime-results-close.identity`

All are versioned typed canonical records, private FD-relative/nofollow and
bounded by the original journal limits. Only the existing fixed `.next` scratch
names are recognized. New types keep the ordinary strict JSON decoder; the old
four-type canonical fast-path union, V1 wire types and Stop validators are not
widened. A V2 intent links the exact work intent and its original work-only v3
plan; the V2 completion adds the full result-bound Core and Session observations.
**There is deliberately no conversion into a legacy v4 Stop intent.**

Before irreversible BEGIN, the adapter makes the intent final and durable,
revalidates the full original source/WAL/peers, and invokes ONLY the existing
fixed process-pinned `/runtime-results-close` endpoint. No file flock spans RPC
or manager observations. Same-UID Unix ancestry, original peer process/FD pin,
state ownership, exact owner/work and strict reply bounds remain mandatory.
The actual Broker and Manager close, and the concrete FileResultStore seal/read
proof, are required by that endpoint. The original independent 5s Session and
5s Core budgets remain unchanged, with result scans within the Core budget.
The caller must provide a bounded context; this does not interrupt kernel IO.

On CLOSED, the adapter rechecks the complete source/work/peers and repeats the
actual terminal RPC before persisting its canonical completion and independent
hash anchor. It revalidates exact final intent/completion/anchor and source links
before returning an opaque `runtimeResultsClosedWorkProof` tied to this original
operation scope and original state/process identity. A receipt lookup rereads
all these files under the SAME still-held operation FD; a cached pointer,
released/new scope or matching count cannot substitute.

The adapter directly requests no daemon/ingress signal or manager Stop,
constructs no backend, performs no ordinary state recovery or operator BSD
state-lock acquisition, and changes no target/image/unit or replays output.
The actual tracked actors still run their ORIGINAL sandbox Driver Stop/Cleanup
paths through the V2 protocol; this is not an assertion that no sandbox stops.
Their close observations alone are not complete physical host-reclaim proof. The proof is known anchored actor/work closure, NOT
current process health, physical Stop or permission to select files.

## Retry, ambiguity and compatibility fences

- Only complete exact canonical scratches may be promoted/resynced. Partial,
  unknown, foreign, legacy, mixed or orphan bytes are preserved and refuse.
- Without a known completion anchor, a dead or replacement original cannot
  invent a close outcome, even if accepted work or a full completion exists.
- A full known anchored completion can survive coordinator/original process
  death. Exact original source/work/state/owner and process-incarnation absence
  are re-proved and all records resynced before a receipt returns. No replacement
  process, report cache or zero PID is adopted. This is process-crash recovery,
  not arbitrary power-loss, malicious-root or independent historical attestation.
- New closure refuses every old close/physical-Stop namespace. Old record-only
  closure additionally refuses every new result-close namespace. No implicit
  fallback, auto-migration, success downgrade or mixed-version adoption exists.
- Legacy startup, raw file selection and update inspection additionally refuse
  even orphan new roots/anchors with all older journals absent. This only adds
  refusals; it never removes a fence or restores an old cap0 self installer.

## Evidence and remaining end-to-end work

Tests use actual private Unix/pidfd/BSD/OFD ownership, actual Manager/Broker/result
journal/accepted work and owned coordinator SIGKILL cuts. Backend/image/placement/
manager/cgroup positives are explicit **models**, with MockDriver, not a VM or
systemd/quota backend. The production image/placement proof must refuse those
fixtures. No source report or test callback produces positive actor closure.
Tests assert no Stop jobs, no operator state lease, no protected target changes,
strict V2/V1 refusal, unknown-prefix preservation, every write cut, same-original
retry, dead-before-anchor refusal, fresh opaque source/WAL joins and owned
coordinator-death recovery. Own current CI and later original-node acceptance
remain required. Prior failures remain failed, not diagnosed by a later green.

Still required: source/candidate/retained-self/startup-overlay format and immutable
managed byte/record/FD/IO budget compatibility; a distinct result-aware physical
Stop and retained original post-Stop state FD; whole result/core/backend/kernel
reclaim join; typed file consumer and same-FD candidate handoff/same-PID health;
durable prior-admission/ingress release; candidate-failure/reboot-safe rollback;
unknown-prefix administration/acknowledgement/legacy integrity migration; current
full original software/owned KVM and ORIGINAL sustained-load qualification.
The Goal remains active, and no new release or production/SLO claim is enabled.

## Following physical stage

The separate [result-bound physical Stop adapter](RESULT_STOP.md) now consumes
this opaque closure through fresh source/WAL joins, uses the original physical
Stop algorithm with a distinct typed journal, and retains the original BSD state
FD. This close component still does not perform those service effects itself.
Neither component enables file activation, backend-reclaim or production
qualification; see that adapter's explicit evidence and remaining-work limits.
