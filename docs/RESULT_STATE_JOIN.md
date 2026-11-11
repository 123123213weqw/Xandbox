# Result-aware stopped-state join (internal, not activation)

The result-aware path now has an internal, read-only gate joining these domains
under **one original operation EX and the same retained original BSD state FD**:

1. The authentic accepted-work/V2 result-close/physical Stop journals and final
   anchors, original source, owner/Before/maintenance and process/state identity.
2. Complete current admission/ledger/session/result/diagnostic/cold-backend state
   bytes, metadata and semantic relationships, compared with the original actor's
   result-bound Core and Broker closure observations.
3. Independent stopped unit/process, known-cold jail/cgroup and the complete
   reserved project-quota absence observations.

`inspectResultsStoppedState` uses the ordinary production manager/cgroup/quota
readers. Its private test seams replace only external manager/kernel domains,
not live actor provenance, journal/source/owner checks, the original state lock
or any complete byte/semantic scan. A report-only retained-state comparison,
legacy Stop proof, Stats response, copied digest or newly acquired lock is not
an entry path. Nothing creates/unlinks/repairs a directory, calls an ordinary
state/backend constructor, stops another process, syncs quota, or selects files.
No new durable journal/format or public API is introduced.

## Ordering and refusals

The stage serializes with `runtimeScope.close` for its entire lifetime. File
flock is used only for bounded read-only source/WAL work; no manager/kernel
callback executes under it. The existing original FD-local positive BSD witness
and global negative veto remain mandatory: unlocked/shared/duplicate/rebound/
closed/foreign state is not repaired, reacquired or adopted.

Read the authentic final result Stop/closure links and require original durable
V2 maintenance, then prove known peers stopped and rejoin source. Decode the
original committed cold backend/launch composition without snapshot widening.
Run the existing two-pass complete retained-state reader against the **actual
original V2 actor observations**, not caller-supplied observations. The complete
cold root requires only its exact backend config, no ownership records, destroyed
ledger records, closed sessions, and every retained result's owner/tenant/output
budget/integrity linkage. Unknown files/scratches/links/incomplete namespaces
continue to refuse, without deletion or migration.

Observe the complete known-cold jail/cgroup/reserved-quota absence twice, checking
runtime/state filesystem identity, and repeat stopped-peer/source proofs between
passes. Finish all external and test callbacks before the final raw source/WAL,
complete root, FD-local BSD and fixed original pidfd tail. Recompare the complete
current retained inventory; any read/format/drift/error/cancellation returns a
**zero** inventory. There is no callback after the final byte-tail boundary and
no nested `runtimeScope.run` lock reentry.

These are independent sampled observations under cooperative original exclusive
locks, not an atomic global kernel snapshot or protection against malicious host
root. The lock/lease and original actor/operation provenance remain the caller's
required lifetime, not a portable certificate. Media erasure and client delivery
are not inferred from checksum integrity or absent backend resources.

## What this does not authorize

The result has `ResultsStateJoined` and observed `BackendResourcesAbsent` only
when the complete gate succeeds. **`ResourcesReclaimed` and `ActivationAllowed`
remain false**, including in the nested retained inventory. No file consumer,
activation, startup, admission/ingress release, rollback or production endpoint
consumes this observation as permission. Default/legacy readers still reject a
results namespace; there is no new-to-legacy conversion or opt-in bypass flag.

Before an installed consumer can use this gate, source/candidate/retained-self
format and byte/record/FD/IO budget compatibility must be established before all
protected mutators, with same-FD handoff/same-PID health, durable prior admission
and ingress release, candidate failure and reboot-safe rollback. Those and
current original Linux/KVM/long-load acceptance remain **unfinished**. The gate
is not a production-readiness, performance, full reclaim, native quota or SLO
claim; previous failures and the published preview are not requalified.

## Test scope

Nine additional tops run in the **existing** result Stop CGO-free gate and whole
race suite. Sixty leaf cases plus four outer boundary groups cover both metrics
inputs, complete original actor provenance/current bytes and read-only repeats,
unbound proof/scope/context/seams, unknown/corrupt namespaces and records, late
source/result/receipt/manager/quota drift, original FD unlock/shared/alias/rebind/
mode/close, unknown kernel/manager outcomes, complete-stage close exclusion and
legacy/incomplete-root refusals. An original owned test actor uses the actual
Broker/Core/FileResultStore V2 protocol and executes/retains one mock result,
then the original result-aware physical Stop/retained-FD path. No result receipt
is fabricated or inserted after a legacy Stop.

A single explicitly named TEST-only backend-label mode and verbatim existing
cold config/diagnostic format construction model the rest of the complete root.
Positive manager/image/placement/cgroup/quota/backend labels are **MODELS**, not
Firecracker/KVM/systemd/quota acceptance. Existing helper modes, all old test
bodies/cases/oracles, frozen producers, wire validators and decoder union are
unchanged. Workflow commands, matrix, race x3/20-minute Go timeout, 25-minute job
limit and host resource/IO/acceptance bounds are unchanged. New-source ordinary
CI must be evaluated on its own actual outcomes, never on a borrowed green run.
