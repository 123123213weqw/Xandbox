# Result-enabled installation: positive managed-policy maintenance

**Prototype, not production-ready. No deployment or original-node validation.**

The explicit `reconfigure-results` and `reconcile-results-policy` commands now
consume an actual closed top-level `resultTransaction` Version2. This is a
positive producer/atomic publication/fresh activation-ACK/retry path, not a
read-only eligibility report or an old Version1 transaction projected from a
new one. The unchanged `RotationPlan` Version1 is a separate policy-source
input schema; it does not select installation transaction version or programs.

## Actual authority and operation

* Decode actual Version2 commit bytes; keep their original digest/gateway
  genesis and full immutable Config4 backend/result binding unchanged.
* Use the original OFD ordinary-operation lease, original file flock and
  complete versioned installation verifier. The SAME operation lease spans
  policy publication, activation outside the file flock and the final fresh
  on-disk/manager ACK. Runtime EX maintenance therefore cannot interleave.
* Reuse ONLY version-neutral policy encoding, pinned source/path ceilings,
  prefix recovery, atomic rename/sync and fixed system-manager activation.
  New-version validation calls `ValidateManagedResultBase` on actual2 bytes.
  Candidate snapshot validation rereads actual2 and original pinned auth;
  no structural legacy projection, fake old base digest or version rewrite.
* Fresh complete target/generated Config4/Contract2 checks and eight original
  installed-program FD metadata/fullhash/stat joins remain mandatory, under
  the independently trusted builder and operator release/self SHA pins.
  Metadata is not cryptographic attestation or retained-state reader ABI.
* Only the existing one-file managed-policy authority changes. Key/TLS epochs
  advance under current managed validation; old genesis/current revocations
  are never restored from an initial snapshot. Backend, programs, launch and
  result/ledger/history files are not rewritten, deleted, rebound or migrated.

The unchanged old rotation algorithm is reproduced behind a separate typed
Version2 adapter. Each transformed function is statically joined back to the
exact original body with only typed receiver/read/validator/verification calls
and local variable renames. Old production entry points, codecs and tests stay
unchanged, including their refusal of Version2 transactions.

## Retry and uncertain outcomes

All eleven original policy durability points remain: four intent writes/syncs,
policy write/sync/prepared/rename/dir-sync/confirmation and final intent removal.
A complete candidate scratch or visible exact committed policy can recover
without the external source. Missing/partial/unowned scratches and competing
requests remain errors. Retain the intent until actual fixed gateway activation
and a fresh exact on-disk current-policy/manager ACK. A signal, RPC submission,
file rename or model callback is not by itself an activation certificate.
Recheck original commit and complete targets after the activation callback;
remove ONLY the matching intent with parent-directory sync.

`reconcile-results` still accepts ONLY the initial installation request. Use
`reconcile-results-policy` for an exact policy operation; retries cannot reuse
an old request for a newer epoch, or operate on a later competing intent.
Failed/uncertain activation preserves current bytes and intent, not a promise
of successful service rollback. Recovery/supersession of an expired or failed
policy is still separate unfinished work and refuses rather than being adopted.

## What this does NOT finish

This is policy maintenance, **not** result-aware RUNTIME maintenance, accepted
work close/Stop/reclaim, original retained-state FD acquisition, live-file
selection, executable upgrade, Config3-to4 migration or state-preserving
candidate-failure/reboot rollback. Those still require the full original
operation/state FD and source WAL, complete CURRENT per-tenant charged/reserved
bytes/count/history/FD/IO budgets, trusted source/candidate/retained-self reader
compatibility, typed actual consumer, SAME-FD handoff/SAME-PID health, immutable
original gateway genesis/CURRENT keys+TLS, durable prior admission and ingress
release, crash recovery and reboot drills. Reports/signatures/metadata/shape,
reacquired locks or timers alone are not that authority. Never wipe bindings or
history, project/normalize configuration, restore stale authority or end at a
permanent refusal/report instead of implementing the actual remaining chain.

New tests use real owned shadow files and original lock/journal mechanics,
MODEL program checks/manager ACK plus a TEST-ELF self pin. Opaque state sentinels
prove nonmutation only, not valid retained-state ABI. The eleven cuts are
in-process injected failure/reopen/retry models, NOT physical process death,
reboot, real gateway/systemd or KVM acceptance. CLI tests exercise actual new
verb dispatch while preserving old/bootstrap fallback. Own complete original
CI, native feature, real service/VM/install/reboot and original guarded40m load
qualification are still required. All earlier actual Go20m/outer25m/40m and
fixture failures remain failed. No measured speedup, deadline fit or SLO claim.
