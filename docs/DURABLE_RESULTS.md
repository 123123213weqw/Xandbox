# Bounded retained execution results (experimental opt-in)

This is a data-preservation prerequisite for runtime updates, **not an operational
updater, lossless delivery, production qualification, hard IO deadline or a fix
for the earlier unknown long-load/metadata exits**. Default jobs remain volatile.
No existing managed launch manifest, startup fence or file selector is relaxed.

## Enable only in an explicitly configured standalone daemon

For example, `sandboxd ... -result-bytes 67108864` opts into a private `results/`
namespace under the existing exclusively locked state directory. The tenant
reservation default is min(16 MiB, node budget); record admission defaults to4096.
`-result-tenant-bytes` and `-result-records` can reduce these admission limits.
Hard ceilings remain1GiB logical reservations/100000records and the original
65536output bytes/job; no automatic expiry, eviction, acknowledgement, GC or
increased guest/resource/IO budget is introduced. Lowering limits preserves all
valid old records and prevents further admission above the new bounds. These
are conservative logical byte reservations, **not a filesystem/kernel quota**.

An existing results namespace with retention disabled refuses startup rather
than silently losing access to results. Unknown format/owner/generation/limit
bindings, names, links, modes, sizes or partial scratch refuse unchanged. The
current managed installer cannot enable this option; its complete cold-state
reader deliberately rejects `results` until a compatible closure and startup
protocol explicitly binds these additional bytes. Do not manually remove that
refusal, restore old cap0 self or treat this feature as update permission.

## Ordering and bounded data

1. The accepted-work obligation and instance idle count cover the WHOLE storage
   reservation pipeline. Freeze cannot pass through a false-zero IO interval.
2. Reserve the job's maximum output plus bounded metadata against node, tenant
   and record limits BEFORE storage IO. Ambiguous failures retain live capacity.
   Persist a private versioned intent by exclusive scratch/write/fsync/rename/
   directory-fsync BEFORE calling Driver.Exec. Argv/auth tokens are not stored.
3. Actual guest results stay RUNNING/unpublished until their bounded terminal
   record is fsynced and renamed durably. Raw output bytes use base64, preserving
   even invalid UTF-8 in the private journal. Error text is bounded/private and
   retains the existing public API redaction. HTTP JSON string encoding is NOT
   a new binary-byte or client-delivery guarantee.
4. Only confirmed persistence sets `result_retained:true` and permits this work
   obligation to succeed. Persistence failure returns a fixed unavailable error,
   never volatile output advertised as retained. Storage IO holds neither the
   instance mutex nor the admission mutex; the guest's independent Stop/cancel
   path is not blocked behind it. A stalled fsync can still delay completion;
   no kernel syscall or shutdown deadline guarantee is claimed.
5. VM cleanup drops the in-memory job map but NOT the separate result journal.
   The original tenant-scoped sandbox/job endpoint can retrieve a terminal
   result after destruction/restart. Session switching does not make an old
   job belong to the new generation: use its original sandbox/job identity.

Restart validates the entire bounded private namespace and ledger ownership
before publishing results. Existing published records are reconfirmed/synced.
A pending intent is reported as `INTERRUPTED`, `result_retained` absent/false and
no output: execution outcome is UNKNOWN, **never replayed**. Pending result state
marks accepted work uncertain even if every ledger record is already DESTROYED.
An old closure receipt/counter cannot establish success for this new namespace.

## Recovery and evidence boundaries

A process death after a full rename can recover a pending or terminal record
without executing anything. Unknown/partial scratch is intentionally preserved
and blocks startup; automatic prefix repair, safe administrative recovery,
retention lifecycle/delivery acknowledgement and full state-root/closure binding
remain unfinished. No arbitrary power-loss, malicious-root rewrite resistance,
media erasure, complete activation/reboot rollback or performance claim follows.

Tests use private synthetic records, bounded mock execution and specifically
owned TEST-child SIGKILL at eight publication cuts. They are not real KVM/quota/
systemd/host failure acceptance. Original cases/repetitions/resource caps and all
prior failures remain intact. No V100 workload or deployment is authorized by
this document; current original-node/KVM/sustained-load qualification is still
required before a production release.
