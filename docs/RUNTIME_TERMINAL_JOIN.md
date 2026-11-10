# Original-state terminal record join — internal, not activation

This unmerged component adds a missing link between the original actor's known
anchored close outcome and the records observed on disk while holding the SAME
operation and original BSD state leases. It does **not** fix the original-node
300-second accepted-work race cap, qualify a release, or enable an updater.
The preceding first 213-top / 852-repetition native attempt remains FAILED:
518 PASS, no reported FAIL/SKIP/race, 334 incomplete/not run. CI cannot fill it.

## What is actually joined

`runtimeScope.inspectClosedTerminal` requires a bounded context and the exact
live scope-bound `runtimeStoppedWorkProof` returned after finish-only work,
known anchored runtime close, explicit v4 Stop and original state acquisition.
A proof from another or closed scope is rejected. Fresh coordinator recovery
must first reconstruct a new proof from the full known original durable chain;
a retained pointer or counts are not recovery authority.

Before and after projection, re-read installed/protected source, original
work/drain/close/Stop records, independent anchors, exact state identity,
manager ownership and actual process/domain absence. No file flock spans a
manager callback. Original operation and state leases stay held throughout.
The private model seam varies only the existing manager/kernel-domain proof,
never the raw records or source/receipt/FD joins.

1. Read the original complete admission/maintenance and ledger/session byte set
   with the existing no-follow, owner/mode/link/type/size/schema/identity and
   cross-record tenant/generation constraints. Reject unfinished records.
2. Enumerate each complete bounded ledger/session name set, sort it, reject
   invalid/duplicate names **before opening records**, and stream one bounded
   ordinary-schema record at a time. Do not retain all raw record bodies.
3. Require Firecracker-labelled DESTROYED core records, CLOSED sessions and
   terminal COMMITTED/FAILED attempts. Reproduce the unchanged live actors'
   domain-separated, sorted `json.Encoder.Encode(record)` projections. Compare
   BOTH complete counts and hashes against the exact known close completion,
   not against caller-supplied digests.
4. Rejoin the full source/receipt/manager/kernel chain, then re-read the complete
   original raw byte set. Its digest must equal the first observation, including
   admission and maintenance. A semantically equivalent whitespace rewrite is
   still raw-byte drift and refuses. Recheck retained leases before returning.

Unknown records, orphan temps, unsupported versions, mock records, aliases,
links, changed values with unchanged counts, changed anchors, scope/root/source
rebinding, cancellation or read errors yield **no partial report**. The projection
stream latches its first failure and cannot resume a rejected prefix. No ordinary
Load/recovery constructor, synchronization, repair, Stop, quota operation or file
selection is performed by the inspector. Directory names and per-record memory
retain their existing hard bounds. Context checks do not make a blocking kernel
read preemptible; no I/O deadline guarantee is inferred.

## Limits and remaining product work

`RawTerminalMatched` means only that these observed bytes, within these held
leases and bounded observations, decode to the known closed semantic records.
It does not prove exact historical bytes before the observation, malicious-root
resistance, media persistence/erasure or delivered task output. Core execution
results are still not durable in the lifecycle ledger.

The report's `ResourcesReclaimed` and `ActivationAllowed` remain false, as do the
old inventory's authority flags. It is not a transferable/persisted capability.
No public CLI action, raw file-exchange consumer, startup unfence, maintenance
release or rollback is added. Complete state-root/orphan, UID/project/quota,
backend namespaces/catalog/backing and retained-self/source compatibility still
must be joined before files. Compatible startup/health/state-FD handoff,
admission/ingress restoration, failure/reboot-safe rollback, result retention,
owned real KVM and the ORIGINAL long-load gate remain required.

## Evidence and performance scope

Portable tests compare projections with real Core/Broker closed proofs and their
actual private persisted records, including empty and populated actors. Their
explicit TEST-only driver wraps MockDriver and changes only its metadata name;
it never constructs Firecracker or launches a VM/tenant command. This is a
metadata/protocol model, **not** backend isolation or reclaim evidence.

Linux tests additionally exercise actual owned TEST-child Unix/pidfd/BSD locks,
full v4 receipts and known-close recovery, unknown/changed raw records, callback
boundary drift, retained scope/state and unchanged startup/file fences. Manager,
image, placement and kernel-domain positives remain models. Compiling these
Linux tests on macOS does not execute them; Linux CI and original-node acceptance
must be reported separately for the current source.

Local CPU diagnostics of the preceding source separated the raw differential
corpus, accepted canonical decoder and transaction benchmarks; the first
transaction profile included old and candidate branches, while a later profile
isolated current candidates. Race-instrumentation/runtime samples cannot simply
be assigned to the application's named call paths, and a short non-race profile
has limited statistical resolution. These portable diagnostics do not identify
the original Linux whole-gate CPU/I/O cause or establish cap fit. No generic JSON
parser, independent old oracle, case, original vector, resource or timeout is
changed to obtain a pass. This join deliberately adds fresh bounded reads; it is
not a claimed performance optimization.
