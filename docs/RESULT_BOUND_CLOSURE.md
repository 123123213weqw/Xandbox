# Result-bound closure and checksum v2 (experimental)

This connects retained outcomes to the actual live Manager/Broker close path.
It does **not** enable managed updates, file switching, startup unfencing,
maintenance release, automatic prefix recovery or production qualification.
The legacy installed cold-state reader still refuses the results namespace.
A [separate disk-only retained-state reader](RETAINED_STATE_READER.md) now
compares the complete known root and all canonical results to supplied V2
observations; it is not an actor/Stop/activation capability or managed updater.
An internal [write-ahead pinned close adapter](RESULT_CLOSE_WAL.md) now persists
this actual V2 actor outcome under its original installed-operation scope. It
requests no physical Stop or file effects and cannot produce a legacy v4 proof.

## New records and explicit legacy boundary

New reservations and terminal records use result-envelope **version2**. A
SHA-256 checksum covers a domain/version-separated canonical body containing the
entire reservation and result, including raw base64 output and bounded error.
Every read/restart validates it before publishing data. This detects accidental
record changes, not a malicious root capable of changing bytes and recomputing its checksum; there is no independent historical anchor or client-delivery proof.

The exact canonical version1 encoding stays readable, **without rewriting it**.
Its terminal API rows explicitly say `result_integrity:legacy_unverified_v1`;
newly written/validated v2 rows say `result_integrity:checksum_v2`. V1 data cannot
be silently promoted to a v2 close proof, and the new writer never completes an
old/reconstructed pending reservation. No offline migration is implemented here.
Pending results are `INTERRUPTED`, not retained, with exit code **-1**, never an
observed clean-zero result or a command to replay. Invalid/unencodable timestamps
refuse rather than panicking through storage encoding.

Execution success is published only after the actual stored terminal row is
read back and matches every driver outcome/identity/timestamp field. A plausible
success flag, mismatched output or legacy integrity marker cannot suffice.
The original node/tenant/record reservation charges, output ceilings, private
permissions and disabled-by-default standalone opt-in policy are unchanged.

## Actual actor and complete result namespace

`Manager.ClosedResultsProof` requires a bounded context, the SAME actual concrete
FileResultStore, successful frozen accepted work, finished pools, zero live
instances, and all real durable DESTROYED records, as before. It reuses the
original record-only implementation internally without changing its validation.
The public legacy `ClosedProof` refuses retention mode instead of omitting it.

The result store installs an irreversible in-memory writer seal. A writer that
started before it, even one waiting for a record lock, refuses proof; later
Reserve/Complete cannot enter. The short index mutex carries only counters and
immutable metadata, never disk IO. Read-only lookup IO neither waits on nor vetoes
this sealed metadata snapshot. Existing writers retain their own FDs; no force
cancellation, borrowed handle, retry or new IO deadline is introduced.

Two full read-only scans bind the entire sorted bounded namespace, all exact
canonical V2 terminal bytes, ledger tenant/generation/output-limit identity,
original live-index hashes, pessimistic charge totals, and per-file/root
identity/write metadata. Unknown, missing, legacy, pending, failed, extra,
linked, rebound, changed or scratch entries yield **zero**, never a partial
observation. Access time alone is excluded. No repair, sync, unlink, quota query,
backend constructor, manager callback or file mutation occurs during the scans.
There is no test/user callback after the last scan. Actual actor memory is
rejoined after IO; the proof is invalid when its actual store closes.

The observation's counts/byte totals/digest describe these current bytes, not
portable authorization, physical resource reclaim, erasure or historical inode
identity. A future installed-state consumer must rejoin the same original scope
and bytes; it must never substitute this report or just its record count.

## Separate private operator protocol

The old V1 runtime-close request/reply types and validators are unchanged.
Retention mode rejects that old endpoint before beginning; old non-retention
mode rejects the new endpoint. No implicit fallback exists in either direction.

The distinct same-UID private Unix endpoint is
`/v1/node/maintenance/runtime-results-close`, with request/reply **version2**.
The process-pinned Go operator client exposes `RuntimeResultsClose`. It requires
the SAME ready durable maintenance owner and actual successful quiescent work.
The coordinator closes the real Broker and Manager, then obtains their actual
session/record/result proofs. Neither Stats nor caller-supplied callbacks can
produce a result. Partial/failing/legacy storage stays fenced, without exposing a
partial Core or Sessions proof; Core cleanup is still attempted independently
when Session close fails. Accepted BEGIN remains irreversible after caller
cancellation; no restart/reopen/release or output replay is enabled.

The original independent **5s Session / 5s Core budgets** remain. Result
inspection is within the remaining Core budget, not an added allowance. Kernel
IO is not made interruptible by a context; state-lock retention still joins the
actual coordinator/actor completion. Private socket ancestry/peer UID, original
process pin, fixed path, command/reply size, strict JSON, owner equality and
redirect refusal remain mandatory. This adds no TCP, tenant token, CLI updater
or source/candidate compatibility bypass.

## Remaining gates

New code requires its own disposable CI and later original-node/software/KVM
acceptance; old green binaries or host reports do not qualify it. Tests use
private records and real in-process actors/Unix/pidfd plus owned child crashes,
with MockDriver rather than a VM/systemd/quota backend. All prior failures stay
failed; this is not a diagnosis of the old long-load exits or a performance/SLO
claim. Managed resource budgets, versioned source/candidate/retained-self/startup
compatibility, typed installed file consumer, same-FD/health handoff, release,
failure/reboot-safe rollback, safe prefix recovery, retention lifecycle and
ORIGINAL sustained-load acceptance remain incomplete. The full Goal stays active.
