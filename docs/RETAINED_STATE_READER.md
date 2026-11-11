# Complete retained-state reader (experimental, disk-only)

This supplies the explicit result-format reader needed before installation can
preserve retained outcomes. **It does not activate a managed installation or
rollback path.** The old installed root reader and operation/Stop formats still
refuse a results-bearing state. File/startup/self boundaries remain fail-closed;
startup/raw file/update-inspection guards additionally reject orphan result-close
WAL paths. No CLI, flag, environment bypass or ordinary daemon path
selects the new reader. `ResourcesReclaimed` and `ActivationAllowed` stay false.

## What is actually compared

The new reader requires a bounded context, a valid exact maintenance record and
valid V2 result-bound Core plus Session format observations. Observations are
inputs to a **disk comparison**, never evidence that a live actor actually
produced them. Its caller must own the original exclusive state lease; the reader
does not establish or certify that precondition.

It performs two complete independent passes over the installed cold root with
exactly one additional **mandatory** known directory: `results/`. No generic
walk/ignore policy accepts catalogs, snapshots, scratch, unknown or missing
names. The original metrics-dependent private socket set is unchanged. Files
and directories are FD-relative/nofollow, same-device, private/type/owner/link
checked; inode, group, size and write/change metadata plus every raw file byte
are bound to the root footprint. Access time alone is excluded. Directory
iteration uses independent descriptions, not a borrowed FD's shared offset.

Each pass:

1. Reads the original admission identity, maintenance side record and anchor,
   complete ledger/session raw authority, including ordinary ownership and
   failed-target semantics. All ledger instances must be DESTROYED and all
   sessions CLOSED.
2. Reconstructs the original sorted Core and Session terminal projections, not
   just counts. It decodes the actual complete ledger again to retain per-owner
   tenant, generation and exact output limit, without buffering all file bodies.
   Its owner index keeps only the Ref key, tenant and exact output limit: it
   never accumulates decoded Record/error payloads across owners. The complete
   record (including LastError) is still validated and included in its terminal
   and raw/root digests; discarding payload from the index is not ignoring data.
3. Rechecks the admission/ledger/session raw authority before the final root
   scan. The full root scan then validates every known namespace, backend config
   and persisted diagnostics, and each result filename/header/ledger join.
4. Uses the **ordinary** canonical/checksum decoder for each bounded result.
   Only complete V2 terminal rows qualify. Legacy V1, pending/partial, corrupt,
   linked, public, oversized, foreign or unknown entries refuse without changes.
   The full sorted raw-record digest, actual bytes and pessimistic reservations
   must match the supplied V2 observation; missing or additional valid rows do
   not pass merely because the remaining rows are valid.
5. Compares both complete root/raw/stat footprints and all parsed observations.
   Even replacement by the same raw bytes in another inode between passes
   refuses. A failed/cancelled scan returns zero, never a partial positive report.

The new pure streaming result projection shares the ordinary decoder and exact
raw-record closure framing with the actor's format. Its tests compare it against
an actual FileResultStore writer/seal. It exposes no stdout/stderr/error payload
and cannot produce a `ResultBoundClosureProof`. Any rejected prefix is poisoned.
The old actor, wire formats, writer, decoder, caps and test bodies are unchanged.

There is no constructor/load/recovery/sync/unlink/repair, backend or manager
callback, quota query, file selection, output replay or new resource allowance
in the reader. A private TEST cut exists only **between** full passes; nothing
calls it after the final scan. Extra semantic/raw passes intentionally add IO;
this is not a performance optimization, IO-budget increase, or hard syscall
termination guarantee.

## Tests and remaining production integration

Tests use private format fixtures, the actual result journal and owned test
processes/FDs. The installed root is a **model**, with MockDriver/backend/systemd/
quota models. Results are explicitly added after the legacy stopped fixture;
that fixture is NOT a result-bound live actor/Stop acceptance. Tests assert that
the old reader and old complete-state join still reject the new namespace.
An additional empty/max4096-byte error control verifies the minimal owner
index structurally and independently checks the complete error-bearing Core
digest. It intentionally does not create 100k records or claim a host-memory
stress test or managed quota qualification.
Source and original CI logs must qualify the new code independently; no old green
binary, report or mock pass qualifies Linux/KVM, physical reclaim or sustained
load. All prior failed experiments remain failed.

Before any real file mutation, the operational consumer still needs:

- The [durable pinned V2 close WAL](RESULT_CLOSE_WAL.md) now supplies an internal
  actor/work receipt under the original operation FD. A distinct result-aware
  physical Stop and original post-Stop state FD join remain required. Neither
  this disk report nor the new pre-Stop closure receipt substitutes for them.
- Source, candidate and retained-self/startup-overlay format compatibility,
  including explicit V1 integrity policy and refusal before incompatible files.
- Managed immutable result-byte/record/FD/IO budgets. Existing logical result
  reservations are not kernel quotas, and lowered ordinary admission budgets
  preserve old data rather than authorizing a destructive migration.
- The typed file consumer, same-FD candidate handoff, same-PID health, durable
  prior admission/ingress release, and candidate-failure/reboot-safe rollback.
- Safe unknown-prefix administration, acknowledgement/retention lifecycle,
  original-node full software/owned KVM and ORIGINAL sustained-load acceptance.

Checksums/footprints describe current bytes, not malicious-root resistance,
independent historical anchoring, client delivery or media erasure. This reader
is a required format component, not completed installation compatibility or a
production readiness claim. The full Goal remains active.
