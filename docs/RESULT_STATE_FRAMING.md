# Fresh retained-result state framing

Status: source implementation awaiting its own CI. This is not a new release,
measured speedup, sustained-load fix, install/upgrade executor, backend binding
migration, reclaim or activation certificate. `v0.1.0-preview.1` is unchanged.

The complete retained-state reader used to hash every result's identical raw
bytes twice inside one file visit: once for the state/stat frame and once in
the unchanged terminal-result projection. A new private `retainedResult` visit
freshly obtains the same bounded bytes and before/after metadata, runs that
ordinary projection, and uses its locally computed raw SHA-256 in the **exact
original** state frame. This removes one explicit raw-digest computation on a
successful row, not the checksum/canonical decoder, file read or later recheck.

The only production caller still rejects the **entire** unknown/unsorted/invalid
result namespace before opening any row. Every row retains its anchored open,
full byte read, type/owner/mode/link/device/size/change checks, V2 canonical and
checksum decoder, ordering/count/byte limits and original ledger/tenant/output
join. On decoder failure the original private failed-prefix frame/count is
still computed before returning the same failure. No rejected prefix is usable.
Ordinary non-result files retain their own fresh raw hash and original frame.

No digest parameter or external observation is accepted by the new visitor.
The digest comes directly from `ResultInspectionProjection.Add` on that same
private raw slice; no callback or filesystem work intervenes. It is not a hash,
file-content, validation or FD cache. Every subsequent row, full pass and
operation rereads and rehashes independently. Full original source/WAL, original
state FD and BSD ownership, pidfd Stop/absence, whole-root semantic joins and
before/after comparisons remain separate and unchanged. No authority, policy,
reservation, resource/IO ceiling, transaction or persisted format is changed.

Four Linux controls (28 named cases plus a whole-root model) compare the exact
pinned original file/result reader bodies against current owned ordinary-format
files. They cover empty/binary/maximum output, reverse creation order, multiple
owners/tenants, checksum/pending/name/type/link/mode/owner/tenant/output/context
refusals, ordinary non-result reads and fresh same-path tampering/restoration.
They compare original raw/stat frames, failed prefixes, counts, observations,
errors and unchanged file trees. The whole-root fixture is explicitly a legacy
Stop model with real result files, **not** an authentic V2 actor or real install.
All old tests, assertions, repetitions, order, matrix and 25/20-minute CI limits
remain unchanged. Linux retained-result CGO-free gates and whole-package race
select the new controls; macOS has zero new cases from this Linux-only change.

A single source-level digest removal proves neither a heap/CPU/IO hotspot nor
latency gain, regression, deadline fit or the original 40-minute load pass.
All earlier failures remain failures. No original-node load is authorized here.

The positive installed result-capable producer/transaction/startup path, FULL
Config3-to-4 binding migration under the original operation/state FDs, complete
current per-tenant reservations, trusted source/candidate/retained-self reader
ABI, typed file consumer/handoff, same-PID health, current gateway authority,
durable admission/ingress release and reboot-safe state-preserving rollback
remain required. Do not delete the old binding, rewrite gateway genesis, restore
old authority or substitute permanent refusal for implementing that chain.
