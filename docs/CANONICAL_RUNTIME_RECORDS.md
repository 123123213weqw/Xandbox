# Canonical work/close records and fixed proof provenance

Status: **internal software optimization/diagnostics, not production
qualification, host reclaim, activation or an operational updater**.

## Same wire and trust boundary

The seven pure work/close/drain/Stop/state-identity record declarations move to
one common-platform file verbatim. Linux effect/authority validators and all
syscalls remain Linux-only. This lets common-platform tests and benchmarks use
the EXACT production schemas, without emulating Linux, opening a backend or
introducing host execution fallback. Existing v1/v2/v3/v4 wire bytes do not change.

Only the four work/close journal record types use the canonical fast path. Their
closed, comparable schema graph contains primitive strings/integers/booleans,
structs and three fixed pointer types, with unique explicit lowercase ASCII JSON
tags. Tests reject reference growth, recursive/ambiguous/embedded fields and
custom JSON/text methods. The compile-time union excludes maps, slices and
interfaces. It is NOT a general-purpose JSON/configuration/API decoder.

The old journal syntax predicate is `strictjson.Decode` followed by exact
canonical re-encoding equality. For a fresh value of these closed schemas,
standard typed unmarshal followed by the SAME equality rejects every duplicate,
folded/unknown/alternate/escaped key, noncanonical field order/whitespace,
trailing value, lossy UTF-8, null/type/coercion and overflow form the old
predicate rejected. Non-object/missing-final-newline forms reject immediately.
Successful returned values must match the independent old predicate. Canonical
but semantically invalid values remain syntax inputs, not newly valid policy:
ALL original semantic/source/owner/process/work/closure validators still run.

Fresh rejected candidates are never published into the caller's output. A
nonzero target or other private schema retains the exact OLD strict expression,
including merge/reference/error behavior; it is not routed through permissive
unmarshal. There is no authority cache or reusable live/stopped boolean.

The enclosing file reader still enforces ORIGINAL MaxPlan, final/scratch rules,
0600, ownership, single-link/no-follow/stat and inventory/hash requirements.
No filesystem or process observation is removed or cached. The syntax helper
itself is not a new bounded-payload API; the original file-size gate remains
before it. Raw installation transaction decoding and file verification are
unchanged. An internal decode result alone never enables files or activation.

## Fixed diagnostic stages, not a changed proof policy

Stop labels its actual scope/source/manager/drain/state/process/persistence/
pre-signal/effect/exit boundaries. The real original BSD holder parser adds
fixed distinct missing/ambiguous/mismatched/malformed labels. Original process
pinning, kernel reads and every reject branch stay intact: no retry, delay,
fallback, lock break/adoption, extra process read or success inference is added.

Only closed labels are rendered. Underlying arbitrary error messages, private
paths/PIDs/records/locals are NOT formatted; `errors.Is/As` retains the original
cause and typed context for callers. A new label observed on a NEW failure is
not retroactive evidence explaining an old generic conflict or long-load exit.

## Evidence and remaining work

Independent old-parser oracles, typed scalar changes (including canonical bad
semantic values), raw duplicate/fold/Unicode/type/depth/size forms, nonzero and
other-schema fallback, deterministic concurrent reads and real private file
boundary tests guard equivalence. Controlled actual owned test children check
pre-signal error provenance without allowing any signal/job effect.

Decoder-only benchmarks compare old/new in the SAME binary on the SAME bytes.
They do not establish that a full protected command fits its original budget,
prove a sandbox SLO, or qualify real KVM/systemd/upgrade/rollback/long-load use.
The full original vectors/cases/counts/time/resource guards remain required.
Current source needs its OWN Linux/native/CI evidence; prior failed/partial
runs remain failed/partial even if later diagnostics or software checks pass.

Durable close still contains semantic observations, not all raw state/backend/
namespace/UID/project/quota/catalog/backing authority. Full source+self/schema
compatible activation, durable maintenance release, restored admission/ingress,
state-preserving failure/reboot rollback, explicit output retention/delivery,
real owned-L1 KVM and ORIGINAL long-load acceptance remain incomplete.
