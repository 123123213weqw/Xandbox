# Source-bound tracked-runtime close

Status: **experimental internal actuator, NOT full-host reclamation or an
operational updater**. The internal installer now composes and journals this
protocol; see [durable runtime close](DURABLE_RUNTIME_CLOSE.md).
No real systemd/KVM/quota/activation/rollback/long-load acceptance is implied.

## Actual authority and effect ordering

The ordinary daemon binds its actual Manager and Broker before exposing its
operator endpoint. Binding is once-only and requires the SAME admission gate
and the broker's exact Core pointer. There is no arbitrary close/Stats callback,
caller-supplied success boolean, alternate lifecycle constructor or host root.
The existing admission state, ledger, session and maintenance disk formats stay
unchanged; this operation adds no sidecar that an old reader might silently use.

Only the exact ready durable maintenance owner can request a close. BEGIN also
requires the ORIGINAL live controller and the actual frozen accepted-work gate's
terminal success. Pending, cancelled/failed/unknown or restarted work refuses;
an ordinary drain/idle count cannot substitute. Status queries do not start a
close. A duplicate BEGIN observes the SAME operation, never spawns another one.

The private `/v1/node/maintenance/runtime-close` POST is bounded memory work
only. An accepted close runs the real `Broker.Close` and `Manager.Close` outside
all controller mutexes and RPC handlers. Caller disconnect/cancellation AFTER
acceptance does not undo it. Original independent session/Core shutdown budgets
remain **5 seconds + 5 seconds**; a bad session journal never consumes the Core
cleanup opportunity. The private test seam varies ONLY these NEW deadlines to
exercise failures, never the original native/CI/resource/time guards.

Broker close revokes routes and persists CLOSED records through its actual
journal actor, waiting for mutations/writers to finish. Core close uses the
normal owned-generation Stop/Cleanup/durable DESTROYED protocol and waits for
its actual lifecycle pools. Neither `Stats.Active==0` nor `LifecycleDone` alone
is accepted as proof. A blocked cleanup or blocked DESTROYED Save stays pending,
even if resources appear absent or an observation callback falsely says idle.

## Opaque live completion, not a transferable certificate

Core proof requires a frozen successful work barrier, closing state, exited
pools, no active allocations AND validated DESTROYED records with no remaining
calls/history. Broker proof requires installed closing fences, exited journal,
zero mutations, no routes/busy/dirty entries and validated CLOSED records with
terminal attempts. Constructors join the ACTUAL terminal paths, not modeled
counters. Proofs are private-owner-bound values; projections contain only counts
and domain-separated sorted semantic-record hashes. No argv, output, raw errors
or tenant records are exposed. Hashes are NOT raw on-disk byte-set attestation.

Only BOTH exact opaque proofs and the unchanged original work fence produce
`phase=closed`. Failure/timeout/unknown work stays `fenced` with no projections;
late journal completion is not silently promoted to success. Controller Close
waits for the actual broker journal and Core pool actors, not just its own
coordinator goroutine: timed-out I/O must retain original state ownership.
There is no resume/release/cancel/force mode.

Only an incarnation-pinned client exposes this protocol. Complete original
owner/before/after identity, strict bounded JSON, live private root/socket/peer/
pidfd before and after each reply are required. Legacy/unsupported endpoints
refuse without ordinary Stop/drain fallback. Cached JSON cannot mint a proof for
another Manager/Broker or a replacement process.

## Boundary that MUST NOT be promoted

This closes/reclaims resources tracked by the actual current lifecycle actors,
according to their Driver/Store contracts. It is NOT proof of all backend
namespaces, unknown/orphan owners, the complete UID/project/quota range, node
cgroup envelope, shared catalog pins/backing/pristine assets or every state-root
writer (diagnostics/control still exist). No backend constructor or ordinary
Store.Load is disguised as inspection. Full resource/version compatibility and
physical Stop/original state lease plus exact all-authority/kernel/namespace/
quota joins remain independent prerequisites before file selection.

The endpoint result remains live-only. The internal installer now persists a
source/work/process-bound write-ahead intent and independently anchored known
close outcome BEFORE explicit v4 Stop; see [durable runtime close](DURABLE_RUNTIME_CLOSE.md).
That new receipt is not whole-host reclamation, file selection or activation.
Missing replies and replacement zero counts remain insufficient. All startup
and raw file-selection namespace fences stay intact. No CLI/update/deployment
is added; original-state-held full authority and rollback joins remain open.

Normal Core Cleanup discards in-memory job outputs, as the existing Destroy
contract specifies. This close is NOT a guarantee that a client fetched a
finished result, nor general durable job-result history. A production upgrade
policy must explicitly resolve result retention/delivery, not relabel command
completion as successful delivery or silently discard it during an advertised
lossless update. The complete production Goal remains unchanged/incomplete.

## Test boundary

Tests exercise real private FileStore/Core/Broker close paths and controlled
mock generation removal, blocked cleanup/DESTROYED/session writes, responsive
status, independent Core opportunity, ownership/binding, caller cancellation,
sticky work uncertainty and original actor retention. Private Unix/pidfd client
and strict wire tests are software evidence only. Mock is not isolation.
No ordinary daemon/systemctl, real backend quota call, VM/GPU, offered load,
privileged host settings or service deployment runs on the original native node.
Real owned-L1 KVM/reclaim/activation/rollback and original long-load acceptance
remain required; historical failed results/cause uncertainty are preserved.
