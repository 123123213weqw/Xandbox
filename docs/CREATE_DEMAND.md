# Bounded creation demand — isolated P0 candidate

**Unqualified runtime candidate, not a released load fix.** Based on released
main plus the independent P0 test-safety work. It selectively reuses the FIFO
and closed-initial-overload mechanisms from PR #23, **not** that branch's asset
copy, writeback, activity, diagnostic or load-harness experiments. None of that
branch's historical runtime evidence certifies this new program.

## Why this change

Two separate memory-only counterexamples are retained:

- Exact released `46b6253`, plus one standalone regression: the managed create
  returns capacity refusal while a known existing instance still occupies the
  slot, before the test releases it. There is no mechanism to await its future
  durable release. Raw-only fail-fast behavior is deliberately retained.
- Exact PR #23 head `faf3c0a`, plus the same targeted new burst regression: with
  N=4 and two authoritative tenants of live quota 3, a second different raw
  intent from one tenant grows waiting callers from 3 to 4 while allocated stays
  4. Its existing per-tenant waiting bound derives from live quota, permitting
  several DIFFERENT future creations from one tenant to lengthen the FIFO.

These establish control-plane behavior, not a unique cause or physical timing
of the historical failed load. In particular, `canary_old_gc` is not proof of
slow GC: the twelfth failed run's two creations already used about 17.36 and
16.87 seconds, leaving about 4.2 milliseconds after its fresh command. Admission
spans include rechecks and must not be renamed pure queue time.

## Policy

1. No new VM capacity: active, preparing and unreclaimed instances retain the
   same node/tenant limits. Only a successful durable DESTROYED commit releases
   a slot. Queueing is not a Ref, ledger key, project or resource reservation.
2. Managed demand may start a future-capacity queue. Raw-only overload still
   fails immediately; raw may join an existing queue so an ongoing managed
   stream cannot monopolize turns. FIFO among currently eligible callers stays
   unchanged: no managed/canary priority, tenant-name special case or reserved VM.
3. Hard waiting-caller caps remain `min(N,128)` per class and twice that globally.
   The old per-tenant/class caller cap `min(N,128,tenant live quota)` is also
   retained, including identical retries; equivalence never waives that cap.
   **Each tenant/class may have only ONE different future reservation intent**,
   regardless of its larger live VM quota. Raw and managed have the same rule.
   Another tenant's eligible work can still bypass a tenant-quota-blocked head.
4. Identical nonempty keyed retries (same tenant policy, normalized spec and
   admission capability) do not represent another future VM. Their independent
   contexts/FIFO positions still count toward the original hard caller caps.
   They never share cancellation or consume another caller's one-shot ticket.
   After one reserves, the others replay the same ordinary key/Ref. Empty keys,
   different specs or different capabilities cannot claim this exception.
   This is NOT an unbounded retry-listener facility or guaranteed queue space.
5. Capacity waiting, ownership persistence and Prepare share ONE existing
   Prepare deadline. Internal `CapacityWaitTimeout` can only shorten that
   envelope. Granting a slot never restarts it; TTL and the client actor budget
   are not extended. Blocking storage still is not a preemptible wall-clock SLA.
6. Waiting cancellation, manager Close, drain and ticket release wake callers.
   Only a valid pre-drain ticket may make its one reservation after drain.
   Used/returned/foreign tickets cannot allocate. The queue is not persistent
   and cannot revive a generation on restart. Zero-value admission gates retain
   their closed state and can be opened/drained without a nil-channel panic.
7. Manager/gate critical sections do bounded in-memory work only. No disk I/O,
   driver calls or waits under the global manager lock. Stop and Cleanup never
   need a creation/Prepare permit. New queue gauges remain fixed-cardinality,
   lock-free observations, not a transactional snapshot or reclaim certificate.

## Overload and idempotency

The existing 429 `TENANT_QUOTA` can now also mean the tenant's one pending
distinct-intent bound, even when its live instance count is below its VM quota.
Wire code/message compatibility is retained; the response is not a count of
live VMs. Node/class exhaustion remains ordinary 503 `UNAVAILABLE`.

Core requests refused **before** reservation expose no Ref and consume no Core
key/record; later reuse can be accepted. An already accepted key still replays
or conflicts by the existing rules before queue admission.

Session Open is different: its initial intent/key may already be durable before
Core capacity is requested. Only an **exact** Core capacity sentinel with no
captured Ref/fence/cancellation is eligible for an overload reply. CLOSED/FAILED
must commit first; that session key remains permanent/gone, not retryable as a
new session. Uncertain/failed closed persistence returns SESSION_UNAVAILABLE.
Wrapped or compound errors, backend capacity errors after allocation, cancelled,
fenced or already-closed attempts never masquerade as ordinary overload.

## Test and acceptance boundaries

The new two-round control uses real Manager calls with memory-only store/driver:
two tenants' raw bursts, another managed caller, and two sequential managed
reservations. It checks the existing FIFO, early distinct-intent rejection, no
resource charge on refusal, and old-generation READY until replacement READY.
Other controls cover concurrent keyed replay, empty/different-spec/capability
non-equivalence, key reuse after unallocated cancellation, drain/tickets/Close,
shared deadline, and **real local FileStore** durable-release and CLOSED-error
barriers. Mock filesystems and generated results are not KVM or power-loss data.

This does not prove fair throughput, a faster physical create, completion inside
the original 35-second actor, or a successful 40-minute run. Every old sustained
load failure remains failed. No test adjusts the offered clock/rates/workers,
N=4/Prepare=1, asset bytes, resource/IO/TTL/history limits, error allowlist,
100-tail requirement, synchronized checkpoint or original-disk cold recovery.

**Do not run this candidate on the shared V100 yet.** Its ordinary daemon has
changed; the existing whole-ELF/probe pins and old KVM reports are not a certificate
for it. Exact new Linux build/ABI binding, compatible guarded load adapter,
independent owned-domain/neighbor/Stop/reclaim checks and a fresh host preflight
must precede any bounded KVM escalation. The PR #23 long-load harness is not part
of this isolated port. Do not disable pins, substitute the old daemon, claim
old results for the new source, or treat shorter diagnostics as the full pass.

The private parallel-copy candidate and its separate one-comparison permission
are untouched. No merge, production deployment or new public version follows
from software controls or a green CI run.

## Fixed probe prequalification

The [new fixed prepare-probe binding](P0_PROBE_BINDING.md) uses independently byte-matched native/cross input and bounded static review. Notification fault observers retain a separate old pin; parser/file controls do not certify live ABI, Stop/reclaim, sustained load or production readiness.
