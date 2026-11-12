# Serial installer verification scratch (experimental)

The existing `verifyTargetsAfterPolicy` file loop uses one private, lazily
allocated **32-KiB maximum** storage buffer per invocation, not one scratch
allocation per target. Its capacity is the **maximum original active slice
required by this private immutable file vector**, including the exact managed
policy override. An all-small vector no longer reserves a fixed 32 KiB. This
pure sizing step observes no filesystem state or caller callback and does not
validate a different transaction. Allocation still follows the first successful
seek, never precedes a fresh open or changes its error precedence.
It is zeroed and released on success and every early
error, before generated-file/inventory proofs or any later stage begins.
This is best-effort in-process cleanup, not forensic or physical media erasure.

This is storage reuse only. Every target still has a fresh anchored open and
type/owner/mode/link checks, a NEW SHA-256 state, the complete context-aware
`size+1` read, exact size/digest comparison and original `Sync`/close. The active
buffer slice uses the unchanged `hashScratchSize`, preserving the original
underlying read widths, cancellation and negative/overflow error behavior.
There is no global pool, hash/content cache, FD adoption, file read omission,
cross-callback validation reuse, change to disk bytes or resource/IO expansion.
The standalone `filesystem.verify`, `hashFile`, scratch selector and their
original pinned-oracle tests are unchanged.

The sole production caller remains behind the original file-list/root inventory
and managed-policy override guards. Original target order, first-error return,
override scope, generated-byte reconstruction and subsequent closed inventories
remain unchanged. No new validator, wire format, installer capability, authority
or execution path is introduced. A first small/error target can still reserve
the full 32 KiB if a later target requires it; this does not promise lower memory
in every individual error case. Even an independently used scratch with stale
sizing must perform the actual full read: it grows if needed, clears old storage
and never exceeds the original 32-KiB read ceiling. Production's complete-vector
maximum avoids that growth. Release also discards the private size reservation.

New Linux software controls compare the old serial verifier and pinned original
hash on actual owned files, error/cancel/overflow cases, retained-storage taint
and same-length changes, release/ownership, and the full V1/V2 shadow committed
verifier. Shadow programs/managers are MODELS, not systemd/KVM installation.

The allocation opportunity is source-derived, **not a measured hotspot,
speedup, deadline-fit or fix for the existing 20-minute/long-load failures**.
All previous failures remain failures; the CI outer 25-minute cap, Go race
20-minute timeout, old cases/repetitions/order/matrix and original host
resource/IO/acceptance limits remain fixed. New source needs its own ordinary
whole CI and original native gates; parser/static checks are not application
tests. No unchanged-source retry is justified by this change.

The complete result-capable installed transaction/producer/commit/startup,
immutable genesis and CURRENT managed-policy authority, trusted build/reader
ABI, current per-tenant reservations/records/history/FDIO, original-FD consumer /
handoff, same-PID health, durable admission/ingress release and reboot-safe
state-preserving rollback remain required. This optimization does not complete
or replace that chain, native KVM/long-load/shipping qualification or the full
production-readiness objective.
