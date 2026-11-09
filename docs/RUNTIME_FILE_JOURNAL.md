# Internal fenced runtime-file transaction core

Status: **incomplete internal coordinator component, no public updater command**.
No production entry calls `runtimeFileExchange`. No compatibility, actual
service drain, guest Stop/reclaim, activation, health, installation, KVM,
power-cut or production-readiness claim follows from its software tests.

This component implements real file staging/selection, monotonic persistent
CAS, retained-image rollback and fresh-handle recovery. It is not another
read-only inventory result. Its writes and abrupt-child-death tests run only
inside anchored, test-owned shadow filesystems. Never invoke the internal
primitive against a real installation in place of the missing coordinator.

## Preserve genesis, not a restored installation snapshot

The existing managed gateway binds its policy chain to the **complete original
installation commit bytes**. Replacing `commit.json` with a new runtime manifest
would invalidate that base binding. Restoring an old commit/policy/key snapshot
to make rollback start would rewind authority, not solve that problem.

The file engine therefore never rewrites the genesis commit. Its separate
`/etc/xandbox-runtime-files` state pins the exact canonical genesis SHA, selected
immutable file vector, retained previous vector, request/input SHA and monotonic
revision. Each successful forward or rollback selection adds a revision;
rollback selects only the immediate retained vector, not caller-supplied bytes
or an earlier authority revision. Exact last-request retries are stable;
unrelated stale requests and revision overflow refuse. Forward selection
reserves the final revision for a possible retained-image rollback.
Surviving payload objects with neither an intent nor head are lost authority,
not a fresh revision zero—even if the binary vector again matches genesis and
the startup fence has also disappeared. The engine refuses this counter loss
without recreating it. This is not recovery from total storage destruction or
protection against a malicious privileged owner.

The fixed writable vector has 14 paths: seven non-backend runtime programs,
the installer executable, the chroot gateway copy, three generated
launch/ingress/readiness files and the two service units. Caller-selected paths,
duplicates, modes or unbounded images refuse. The original six backend assets,
backend config, auth/PKI/policy, genesis, ledger/session/node/catalog/owner/quota
state are **not writable**. Actual qualified descriptor/render/static-ELF
construction remains the future adapter's responsibility: a permitted path
and byte hash alone are not semantic compatibility.

## Ordering and recovery

1. Acquire the **original** installer operation OFD EX lock, then its original
   file EX lock. No new/recreated/replaced permanent lock is accepted. Read and
   validate genesis, protected installed files and the current managed policy
   under that unchanged base. Other pending install/policy operations refuse.
2. An internal stopped-observation boundary must succeed before any journal
   work. This is not a CLI boolean/override; its current tests use a model,
   **not** a real manager or quiescence proof.
3. Persist the exact intent. Seal and sync complete old and new immutable
   payloads into bounded content-addressed objects **before** changing any
   final target. Shared bytes are deduplicated. Prefix recovery may still need
   the producer before sealing; after the first final swap, all required old
   and new bytes must already be retained independently of that producer.
4. Persist a matching `runtime-files-pending.json` startup fence in the original
   install root. The existing legacy installer rejects this unknown inventory,
   including at startup. Repeat the stopped boundary and protected/base proof.
5. For each changed target, verify the original bounded inode/bytes, seal a
   same-directory scratch from the retained object, recheck the old path, rename
   and sync its parent. Mixed old/new images are recoverable **only while
   fenced**, never represented as an atomically running service set.
6. Reverify every selected image, genesis and protected files, then atomically
   persist/sync the next CAS head. Only known superseded objects, independently
   hash-verified and no longer referenced by current/retained vectors, may be
   reclaimed. At most current + retained + one in-flight candidate is admitted.
   A crash during this reclaim retains the intent for exact recovery.
7. Retire only the matching file intent after the head and file effects are
   durable. **Keep the startup fence.** Even a successful retained-image
   rollback reports `StartupBlocked=true` and `ActivationAllowed=false`.

Unknown state, scratch, objects, wrong hashes/modes/inodes, producer drift,
genesis changes, failed stopped observations, conflicting intents or uncertain
persistence refuse without deleting/blessing the discrepancy. A failed write
does not become a success receipt. A fresh descriptor can resume the same
request after actual test-child SIGKILL; this does not prove media power-loss
behavior or allow resuming service on a mixed file set.

## Evidence scope

Controls exercise real shadow-file fsync/rename/locking, forward/rollback/retry,
stale CAS, permanent-lock loss/wait cancellation, protected and mutable byte
preservation, current/retained object bounds and interrupted third-version
reclaim. A valid forward managed-policy envelope is retained through binary
rollback with the same genesis base and advanced key epoch; that fixture models
ACK removal, not an actual frontend ACK or PKI deployment.

Named error cuts cover intent, complete object sets, startup fence, three
different target swaps, head and intent removal. Six additional actual
self-SIGKILL cuts bypass Go defers; the parent requires a signaled SIGKILL exit,
not a fabricated error or `os.Exit(137)`, then reopens a fresh anchored root.
These are selected software boundaries, **not** exhaustive filesystem fault,
hardware reboot, unknown-PID termination, VM-abort or guest workload tests.
No model runtime bytes or test hook/FD-root selector is a production artifact.

## Missing integration — do not remove the fence

The current installed self pin and generated startup verifiers still bind the
original immutable targets. A real forward activation needs a **strict,
genesis-preserving runtime overlay/self-pin verifier**, not rewriting genesis
or allowing arbitrary file/hash overrides. It must preserve managed policy's
old base while verifying the selected runtime vector and its generated config.
Rolling back a daemon must not roll back the policy chain or credentials.

Also required: source-bound **all-authority** backward-reader compatibility;
persistent admission drain; observed accepted-work completion and independent
full execution-domain/owner/quota reclaim; real manager and held-PID identity;
safe ingress/admission restoration; bounded staging/headroom accounting;
interrupted/reboot recovery and failure-triggered state-preserving rollback in
an owned L1. Only then can a public executor and explicit fence-finalization
operation be considered. The file core deliberately contains **no** such
finalization function and starts no services or candidate program.

PR #29 remains read-only inventory. PR #28's fixed terminal Mock-reader test
does not prove those missing authorities, fix its earlier unexplained exit, or
qualify the original sustained-load gate. All original failed long-load runs,
resource/asset/IO ceilings and the 35-second actor/40-minute offered clock,
rates/workers, N=4/Prepare=1, 100 tails and sync/cold requirements remain.
