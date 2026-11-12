# Original state-owner proof: FD-bound candidate, not release qualification

This is an unmerged P0 candidate. A real original-node run on its predecessor
rejected two otherwise-matching global lock rows with different display
ordinals before an intended fault cut. A later independent PSI protection
stopped that run. Neither observation establishes the cause of this or earlier
missing/ambiguous rows, and green CI cannot replace original-node/KVM/long-load
acceptance. Historic failed results remain failed.

## Why change the positive source

A whole-system `/proc/locks` read can span sequence iterations; its displayed
ordinal is not a stable lock-object identity. Counting that observation is not
an atomic ownership snapshot. The candidate does **not** deduplicate those rows,
accept the first matching row, retry a rejection, or call a different source as
an acceptance fallback. Positive authority now requires an independently bound
**single process FD and single FD-local kernel lock row**, before Stop intent or
signals, with all original source/manager/drain/state/operation checks retained.

The pinned [Linux v6.8 FD reporter](https://github.com/torvalds/linux/blob/v6.8/fs/proc/fd.c)
retains one file object while producing its FD information. Its
[lock reporter](https://github.com/torvalds/linux/blob/v6.8/fs/locks.c)
filters by the file description and serializes the associated inode lock lists.
These are reference implementation facts, not proof of the original node's
running kernel or a diagnosis of a historic failure. See also the official
[FD information documentation](https://docs.kernel.org/filesystems/proc.html#proc-pid-fdinfo-fd-information-about-opened-file).

## Mandatory positive evidence

1. Open the existing pidfd watch **before** reading process metadata; require the
   exact original PID/boot/start incarnation. Never select another process.
2. Freshly open and verify the original state directory and controller.lock,
   including original device/inode/ctime, owner, mode, size and link count.
   Keep this inode FD open throughout the kernel observation, rather than
   retaining only a scalar identity that could later be reused.
3. Open PID, `fd` and `fdinfo` directories through directory FDs with no-follow;
   require actual procfs. Read at most **4,097** names and reject more than
   **4,096**. Validate the entire canonical, unique numeric name list, without
   truncation. No discovery or authority cache exists across calls.
4. Stat FD referents, never open/duplicate/signal or flock the daemon's target
   FD. Require exactly one matching original device/inode and full metadata;
   **multiple matching FD aliases also refuse**, even if they share a lock.
   An unrelated disappearing directory entry supplies no witness. Other stat
   errors refuse; a selected FD's subsequent disappearance also refuses.
5. Read only its no-follow, procfs-verified FD information, capped at **4,096
   bytes** (one extra byte detects overflow). Require the closed four regular
   file headers and exactly one lock row. Header inode must equal the pinned
   original. Apply the unchanged original BSD `FLOCK ADVISORY WRITE`, exact PID,
   device/inode and `0 EOF` predicate to that row. Open/read/shared/POSIX/OFD,
   malformed, duplicate and foreign observations confer no positive authority.
6. Restat the same selected descriptor, check the still-open original pidfd is
   live, and reverify the held original state path/metadata. Caller cancellation
   remains an error. No positive observation is cached for a subsequent poll.

## Keep the original negative veto — FD-only is insufficient

FD-local reporting does not enumerate global blocked requests. An early,
unpublished FD-only implementation was therefore rejected during source review.
The candidate **also retains the fresh original bounded 4 MiB global read** and
every original per-row format/device/type/waiter/foreign-owner check. Any read,
size, malformed or matching-inode foreign/blocked observation refuses, even when
the FD witness was valid. Only the old global **cardinality inference** is
retired: a nil negative veto never proves ownership, with zero, one or repeated
matching global rows. The mandatory positive evidence comes from the single
FD-local row, not from counting/deduplicating the global view.

The old global owner parser and its independent historic oracle remain unchanged
and tested. The negative-only parser copies the original per-row predicates;
differential controls preserve every original rejection except the explicitly
retired global missing/ambiguous cardinality result. It is private and cannot
be used alone to authorize Stop. Actual blocked-waiter tests must still refuse
before Stop namespace, manager jobs or state changes.

## Accounting and compatibility

This is an intentional kernel proof-source redesign, **not** an IO-equivalent
pure optimization. Each call adds a held state lease, bounded FD-directory and
referent metadata discovery, one bounded FD information read, selected-FD and
state rechecks; it retains the original global read and pidfd lifetime. It opens
no extra target handle in the daemon and modifies no host/process/file setting.
The existing private deterministic fault seam includes one new
`runtime-state-fd-after-observation` cut before final liveness/path checks; there
is no public flag, alternate proc root or bypass constructor.

The closed FD format, permissions, procfs support, descriptor bounds and real
kernel reporting must be checked on each supported environment. Unsupported or
uncertain cases fail closed; no sudo, permission change, older proof fallback or
silent format downgrade is attempted. Excess descriptor aliases intentionally
refuse. These limits are not claimed to fit every production workload yet.
On-disk Stop v1/v2/v3/v4 bytes and all other intent, effect, receipt, recovery,
compatibility and activation rules are unchanged. This is not permission to
restore an incompatible installer, release admission or activate files.

New portable grammar/ceiling/discovery controls, old per-row oracle controls,
real private TEST-child exclusive/unlocked/shared/POSIX/OFD/foreign/duplicate/
dead/incarnation/path/metadata negatives, post-observation path/death/error cuts,
and actual Stop no-effect/waiter cases supplement every old test. Existing full
race x3 and dedicated Linux gates remain, without dropping or substituting any
case. Compilation/macOS checks alone do not execute the Linux cases. Full
original-node software gate, resource joins, compatible activation/release/
rollback, owned real KVM and ORIGINAL long-load acceptance remain mandatory.
