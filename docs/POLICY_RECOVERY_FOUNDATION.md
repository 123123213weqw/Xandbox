# Forward policy recovery — persistence and locking foundation only

**Experimental and incomplete. There is no expired-policy recovery command.**
The [managed v2 candidate](MANAGED_POLICY_NATIVE.md) still cannot supersede an
installed, never-ACKed policy after its certificate expires. This checkpoint
provides prerequisites, not a workaround, feature acceptance or production SLO.
Its [separate native record](validation/policy-recovery-foundation-v1.json) must
not replace the earlier managed-policy or hardware records.

## Existing-state persistence primitive

`openExistingPolicyState` opens the original private `gateway.lock` without
`O_CREAT`. Missing lock/identity/record, an interrupted bootstrap, changed binding,
nonempty or non-regular lock, hard links and symlinks fail closed. It never repairs
or bootstraps the directory. The ordinary supervisor opener retains its initial
bootstrap role; it now also rejects nonempty/special-mode locks early and opens
nonblocking so a foreign FIFO cannot hang the check.

The **private, unwired** `advancePolicyState` can confirm or advance an existing
high-water mark for epoch 2 or later, using the unchanged store's exact/+1 CAS.
It validates the bounded Snapshot, matching TLS private key, hostname/usage,
nonempty certificate validity interval and immutable backend credential owners.
For this persistence-only check, certificate validation uses the leaf's validity
boundary rather than wall-clock time. The result is discarded: no `Policy`,
listener, sealed descriptor, child message or ACK escapes this helper.

This is **not permission to serve an expired or future certificate**. All normal
startup, reload, child and new-candidate paths retain their actual-time checks;
none calls this helper. It is deliberately unexported and has no operational
caller. A future caller must first prove the exact currently installed committed
payload, installer base/self/full inventory, original lock and stopped ingress.
No state deletion, epoch skip/reuse, binding reset or credential revival is allowed.

## Whole-operation exclusion without a new lock file

The actual installer `Apply`, `Reconfigure` and `Reconcile` engine paths now hold
a shared **OFD byte-range lock** on the original zero-byte installation `.lock`
through file work **and** manager/ACK reconciliation. A future explicit maintenance
operation will need the exclusive form before stopping ingress. There is no such
operational exclusive caller yet.

This lock is separate from the original `flock` that protects file proofs:

1. Fresh installation may create the original lock only under the existing
   empty-directory bootstrap rules, then drops that bootstrap flock.
2. Acquire the operation OFD lock, then the ordinary file flock. Never upgrade an
   operation lock while holding a file flock.
3. Release the file flock before manager/start/ACK work, retaining the operation
   lock through final verification and receipt, or any error return.
4. Status, the capability-free startup verifier and gateway startup still use
   only their ordinary read-only flock. No new write capability or lock file is
   added to those readers.

The FD is `CLOEXEC`; each independent open owns its lock. Closing an unrelated
FD cannot release another operation's lock. Acquisition uses nonblocking bounded
context-aware retries and rechecks the original inode, mode, owner, single link
and zero size. Unsupported kernels fail closed, not back to POSIX process locks.

The primitive permits only explicit local filesystem types (ext4, XFS, tmpfs,
overlayfs and Btrfs). This list is **not** runtime/storage qualification; the
production deployment profile still needs its separate pinned ext4 acceptance.
NFS/SMB lock emulation is excluded because `flock` and `fcntl` may interact there.
See the [Linux flock manual](https://www.man7.org/linux/man-pages/man2/flock.2.html)
and [glibc OFD lock semantics](https://sourceware.org/glibc/manual/2.33/html_node/Open-File-Description-Locks.html).

## What this evidence does and does not show

Software tests use real Linux files, sync/rename, policy-store locks and OFD/flock
syscalls, including independent processes. Installer engines run against an
anchored **shadow root**, model artifacts/manager/ACK responses and synthetic PKI.
They do not run the root CLI, a real systemd service, a real TLS child or KVM.

Coverage includes expired and not-yet-valid certificate persistence without
weakening serving validation; missing/corrupt authority refusal without mutation;
valid orphan preservation on rejected admission/CAS (with successful collection
as a positive control); exact cold replay; before/after-commit test-process death;
four simultaneous shared-lock processes; killed shared/exclusive owners; no FD
inheritance across exec; inode replacement; cancellation; and the actual ordinary
engine scopes spanning manager/ACK callbacks while their read-only gate works.
These test-process deaths are not power cuts, partial writes or block-device faults.

## Remaining implementation and acceptance

A complete explicit maintenance workflow still has to:

- serialize against ordinary operations, pin the unchanged active main process,
  and stop/start **only ingress** without pulling in or resuming main/guests;
- journal the exact superseded request and source/base/config/old/new hashes;
- durably advance the **currently installed** predecessor before overwriting it,
  without exposing it to a serving child; publish only a newly valid successor;
- recover every publication/intent-update/ACK window, source loss and successive
  never-ACKed expired successors using bounded metadata, not an unbounded chain;
- distinguish an installed expired policy from an **uncommitted** expired candidate,
  which needs its own proven abort/supersession rule, not an epoch skip;
- obtain fresh owned-L1 root-CLI/TLS/KVM/drain/cold/fault/cleanup evidence with
  the new runtime artifacts. Earlier ELF reports cannot certify this checkpoint.

Until then, the operational liveness gap remains explicit. The public schema,
initial authority bytes and CLI command set are unchanged by this checkpoint.
