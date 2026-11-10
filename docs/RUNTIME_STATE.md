# Original state lease and read-only core inventory

Status: **internal, incomplete coordinator component, not a public updater**.
No production command currently executes this sequence. Software/model tests do
not qualify real systemd/KVM, task completion, complete reclaim, activation,
upgrade/rollback, reboot/power loss or sustained load.

## Original lock ownership, not a stopped boolean

The installer's original operation OFD lease is separate from the daemon's
existing BSD `controller.lock`. New physical-stop intents are version 2: before
any effect, bind the original state-root and zero-byte, single-link 0600 lock
device/inode/change identity. Read the fixed kernel `/proc/locks` and require
the original pidfd-pinned main incarnation actually owns the complete exclusive
BSD lock on that exact file. Merely finding a current pathname, a contested lock
or any same-UID holder is insufficient: the daemon could retain an unlinked old
descriptor. The reader is bounded, permits no alternate proc root and fails
closed on unsupported/ambiguous observations. See the [kernel proc lock format](https://docs.kernel.org/filesystems/proc.html#proc-pid-fdinfo-fd-information-about-opened-file).

After the exact Stop receipt and **fresh** fixed manager/kernel absence proofs,
the same typed scope can acquire the existing original state lock using the
daemon's BSD nonblocking exclusive protocol. It never creates, truncates,
removes, replaces or breaks a lock, waits out a foreign holder, or constructs a
backend. Revalidate all original identities after acquisition and repeat the
physical-stop observations; retain the state FD and directory FD until the scope
closes. Lock order is original operation EX, then original state EX; file flocks
cover only on-disk records and never manager calls. Failures close only acquired
local descriptors. Scope close releases state ownership before operation ownership.

Version-1 stop records retain **only** their earlier physical-stop recovery
semantics. They cannot acquire this stronger state authority, are not silently
rewritten/upgraded, and still never authorize file selection. Device/inode/change
binding is not a portable backup or a reboot certificate; uncertainty refuses.

Version-3 Stop additionally requires the exact independently anchored known-work
completion link from [work-bound Stop](WORK_BOUND_STOP.md). It preserves the
original state/process identities and requires this link again on fresh state
acquisition; it never upgrades v1/v2 or interprets termination as work success.
The resulting state lease still does not certify full reclaim/activation.

## Core inventory is not full resource inventory

While both original leases are retained, an unexported reader parses admission,
ledger and session disk authority without invoking effectful constructors or
ordinary store loaders. Pure schema decoders reuse the original strict validators
and versions; there is no legacy migration, index publication, temp deletion,
directory sync, recovery rewrite or journal restoration. Reads can affect kernel
access-time accounting; no no-atime/media-forensics guarantee is made.

- Descriptor-anchored private directories and single-link 0600 record reads;
  bounded pages, per-file bytes and unchanged ordinary hard record ceilings.
  Check file identity/mode/size/mtime/ctime around reads and directory/link
  identity around traversal. Context cancellation returns no partial report.
- Unknown names, orphan temps, symlinks/hardlinks, invalid bytes/modes/versions,
  duplicate keys/identities, filename mismatch, non-Firecracker ledger records,
  foreign admission/epoch and inconsistent cross-tenant/generation joins refuse
  **without repairing or deleting any suffix**.
- Admission must still be the exact saved drained state and identity. Session
  current/history joins use the ordinary broker's immutable ledger ownership
  semantics. A failed target may legitimately lack ledger authority under those
  existing semantics; it is explicitly counted, never silently certified.
- Valid unfinished ledger/session records are classified, not changed to terminal.
  Even an empty or entirely terminal core report leaves successful-work,
  resources-reclaimed and activation flags **false**.

This reader does **not** enumerate all state-root authorities, backend owners,
shared catalog pins/backing, diagnostics, credentials or runtime resources. It
does not prove kernel project-quota zero usage/reservation release, exact jail/
cgroup removal, owner/UID/project release or successful accepted calls. The
state lock is advisory exclusion for cooperating ordinary writers, not a root
adversary boundary or a transferable durable resource certificate.

The separate [stopped-backend reader](RUNTIME_BACKEND.md) now reuses this leased
core with a complete byte-set binding for owner/namespace/project joins. It does
not promote this core report to full reclaim or enable snapshot policy.

## Evidence limits and missing integration

Tests use actual original BSD locks, live lock-holder observations, pidfds,
private Unix admission CAS and strict real persisted schemas/cross-record joins.
Positive manager/image/placement/cgroup proofs are still explicit private models;
the production entry refuses those fake domains. Known parent-owned Go test
children only; no shared-host service/VM, privileged quota operation, backend
constructor, offered load or deployment. An actual coordinator self-SIGKILL while
holding state ownership exercises kernel descriptor release and fresh-scope
reacquisition, not a real host crash or durable media guarantee.

Next: complete all-authority readers and backend/owner/catalog/quota joins;
actual accepted-work policy and maintenance exclusion; independent full reclaim
before immutable file selection; source-bound candidate/retained compatibility;
held-PID cap0 health/activation; prior-admission/ingress restoration and failure/
reboot state-preserving rollback; staging and guarded owned-L1 qualification.
All startup/maintenance fences and raw file-selection refusals remain. Original
long-load failures, unexplained metadata exit and all budgets/assets/benefit/
offered-clock requirements remain unchanged. Full production Goal is incomplete.
