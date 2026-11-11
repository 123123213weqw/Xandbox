# Ordinary-operation runtime namespace veto

Runtime upgrade remains **incomplete and unavailable as a public command**.
This change supplies a negative compatibility boundary, not a candidate reader
contract, activation right, rollback certificate or production-readiness claim.

## Refuse before ordinary effects

An interrupted/future runtime coordinator may leave state outside the original
installation directory. Checking only the original commit and policy does not
prove that this side state is absent. Ordinary install, reconcile, reconfigure,
policy recovery, pending-policy replacement and draft discard now veto **any**
`/etc` sibling starting with `xandbox-runtime` or `.xandbox-runtime`, including
future formats, empty directories, partial files, anchors and hidden scratches.
No content, version label, hash or caller report can bless such an entry.

The six installed-operation adapters retain the **same original OFD lease**
across their existing file/manager/ACK work. The veto runs after acquiring it,
before transaction effects. Rejection closes only that acquired descriptor.
Initial installation also checks before creating the install directory and
before the original fresh-root bootstrap may create its permanent lock, then
rechecks under its acquired original lease. All original bootstrap rules,
flock/OFD ordering, fresh self/source proofs and manager boundaries remain.

Startup, update inspection and status also refuse the reserved prefix. Startup
and inspection retain **all 13 original explicit path checks** in addition to
the new complete-parent prefix scan. Startup still uses its existing read-only
SH flock, not an operation lock that could deadlock its own maintenance owner.
Internal runtime recovery primitives keep their original private entry points;
this is not a new way to invoke them or remove any startup fence.

## Bounded, read-only observation

The scan opens `/etc` from the original root descriptor, never follows a link,
checks trusted directory metadata and reads at most 4,097 sibling names. More
than **4,096 siblings** is an explicit new scan-precondition failure, not absence.
This does not increase any existing record/directory/resource/IO or acceptance
limit. A large or uncertain host parent must remain refused; there is no override.
Sibling payloads are never opened (including FIFO/symlink targets), repaired,
deleted, renamed or normalized. The original parent is checked after the read
and against a fresh linked descriptor, excluding only access time. Errors,
parent replacement, changed metadata, a missing parent or cancellation refuse.
Kernel IO already in flight cannot be interrupted by a context deadline.

Cooperating runtime writers require the original exclusive operation/file
locks; a successful absence scan is **not** a portable permission after releasing
them. This is not global filesystem atomicity or a malicious-root boundary.

## Controls and remaining requirements

New Linux-only controls exercise all six real ordinary adapters against every
original side-state path plus future/raw-byte names, with unchanged owned trees
and zero manager/loader/advance/confirmation effects. They cover bootstrap,
original-lease lifetime, late publication before the veto, cancellation,
untrusted parents, entry types, exact scan-count boundaries and fresh concurrent
reads. Boundary lists are in-memory controls, not thousands of created files.
An independently retained pre-change reconfigure entry is compared with the
guarded entry on separate owned filesystem/model-manager installations. Its
outcome needs the current ordinary CI; these are not native systemd/KVM tests.
All old tests, repetitions, ordering, workflows and 25/20-minute caps stay intact.

The full solution still needs trusted source/candidate/retained-self executable
and format evidence, complete current byte/record/FD/IO budget compatibility,
typed original-FD consumer/handoff, same-PID health, genesis preservation,
durable prior-admission/ingress release and candidate-failure/reboot-safe rollback.
Unknown state is retained for that protocol, not converted into compatibility.
No new deployment, native KVM, long-load, reclaim, performance or release
qualification follows from a namespace veto or its software tests.
