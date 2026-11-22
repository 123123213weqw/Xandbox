# Read-only runtime update inventory

Status: **experimental software prerequisite, not an upgrade or rollback
executor**. No new release, live installation, Linux/KVM qualification or
production-readiness claim follows from this command.

The initial installer cannot select a new runtime. Before a future transition
can be designed safely, distinguish the installed bytes from the publisher's
current candidate and retain the **actual installed release**, not just any
previous version. `xandbox-install inspect-update` connects those existing
authorities without changing either one.

## Fixed command and private pins

From a trusted build, outside the installed self-pinned executable path:

```text
xandbox-install inspect-update -plan PRIVATE_INSPECTION_PLAN
```

Do **not** replace `/usr/libexec/xandbox-install` just to run the new command.
The inspecting binary need not equal the installed installer: it performs no
mutation or service-manager action. The installed installer file is still
verified against its original commit. No candidate binary is executed, even
for a version/health query. Linux root and the existing local systemd/installer
layout are required; unsupported platforms refuse.

The root-owned, private, bounded regular-file plan uses
`installtxn.UpdateInspectionPlan`, version 1:

| Field | Required meaning |
| --- | --- |
| `install_commit_sha256` | Exact canonical current `commit.json` bytes |
| `release_revision` | Exact current publication revision, at least 2 |
| `candidate_release` | Publisher's current candidate descriptor digest |
| `retained_release` | Publisher's previous digest, equal to the installed release |
| `policy_revision`, `policy_sha256` | Exact current managed policy envelope, or 0/empty for v1 installation |

There is no latest, force, unit/target selector, state-backup path, automatic pin
discovery or compatibility override. Unknown/duplicate fields, unbound policy
revisions, equal current/candidate releases and revision overflow are refused.
Obtain private pins independently under the existing operator procedure; this
is not a credential-distribution mechanism.

## Actual checks and lock scope

1. Acquire the **original existing** installer OFD operation SH lock, then its
   file SH lock. No lock is created, truncated, replaced or unlinked. Exclusive
   maintenance and ordinary install/policy commits cannot race these
   observations. Cancellation refuses; no lock fallback exists.
2. Check the exact installation commit, original 25/v1 or 24/v2 targets,
   generated units/manifests, closed immutable inventories and current policy
   pin. Any initial/policy/recovery/supersession intent, scratch, unknown file or
   byte/mode/ownership drift refuses. Do not reconcile, delete a journal or
   restore an older policy to make inspection pass.
3. Hold the publisher's **original existing** EX lock using the ordinary
   release consumer. Verify both complete retained bundles, descriptors, object
   inventory, ownership/modes, exact lengths/hashes, native static ELF rules and
   128 MiB workspace requirement. Require the candidate to be its current
   reference and the installed release to be its retained previous reference
   at the exact revision. No candidate/source is extracted or run.
4. Count changed roles, separately identifying the six backend-config-bound
   asset roles (VMM, jailer, warden, kernel, initrd, workspace). Recheck the
   installed bytes/commit/current policy while both authorities remain locked.
   Return a closed result, then release locks.

The fixed ten-minute caller deadline includes lock waits and byte hashing.
Hashing reads bounded full artifacts and may take time; kernel I/O can block,
and a context deadline is not I/O-preemption or a shared-host safety guarantee.
No privileged inspection is run on a shared node by the software tests.

## What the result does NOT prove

Success reports `installed_files_verified`, `candidate_release_verified` and
`current_release_retained`, plus bounded changed-artifact counts. It omits all
private hashes/paths, request IDs, credentials and raw manager output. Failure
returns no partial-success object. These remain **false** on success:

- `compatibility_proven`: version labels or unchanged backend assets do not
  prove a binary's backward-reader/schema/protocol compatibility;
- `drain_reclaim_proven`: no admission drain, accepted-work observation, guest
  Stop, owner/quota/domain inventory or full reclamation is performed;
- `activation_allowed`: no durable runtime transition intent/CAS, binary
  switch, PID verification, readiness, retry/reboot or rollback exists here;
- `services_changed`, `state_changed`, `production_ready`.

Mutable ledger/session/node/owner/catalog/runtime-policy authority is not read
as a consistent snapshot, frozen, reset, restored, copied or replaced. A live
service can continue changing it. The result is a point-in-time artifact
observation, **not** a receipt a later executor can reuse instead of reacquiring
locks and re-proving every prerequisite. Zero changed artifacts would not
authorize rewinding authority history either.

## Evidence and next implementation

Policy/CLI controls run on every platform. Linux software controls use anchored
test-owned shadow files and the real release reader, structural ELF **data**,
two complete workspace hashes, corrupt candidate/retained/installed bytes,
stale pins, pending/scratch records, permanent-lock absence, bounded lock
cancellation and managed-policy rotation. They verify no persistence helper,
manager action, authority-file change or lock replacement. They are not a live
systemd transition, functional VMM, native/cross equality or hardware test.

The remaining executor must add source-bound compatibility contracts and real
backward-reader tests; persistent drain plus independent full reclaim; durable
monotonic CAS/intent and exact retries; safe multi-file activation and same-PID
health verification; failure/interruption/reboot recovery and **state-preserving**
rollback drills in an owned L1. Never make rollback work by restoring an old
ledger/policy or weakening the initial installer's commit gate. Until then,
retain the existing installation and use separate owned environments only.
