# Managed policy v2 — explicit forward recovery candidate

**Experimental: native software regression passed; not production ready.**
This follows the source-bound [persistence/locking foundation](POLICY_RECOVERY_FOUNDATION.md).
That historical checkpoint did not expose a recovery command. The code now adds
one, but neither its earlier evidence nor any older ELF hardware report certifies
this workflow. Fresh root CLI/real TLS child/systemd/KVM/drain/cold/fault/cleanup
acceptance remains required. An uncommitted-candidate liveness gap also remains.

## Source-bound software evidence

The [new software record](validation/managed-policy-recovery-native-v3.json)
binds source `66dd051`, its archive/runner and all 21 actually rebuilt native
artifacts. Linux Go 1.27.3 full `-race -count=3`, vet, 18 meaningful focused
parents repeated three times, 17 returned-error cuts, 17 actual **test-process**
death cuts and eight prior-committed settlement cuts repeated three times passed.
The empty process-helper entry is excluded from that parent count. The unchanged
Linux Python harness suite passed 235 tests with zero skips. Darwin race/vet and
five cross/native byte-equal amd64 artifacts are separately bound. Manager, ACK,
installer advance and kernel-positive observations remain models as described
below; actual kernel fake-filesystem rejection is not a positive hardware proof.

A separate [opt-in PKI producer](../cmd/xandbox-managed-fixture/README.md) at
source `91c14c2` has its own [pure native tests and artifact record](validation/managed-policy-fixture-native-v1.json).
It prepares synthetic initial/short-lived/fresh recovery inputs; no root fixture
operation, interrupted real service or KVM acceptance is claimed by those tests.
Its test-only tag does not change the 21 runtime/foundation artifact sources.

## Fixed administrative operation

```text
xandbox-install recover-policy -plan PRIVATE_PLAN -expected-revision N -request-id NEW_REQUEST -supersedes-request-id PENDING_REQUEST
xandbox-install reconcile -request-id NEW_REQUEST
```

`N` is the **currently installed committed policy** revision, at least 2 and less
than uint64 max. Both IDs are distinct 32-lowercase-hex values; neither can reuse
the initial-install request. The superseded ID must identify the current pending
rotation (or its committed pending recovery), not an arbitrary historical request.
The original self-pinned installer, immutable base/config/backend authority and
all other installed targets must still match. This is not a v1 node conversion,
a binary/self upgrade, a backend migration, a task runner or a reset mechanism.

The closed `RotationPlan` remains `{version:1, policy:Asset}`. Its private SHA256-
pinned input is a full **Snapshot** at epoch `N+1`, not an envelope or a journal.
A newly admitted candidate must pass current-time TLS/key/backend-owner validation.
There is no force flag, service selection, alternate state root or host task argv.

Use ordinary `reconfigure` after a completed/ACKed policy whose intent was already
removed. The explicit maintenance operation is for an installed **pending** policy,
including one that never ACKed and has since expired. It may interrupt ingress.

## Bounded journal and ordering

One canonical `policy-recovery.json` (32 KiB maximum) binds the exact base/config/
initial anchors, old/new envelope hashes, predecessor Snapshot digest, source pin,
new/superseded request and previous typed rotation intent. It contains **no copied
Snapshot/certificate/key** and no recursive history. Its sole journal scratch is
`.policy-recovery.next`. The existing policy/intent scratch bounds do not expand.
The successor envelope adds an optional `superseded_request_id`; initial envelopes
and ordinary envelopes without that marker retain their original encoding.

1. Acquire operation **EX** on the original zero-byte installer `.lock`, then the
   ordinary file EX lock. Prove self/base/current pending authority and full
   immutable files; validate all recognized scratch bytes and the new candidate.
2. Persist the typed recovery declaration before stopping ingress. A future
   declaration fences predecessor startup and prevents ordinary installer
   mutations from bypassing the maintenance request.
3. Release file EX, retaining operation EX. Pin the unchanged active main process
   with a pidfd and exact manager observation; validate fixed unit fragments,
   drop-ins and enablement links. Stop **only ingress**, if needed, with the fixed
   administrative `--job-mode=ignore-dependencies stop xandbox-ingress.service`.
   Confirm it has no main PID and is inactive/failed, main is still unchanged,
   and the fixed ingress cgroup-v2 subtree is absent or reports `populated=0`
   and `frozen=0`. Manager inactivity alone is not a whole-subtree empty proof.
   This check is read-only and does not imply full resource reclamation.
4. Under file EX again, re-prove the declaration/files and durably advance the
   **currently installed predecessor** in the original gateway store. Existing
   state only: exact digest or +1 epoch, never bootstrap, reset, reuse or skip.
   The store's own EX lock also refuses a surviving supervisor.
5. This old-payload persistence check validates coherent crypto/backend ownership
   at the leaf's validity boundary, not current time. It never returns a serving
   Policy, opens a listener, seals a child descriptor or produces an ACK. All new
   admission and normal startup/child paths still use actual time.
6. Only after predecessor durability, sync/rename the newly valid successor into
   the fixed policy file. Replace the precise old rotation intent with its exact
   successor via anchored inode/hash CAS and a matching scratch prefix. Normal
   startup refuses the new-file/old-intent window, too.
7. Release file EX. Start **only ingress** using the existing fixed
   `--job-mode=ignore-requirements` start, then require exact real operator/child
   ACK facts. File publication, signal submission and a waiting response are not
   success. No main start/restart/stop, node resume or guest command is introduced.
8. Under file EX, re-prove base/full files/new bytes/current-time validity and ACK.
   Remove the matching recovery declaration **first**, sync, then the matching
   rotation intent and sync. Keep operation EX and the original main-incarnation
   proof through the final callback/receipt. Failure never implicitly restarts
   main or resumes a drained node; receipts still have `production_ready=false`.

The stop mode's dependency behavior is from the
[systemd v255 administrative job semantics](https://github.com/systemd/systemd/blob/v255/man/systemctl.xml).
The separate whole-subtree empty proof uses the [kernel cgroup-v2 population
semantics](https://docs.kernel.org/admin-guide/cgroup-v2.html#un-populated-notification);
a fake regular filesystem cannot stand in for that kernel observation.
It is limited here to explicit root recovery of one fixed unit, not ordinary
application dependency management. Actual owned-L1 behavior still needs testing.

## Exact retry and repeated committed failures

A complete candidate scratch or the installed successor permits source-independent
retry. A partial scratch/journal without candidate bytes still needs the pinned
original source; a metadata hash cannot invent a missing private key. The same
live operation may retain its already pinned candidate in bounded memory when the
source is removed during stop. Unknown records, links, modes, prefixes, changed
sources/requests and missing durable authority are never repaired or adopted.

`reconcile` observes a matching declaration under operation SH, drops SH, then
reacquires EX and re-proves everything; it does not upgrade while holding a file
lock. Older request IDs cannot act on the successor's recovery. A lost final
receipt uses the installed envelope's request/supersession/source metadata and
normal exact ACK reconciliation without an unnecessary second maintenance stop.

If a recovery's successor was committed but never ACKed, then expires, a later
explicit request can settle that predecessor without serving or ACKing it:
advance its current installed Snapshot durably, normalize its own pending intent,
remove the exact old declaration (not a success receipt), then declare/publish
the valid next epoch. Cuts during this settlement must remain recoverable. At
most one bounded recovery declaration exists, not an expanding snapshot chain.

## Evidence boundary and unfinished cases

The software tests exercise real anchored shadow-root files, sync/rename, OFD/
flock and test-process exits. Their installer manager, ACK and predecessor-store
advancement are **models**, including the separately labeled test marker used
across process death. The real gateway store is tested independently in package
`gateway`; that is not an end-to-end root maintenance proof. No production CLI flag, environment dispatch or RPC accepts an alternate
root, manager, ACK, advance or kernel-population observation.

A declared **uncommitted** candidate is not a consumed installed epoch. This
command intentionally does not turn such a declaration into permission to skip
or reuse durable state. In particular, a candidate that expires before publication
can still require a separately proven abort/supersession protocol. That protocol
is not implemented, so the broader recovery liveness requirement is unfinished.
The original production milestones, artifact requalification, persistent audit/
retention and saturation/SLO acceptance also remain open.

### Regression runner budget, not a production latency change

The first frozen-source regression at `9520e63` failed the Go test binary's
**cumulative default 10-minute alarm** at 600.038 seconds; the then-active old
rotation case had run for about 2 seconds. Its new focused matrix had passed in
109.298 seconds. The failed original is retained; it is not a passing qualification.
The expanded suite still runs all tests with `-race -count=3`. Its explicit finite
per-package test-runner budget is now 15 minutes, and the matrix CI job budget is
20 minutes. No test is removed, shard omitted, detector option relaxed or failure
hidden. These are software test-runner limits, not sandbox switch/Stop/GC SLOs;
no service resource limit, guest limit or owned-L1 runtime deadline was increased.


### Preserved second failure and the same-source harness correction

The next frozen run at `66dd051` passed the full installtxn race-three package in
608.055 seconds, but the overall run failed two Firecracker UDS test parents:
its private native-harness `TMPDIR` made actual socket paths 118–127 bytes long.
Linux's [Unix-socket pathname field](https://www.man7.org/linux/man-pages/man7/unix.7.html)
is 108 bytes. A controlled same-source probe of the same selected tests failed
with the long prefix and passed with the short prefix; originals and hashes are
retained in the new record. Subsequent stages and release builds did **not** run
in that failed invocation. It is not retagged as a passing qualification.

The final successful run used exactly the same source/archive with a shorter
private test `TMPDIR`, first repeated both affected parents three times, then
ran the entire unchanged matrix. No Unix endpoint became TCP, failing case was
skipped, race option weakened, runtime deadline/resource increased, or historical
hardware evidence re-signed. Three tagged-helper log basenames retained their
older runner-version suffix; the new proof binds their actual final runner and
hashes, not a nonexistent completed stage of the failed invocation.
