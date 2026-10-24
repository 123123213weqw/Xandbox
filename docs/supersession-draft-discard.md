# Hash-bound supersession draft discard (software-qualified, not hardware-qualified)

This narrowly scoped administrative operation addresses an unfinished
`.policy-supersession.next` when its original replacement source has been lost.
It does **not** discard a committed supersession declaration, roll back a policy,
repair lost authoritative files, or qualify Xandbox for production.

```text
xandbox-install discard-supersession-draft -expected-revision N -pending-request-id P -draft-sha256 H
```

Arguments have fixed order: positive canonical decimal `N` below uint64 max,
32 lowercase hex digits `P`, and 64 lowercase hex digits `H`. There are no root,
path, service, force, arbitrary command, source, or new-authority selectors.
The production entry requires the existing root Linux/systemd contract and
the installed installer ELF's self pin.

## Preconditions and ordering

1. Hold the **original** installation inode's operation OFD lock exclusively,
   then the ordinary installation flock. Validate the canonical initial commit,
   every immutable target/hash/mode, generated configuration, complete artifact
   inventories, and private directory ownership/modes. This is a special
   maintenance inventory view, not a weakened startup gate.
2. Installed policy must be exactly revision `N`. A canonical, base/config-bound
   **future ordinary rotation intent** must identify `P`, expect `N`, and bind
   the exact installed predecessor hash. No committed supersession or recovery
   record, other metadata scratch, or unknown entry is accepted. Proposal DATA
   `.policy.next` may be missing/opaque/partial but remains bounded, private,
   single-linked, and untouched. Neither original source is needed.
3. The named draft, if present, must be a private regular single-linked file,
   mode 0600, bounded by `MaxPolicySupersession`, and hash exactly `H`. Zero,
   partial, and complete **uncommitted** bytes confer no authority. Pin its inode
   and size. No opaque draft is decoded/adopted as policy authority.
4. Release the file flock, not the operation lock. Use the existing fixed
   ingress-maintenance manager: pin and recheck the active main PID via pidfd,
   stop **only** ingress, and require the actual whole ingress cgroup subtree to
   be absent or empty and unfrozen. Failure does not restart ingress.
5. Reacquire the file flock, repeat the full file/base/inventory/self proof and
   predecessor/intent/draft CAS. Confirm **existing** durable gateway revision
   `N` and snapshot digest under its original state lock. No bootstrap, advance,
   collection, listener, ACK, main restart, or admission resume is allowed.
6. Rehash the held draft, compare the pathname's inode/metadata, unlink **only**
   `.policy-supersession.next`, and fsync its directory. Revalidate current
   absence, unchanged policy/intent, and immutable inventory. Main must still
   be the same live process when maintenance returns. Ingress stays stopped.

As elsewhere, cooperative root operations obey the original locks. Hash/inode
rechecks detect tested replacements and same-inode mutations; they are not a
security boundary against an administrator who can arbitrarily rewrite trusted
root files after the final check, nor against storage rollback/media corruption.

## Why no new abort journal

No policy authority changes. Before unlink, a crash leaves the original future
intent (and possibly draft); after unlink, it leaves the **same future intent**.
That intent independently fences startup against the still-installed predecessor.
The operation never removes it, `.policy.next`, current policy, or a committed
declaration. A new replacement must still pass `replace-pending-policy` with
fresh valid material and consume only the unconsumed next epoch.

This avoids recursively introducing another partially written abort journal.
The result certifies **current state**, not a durable historic discard request:

- `draft_removed=true` only when this invocation unlinked the exact present hash.
- An absent retry must reprove all other preconditions and current gateway state;
  it reports `draft_removed=false`, even after a previous unlink-before-receipt
  crash. `requested_draft_sha256` is then a caller argument, **not** an attestation
  about missing historical bytes. Different requested hashes cannot prove a prior
  operation happened.
- `draft_absent=true` and `ingress_stopped=true` do not mean policy files committed,
  ingress activated, node admission resumed, or production readiness.

## Evidence boundary

The [software-only frozen proof](validation/supersession-draft-native-v2.json)
binds Go source `df679bb868f8fbab68b9b7563b9aee5824ea771e` and its exact
archive/runner/artifact hashes. Linux Go 1.27.3 completed the **entire same-process
whole-package `-race -count=3`** run (installtxn: 1076.307 seconds within the
unchanged 1200-second package alarm), vet, four opt-in fixture race suites x3,
CGO-free quota x3, and 261 root pure Python tests with zero skips. All 23 native
artifacts were actually rebuilt; only `xandbox-install` and `installtxn.test`
changed bytes versus the prior material-qualified artifacts. Seven independent
amd64 cross-builds match native bytes; two arm64 cross-builds are compile-only.
macOS separately completed the default full race x3 and vet.

Ten meaningful new focused parents pass x3 within that full invocation. One
empty process helper is excluded from the meaningful count. Shadow-root tests
cover source-free empty/partial/opaque/complete drafts,
refusals, exact CAS, stopped-ingress revalidation, original-lock exclusion,
returned errors, and actual **test-process** exits at five boundaries. Manager,
kernel emptiness and durable-state confirmation are modeled there. These are not
root CLI/systemd/TLS/KVM or physical power-loss evidence. The first native
attempt's negative-control setup omitted a mandatory readiness callback and
failed before reaching the discard operation. Its failed original is preserved;
the fixture was corrected, not the production path or runtime limits. That
failed attempt is not counted as acceptance.

**Owned-L1 qualification of this new production operation is still required.**
Older runtime binaries and named hardware-case reports do not qualify it. There
is no new switch/Stop/reclaim runtime latency claim or production readiness.
