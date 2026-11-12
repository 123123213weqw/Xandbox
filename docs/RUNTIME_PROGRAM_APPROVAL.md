# Original-scope program-byte approval

Status: **internal prerequisite; no public updater or execution permission**.
This component verifies an administrator's Ed25519 approval of exact program
bytes and binds a live observation to an authentic result-aware Stop scope.
It does not establish build/source provenance, executable ELF validity, reader
ABI, state-format/budget compatibility, health, file-selection permission,
activation, ingress release, reboot recovery or rollback safety. A signature,
report, version label or this observation alone must never authorize those acts.

## Explicit opt-in administrative trust

There is **no built-in key, TOFU, path/key override, signing command, automatic
provisioning or deployment**. Unconfigured installations refuse this new private
operation; existing ordinary interfaces and their runtime namespace veto remain
unchanged. No real host files or credentials are created by this change.

- Fixed authority file: `/etc/xandbox-artifact-authorities.json`, owned regular
  single-link file, mode `0600`, at most the existing `MaxPlan` (16,384 bytes).
- Fixed certificate directory: `/srv/xandbox-runtime-approvals`, trusted mode
  `0700`. Each requested certificate is an owned single-link `0600` regular file
  with the same byte ceiling. No symlink target is followed; nonregular
  records refuse before any payload read.
- Authority schema: version 1, nonzero epoch, 1–4 keys sorted by distinct key ID.
  A key ID is lowercase SHA-256 of its 32-byte public key. Public keys and
  64-byte signatures use exact canonical standard Base64.
- Certificate schema: version 1, signing key ID and a version-1 claim containing
  the **same current authority epoch** and exactly eight ordered role/size/SHA
  tuples: daemon, gateway, ingress, installer, launcher, node, ready, template.
  Each size retains the original runtime program ceiling of 64 MiB.
- The signature covers the literal domain
  `Xandbox runtime program approval v1\x00` followed by the claim's canonical
  `encoding/json` bytes plus one LF. Certificate filename is lowercase SHA-256
  of the canonical program tuple array plus LF, followed by `.json`.

All records must match their complete canonical struct encoding plus LF.
Unknown, duplicate, folded, reordered or alternate escaped fields, alternate
Base64, partial data, invalid lengths/epochs, untrusted keys and bad signatures
refuse. The standard [Ed25519 verifier](https://pkg.go.dev/crypto/ed25519#Verify)
is used only after exact public-key and signature length validation.

This authority is a **new explicit local administrator-controlled trust root**,
not an externally verified GitHub build attestation and not a malicious-root
boundary. The epoch comparison is not durable global anti-rollback. A future
upgrade protocol must pin its authority/certificate evidence before effects and
preserve authorized rollback/recovery semantics; it may not silently restore an
old key policy to get past revocation. No actual issuer/key policy is deployed
or recommended as already qualified by these software tests.

## Actual byte and descriptor verification

Inputs are nine original producer-owned file descriptors for the existing
runtime executable subset, not JSON paths or FD numbers. The sealed chroot
gateway copy must match the approved gateway size/hash. Missing/duplicate/
extra target paths, incorrect modes or sizes and divergent gateway copies
refuse. Protected backend programs and mutable configuration are not added to
the writable vector or approved by this component.

The trusted authority and signature are checked **before accessing program
descriptors**. Each original regular file is then fully hashed, exact-size
checked and stat-bound before/after, without seeking, duplicating, closing or
reopening its description. `io.SectionReader` uses the original file's ReaderAt;
source offsets are preserved. There is no hash/data pool or validation cache.
Each hash uses fresh scratch bounded by the unchanged 32-KiB selector. Existing
resource/IO/FD/acceptance caps are not increased: this new work must be charged
and qualified within them by the eventual complete consumer.

Authority/certificate files and linked parents are rechecked around bounded
reads and again after program IO; every original program FD is rechecked at the
tail. Record inode/ctime/hash and parent inode/type/mode/owner are retained for
live rechecks. Parent child counts/timestamps/sizes are not cross-stage pins
because the coordinator legitimately adds siblings; within each read all parent
metadata except access time must be stable. Sibling contents are not scanned or
repaired. Missing/uncertain records, changed bytes, links, modes, identities,
revocation or cancellation produce no partial evidence. In-flight kernel IO
cannot be interrupted by a context deadline; this is not global atomicity.

## Genuine original-scope join, not a serialized capability

`runtimeScope.approveRuntimePrograms` additionally requires a bounded context,
the authentic V2 actor/work/result-close/physical-Stop proof, its exact fresh
source/WAL/closure, original operation EX and **same retained BSD state FD**.
Original process absence is checked with the existing fixed pidfd tail. The
source/state/FD checks repeat after artifact IO with no injectable manager or
kernel callback after the tail starts. No cached report supplies those facts.

The returned private live object owns only metadata copies and borrows the
original program descriptors. `recheck` repeats signature, complete program-byte
and original-source/FD checks, then compares the initial record/descriptor pins.
Closing a borrowed FD or retiring the original scope invalidates it. JSON cannot
reconstruct it; there is no wire constructor or public invocation. Reopening a
new operation/state lock is not recovery of this observation.

It remains **program-byte approval only**. Nothing consumes it as permission to
call the raw file engine. That engine still refuses the result-Stop namespace
and retains its startup fence. Sealed-object/cold recovery requires a future
explicit protocol, not reuse of a closed-FD observation.

## Tests and remaining production chain

Software controls use ephemeral TEST keys and non-executable DATA files. They
cover independent signing/domain encodings, canonical/unknown/partial records,
key and epoch policy, byte mutations, exact descriptor offsets, bad record
refusal before source access, hard links/modes/types, same-content replacements,
revocation, legitimate sibling changes and fresh concurrent reads. One original
actor/Stop/same-FD lifecycle exercises the scoped join, metadata alias isolation,
serialized/foreign/forged proof refusal, revocation and scope retirement. Its
backend/kernel positives remain explicit models, not native KVM acceptance.
All original source files, tests, workflows, counts and 25/20-minute caps stay.

The final updater still needs actual trusted source/build/ABI evidence for
source/candidate/retained-self, complete current state and per-tenant byte/record/
FD/IO budget compatibility, typed same-FD file consumer/handoff, same-PID health,
genesis preservation, durable prior-admission/ingress release and candidate-
failure/reboot-safe rollback. Full current software/native/KVM/long-load and
shipping-ELF qualification are still required; approval does not replace them.
