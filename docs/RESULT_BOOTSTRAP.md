# Explicit result-enabled cold installation transaction

Status: implementation awaiting its own software/build-artifact and real
Linux/KVM qualification. **Prototype, not production-ready.** The published
version remains `v0.1.0-preview.1`; nothing is merged, released or deployed here.
Do not run this on the shared V100 merely because the commands now exist.

## Actual connected path

`xandbox-install` has explicit `apply-results`, `reconcile-results`,
`status-results` and cap-zero `verify-results` entry points. They use the
original fixed root/systemd composition, original installer flock and OFD
operation lease, pinned release store, fresh target reads/full hashes, bounded
same-PID readiness and managed gateway acknowledgement. There is no task argv,
shell, user-selected service, host-execution fallback or automatic deployment.
The CLI keeps the original ten-minute context; CI remains 25 minutes, whole
race 20 minutes, with every old case/repetition/order/matrix unchanged.

The input is the **unchanged managed Plan Version2**. Its backend asset SHA
already binds the complete immutable Config4, including the result policy.
No second result-policy authority is copied into the plan. The new committed
transaction is a distinct closed top-level **Version2** type with 24 targets;
legacy Version1 transaction readers and entry points still reject it. No
transaction/config is normalized to an older version to bypass a validator.
The shared pure file-inventory predicate retains every original constraint;
each versioned entry retains its own exact version/revision/request guard.

The actual producer freshly pins the original input/source FDs, requires cold
Config4 with complete node/quota/IO/result reservations, independently repeats
ordinary and result admission on the source, constructs `NewResultContract2`,
and hashes its exact JSON+LF into the real ingress and readiness manifests.
Original unit generators, parent/ingress/reserve/capacity envelopes, target
modes, order, source hashes, atomic intent/commit publication and directory sync
mechanics are retained. The main unit explicitly calls **`verify-results`**;
old `verify` is not relaxed or used as a fallback.

The new gateway base reader accepts a separate Version2/Plan2 cold genesis.
The actual gateway startup dispatcher selects either disjoint strict base
version. The legacy `ValidateManagedBase` body remains unchanged and rejects
the new version. This validates only the immutable gateway/policy base, NOT the
whole installation. The full versioned startup verifier remains mandatory.

## Same-source program build gate, not source attestation

Before materialization, the public producer validates eight actual original
source FDs. Every subsequent public startup/status/reconcile reopens installed
programs and repeats the join: installer, daemon, launcher, readiness, ingress,
gateway, node and template. The running SHA-pinned installer is the reference;
source paths or candidate JSON cannot choose a replacement reference.

Under an **independently trusted builder and operator release/self SHA pins**,
only same-revision, clean Git, CGO-free, static Linux SDK `go1.27.4` builds with
exact module/package/architecture identities are admitted. Dependency versions
and sums must belong to that executing installer's dependency set; replacements,
duplicate settings, race/tag/experiment builds and mismatches refuse. The
original FD's complete fresh checksum and before/after identity are independently
checked. Go metadata strings can be forged by a malicious builder: this gate is
NOT a cryptographic build attestation or a substitute for trusting/qualifying
the builder. It is NOT arbitrary-source/backward-reader ABI compatibility.

Metadata reads share the existing per-program **32-KiB** reader budget. ELF
header/name bounds are proved before parser allocations. Only one uncompressed
`.go.buildinfo` section, at most 16 KiB, is read; its inline strings and lengths
are bounded/canonical before the standard module-info parser is called. Pointer
formats, oversized/ambiguous sections or unknown framing refuse. No binary is
executed, no whole binary is loaded into memory, and no IO/cgroup/quota/test cap
is automatically enlarged. Full checksum passes still cost IO and may exhaust
an existing deadline; this is not a claim that delivery fits every budget.

A new required `linux-build` check reads the **eight existing amd64 CGO-free
SDK4 outputs** after the unchanged amd64/arm64 build loop, three times. It binds
the actual checkout revision (which may be a PR merge revision), not an invented
head or release attestation. Ordinary race runs explicitly skip only this NEW
artifact-dependent control when those outputs/pins are absent; they cannot
count that skip as artifact evidence. Existing tests are not skipped or reduced.
ARM64 remains build-only until its own reader/runtime evidence is obtained.

## Fresh only; preserve existing state and authority

The original initial inventory must prove empty mutable roots, no prior backend
binding, no unknown artifacts/execution domains or adopted services. Existing
legacy commits/bindings and every runtime side-journal namespace refuse. A
pending exact new request retries its own Version2 intent; conflicting requests
refuse. The original commit is never rewritten to rebless changed targets.
Manager/readiness/ACK failure remains unconfirmed; committed files and current
authority are preserved, not deleted or restored from an old snapshot.

Only the original initial request is supported by `reconcile-results`.
Separate explicit `reconfigure-results` / `reconcile-results-policy` now wire
managed one-file policy rotation and exact source-independent activation retry
for the actual Version2 commit; see [policy maintenance](RESULT_POLICY_MAINTENANCE.md).
Policy recovery/supersession, result-aware RUNTIME maintenance scope and
existing-state migration/rollback remain **not yet wired**. This policy path
does not select runtime files, acquire a stopped-state lease, migrate bindings,
or restore prior authority; it preserves the existing result/ledger state.
Legacy mutators still reject Version2. Cold install and policy maintenance do
not substitute for the remaining work or authorize evaluation on a shared host.

Existing Config3-to4 migration still requires an explicit FULL binding transition
under the **original retained state FD, operation scope and source WAL**, complete
current per-tenant bytes/reservations/count/history and FD/IO budgets, independently
trusted source/candidate/retained-self reader compatibility, crash-cut recovery,
same-FD handoff, same-PID health, durable prior admission and ingress release,
and state-preserving candidate-failure/reboot rollback. Do not delete config.json,
wipe result/ledger/history, restore old revocation state, serialize a legacy
structural projection or rewrite an existing gateway genesis/current key/TLS epoch.

## Evidence boundaries

New controls cover strict version separation, actual V2 byte pins/envelopes,
all 82 original initial-install persistence cuts with exact retry, owned shadow
startup/reconcile/reopened-root and failed ACK, refusal of existing state/program
gate bypass, bounded metadata and actual existing native build outputs. Shadow
program/manager callbacks are explicit **models**, not real executable approval,
systemd, original V2 actor, KVM, handoff, migration or rollback certificates.

The full current CI, native feature test, real KVM/install/reboot drills and the
original resource-guarded 40-minute load qualification remain required. All
previous failures remain failed. No CPU/IO cause, speedup, deadline-fit, stable-CI,
rollback-ready or production-ready claim is made by this implementation.
