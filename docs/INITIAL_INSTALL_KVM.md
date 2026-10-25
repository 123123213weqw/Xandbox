# Ordinary initial installer: limited real systemd/TLS/KVM/cold qualification

[Evidence](validation/initial-install-kvm-v1.json) binds harness source
`0ff735aa6d6d1da91e2d5745377530d7f24d7d37` to new ordinary installer source
`921b3107467b94cfff0c76afd3032c2d3450a7ee`, not an inherited publisher or manually
preinstalled service report. **Production readiness remains false.**

## What actually ran

The opt-in `--install-assets` profile starts from the basic owned Ubuntu/systemd
image, not a deployment/readiness profile with preinstalled ordinary units. It
retains the existing 16 GiB/12-vCPU/24-GiB-disk resource specification, bounded
outer lease, no guest NIC, pinned kernel/QEMU and identity-owned cleanup. A tagged
TEST ONLY PKI helper creates ephemeral CA/leaf/credentials inside L1; it is not a
production key-distribution service. Raw console, requests, tokens, keys, VM
identities, manifests and storage UUIDs remain private.

- Actual `xandbox-release` publishes the real thirteen pinned bundle roles.
  Actual root `xandbox-install` validates and materializes the fixed 25 targets.
  Nonroot reaches the real executable and gets the closed CLI refusal; bad source
  pins and stale publication revision refuse without a candidate unit.
- A TEST ONLY parent traces **its own** ordinary installer child. At the exact
  `.commit.next` openat entry it verifies the child executable and directory FD,
  kills that installer and reaps its threads. There is no production hook,
  alternate-root flag, arbitrary process attach or host task-execution route.
- The real candidate main unit is already guarded, intent exists, commit/scratch
  do not. While the independent operator holds the original install lock, a real
  manager start runs the production pre-gate. Only after its lock FD is observed
  does the observer require the exact installer ELF, sole `.control` Tgid and
  **all observed Go threads NNP1/caps0**. Releasing the lock produces a failed
  start before the ordinary daemon or any backend binding/state file.
- The same request recovers, commits and reconciles without reset-failed, repair,
  restart or implicit node resume. A different request conflicts. Exact retry
  and read-only status use closed receipts with production_ready false.
- The declared original asset/config sources and bootstrap executable are removed
  by exact names. The installed executable reconciles without those paths and
  does not restart existing service incarnations. Private observer snapshots are
  separate byte-exact copies, not a production backup/reconfiguration mechanism.
- Four simultaneous real guests cross authenticated TLS and the ordinary UDS/
  vsock path. Actual guest UID/boot, pinned VMM ELF, reserved UID, capability/NNP/
  seccomp state and live kernel project limits are checked. Tenant/node/auth
  refusals are exercised. STOPPED still refuses a fifth allocation before DELETE;
  durable reclaim separately waits for exact resources and quota release.
- A real managed session and writer cross ACK drain; raw/session/switch admission
  denies without metadata growth while old execution and Stop/GC continue.
  Exact operator CAS/retry, healthy automatic manager restart while drained and
  explicit resume are checked. Installation reconciliation does not open admission.
- A fresh live guest is checkpointed drained. Original disk cold boot preserves
  the full control commit, immutable install files, missing source paths and
  machine ID while changing boot ID. Both ordinary services become ready without
  operator activation. Old assigned guest/key handling, explicit root resume,
  fresh raw/session pristine guests, all four projects zero and clean manager
  teardown are checked.

The two-ready-boot result passed all mandatory typed fields and 139 negative
semantic verifier controls. Linux Python before hardware: 235 tests, zero skips.
Independent read-only audit confirmed both outer generations absent. A fresh
combined audit includes six failed hardware scopes plus the passing scope:
**7 scopes / 8 unique outer generations / 29 unique declared paths**, all absent
without supplemental cleanup. Two wrapper failures occurred before VM launch.

## Static PIE correction and native provenance

The actual pinned Firecracker and jailer are ET_DYN static PIE, without an ELF
interpreter or imported-library dynamic tag; both carry DF_1_PIE. The old generic
ET_EXEC consumer rejected Firecracker before intent. The production correction
is **role-bound**: only those VMM roles may be static PIE, with a file-backed
executable entry, native architecture, bounded/terminated PT_DYNAMIC and no
DT_NEEDED/RPATH/RUNPATH/audit/filter dependencies, even if section headers are
absent. The Go service/self ET_EXEC rules remain unchanged.

Actual pinned VMM bytes were inspected and parsed as **data** on the build host,
not executed or Rust-compiled there. New source passed Linux Go 1.27.3 full
race-count3/vet, role/dependency negatives, actual pinned-data parsing-count3,
existing persistence/process-contention tests, tagged helpers and CGO-free quota
controls. Native Python: 234 tests, zero skips. New installer/test amd64 native
and cross bytes match; arm64 cross builds passed. All fifteen prior artifacts
and two PKI fixture artifacts were actually rebuilt byte-equal; only installer/
its test changed. macOS full race-count3 passed; 235 Python tests have five
platform skips. None of this re-signs the earlier runtime reports.

## Measurements and boundaries

One sample observed STOPPED plus empty execution domain at **112.362 ms**, and
complete durable private reclaim at **592.642 ms** from the same stop-request
origin. These include TLS/HTTP and observer overhead; the second includes the
intervening capacity-refusal check, DELETE and quota/resource observation.
They are not pure kernel timings, installation speed, switch latency, a workload
speedup, physical media erasure, percentile estimates or a production SLO.

All failed originals remain bound to their own sources and reports. Early
failures exposed wrapper access/version-reference mistakes, incomplete trace/
console diagnostics and a ptrace exit race. One failure proves the old static-PIE
consumer incompatibility. The last failed observer checked executable identity
before waiting for the lock FD; its transient executable was not captured.
The final observer retains all exact identity/capability checks after lock-FD
readiness. No timeout, resource limit, dependency guard or runtime policy was
relaxed to obtain the passing result.

Still unfinished: installation filesystem D/EIO and full manager/crash matrix,
consistent auth/TLS reconfiguration (manual rotation invalidates this immutable
commit), upgrade/rollback/catalog/backup, reliable audit/retention, independent
operator reproduction, saturation, open-loop fairness and production SLOs. The
full original M1–M4 objective remains active; this is a named finite integration
qualification, not a production-ready release.
