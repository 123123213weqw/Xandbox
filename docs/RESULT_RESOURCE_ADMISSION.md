# Explicit retained-result resource admission

Status: **runtime-budget foundation; full installed updater remains incomplete**.
This change protects the actual `sandboxd` and Firecracker constructor/manager
paths, not just a report. It does not enable retention on any host or change the
existing initial-install `Plan`, launch `Manifest`, tests or 25/20-minute caps.

## Actual opt-in and pre-effect checks

- Firecracker config **version 4** requires the existing complete node policy,
  quota/IO policy and a new `results` object. Its version is 1, with explicit
  `bytes`, `tenant_bytes`, and `records`. Bounds come from the **same ordinary
  `sandbox.ResultLimits` validator**: at most 1 GiB and 100,000 records; tenant
  bytes positive and no greater than the global limit. There is no new default,
  eviction, expiration, acknowledgement, migration or operator-envelope growth.
- Config versions 1–3 retain their original representation with **no results
  field**. They cannot authorize nonzero retained-result limits. Config-v4
  without a result policy, legacy policy with that field, or mismatched/disabled
  CLI limits refuse. Ordinary CLI defaults are normalized exactly as before;
  retention still requires explicit nonzero `-result-bytes`.
- For a Firecracker retention request, the actual daemon checks the complete
  policy **before auth/state/result constructors**. It then checks the actual
  loaded result reservations before `Bind` may recover a row, and again after
  binding, before any backend constructor. No over-budget record is erased or
  rewritten to make the smaller budget fit.
- `NewWithResultAdmission` repeats the exact result match on its **own freshly
  read config**, before asset checks, KVM, node/quota creation or binding. An
  earlier successful preflight cannot authorize a replaced policy. Legacy
  constructors pass disabled limits and cannot silently activate config-v4.
- The actual Firecracker driver exposes a memory-only result-admission check.
  `Manager.New` requires its real `FileResultStore`, checks actual loaded global
  and tenant reservations and matches immutable limits **before ledger Load**,
  then repeats after result Bind and before worker construction. Arbitrary store
  implementations, typed-nil/closed stores and imported over-budget data refuse
  on this backend. Existing mock drivers retain their separate test contracts;
  this is not a Firecracker-to-host/mock execution fallback.

## Reservation accounting, not a quota or wall-clock guarantee

Config-v4 charges additional planning margins **inside** the existing operator
controller memory, managed disk and inode ceilings:

- controller planning memory: `4 MiB + 16 KiB × result-record limit`;
- managed disk: `256 KiB + 2 × logical bytes + 2 × 64 KiB × record limit`;
- managed inodes: `4 + 2 × record limit`.

The file padding accounts conservatively for final and temporary files; the
existing node calculation additionally reserves the same managed disk/inodes
still free. Checked arithmetic is used. Insufficient controller/disk/inode
envelopes **reject**; none of their configured limits, IO settings, host reserve,
worker counts or test/acceptance caps are automatically increased. Legacy
reservations add zero and retain their original calculations.

These are conservative planning margins, not proof of unique RSS, filesystem
quota enforcement, physical media erasure, syscall deadlines or measured host
capacity. Result byte limits are pessimistic **logical reservations**, not raw
JSON lengths: small output files can still consume larger reserved capacity.
The current loaded-index check is not a complete disk/source/WAL/FD compatibility
or activation certificate. Complete current per-tenant byte/record/history/FD/IO
compatibility under the original stopped scope remains required for an updater.

## Closed legacy schemas and the remaining real installation work

The existing initial-install `Plan` and launch `Manifest` have explicit frozen
shape/serialization/differential tests. They are **not extended, repurposed or
bypassed**, and those tests are not weakened. The existing installed launcher
therefore still emits no result-retention flags and rejects the new backend
version; this commit does **not** claim that installed opt-in is complete.
A distinct versioned installed policy/manifest/transaction must compose this
actual admission path with current-state compatibility, same-FD handoff,
same-PID health, genesis and durable admission/ingress release, including
candidate-failure/reboot-safe rollback. Disabled startup's existing refusal of
an unexpected results namespace must remain intact. No automatic enablement or
legacy-data rewrite is permitted to bypass it.

Tests exercise actual owned result files and actual early daemon rejection;
node policy and inert-driver checks are software/memory checks, not KVM, real
quota, systemd deployment or shipping-ELF acceptance. Full current CI, original
native/KVM/long-load and shipping-ABI qualification remain incomplete. No host
has been configured or deployed by this work.
