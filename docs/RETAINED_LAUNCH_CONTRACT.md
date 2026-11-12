# Explicit retained-result launch contract (experimental)

The ordinary launcher, readiness gate and ingress launcher share a bounded
`launch.Contract`. V1 is exactly the existing `launch.Manifest`. V2 is a
**different envelope**, not extra fields or a changed interpretation of V1:

```json
{
  "version": 2,
  "launch": { "version": 1, "...": "the complete unchanged V1 node policy" },
  "results": { "version": 1, "bytes": 8388608, "tenant_bytes": 2097152, "records": 32 }
}
```

The illustrative `...` is NOT a valid field. The complete envelope, including a
producer's final LF, must fit the existing 16-KiB ceiling. Both branches retain
strict unknown/duplicate-field rejection. A V1 decoder rejects V2; there is no
automatic opt-in, default budget, arbitrary argv or mock/host execution fallback.

## Actual consumers

* `launch.Run` decodes the trusted file, verifies the original pinned assets,
  validates the actual backend and its admission limits, and checks the exact
  Config4 `ResultPolicy` match before group preparation. The shared group body
  receives the original Config4, not a downgraded configuration. Resource and IO
  envelopes, readbacks, privileges, inherited-FD rejection and same-PID exec stay
  unchanged. Only three explicit result-limit flags are added to ordinary argv.
* `serviceready.Run` independently decodes the hash-pinned node contract and
  matches its result policy against the pinned backend. Both pre/post health
  process proofs compare the **entire** actual `/proc/PID/cmdline` against the
  same contract's arguments. Old argv, missing flags, changed limits and extra
  arguments cannot pass that equality. Original pidfd, executable, placement,
  private state/socket, peer credential and bounded health checks remain.
* `ingresslaunch.Run` independently decodes the hash-pinned contract and checks
  the original gateway authority/socket, backend result policy and full separate
  ingress/node/operator-reserve composition. It retains its own fresh ordinary
  backend/admission validation and original privilege/exec boundaries.

`Contract.Node()` is only a copy of shared placement/asset/parent metadata. It is
NOT the V2 argv/backend contract. `Line()` produces candidate canonical bytes;
it does not attest original file bytes, update any pin or grant execution.
Structural composition is not current-state budget admission. The ordinary
daemon/constructor/Manager retain their independent fresh config and actual
imported global/per-tenant reservation/count checks described in
[RESULT_RESOURCE_ADMISSION.md](RESULT_RESOURCE_ADMISSION.md).

## Still required before installed opt-in, upgrade or rollback

This is an actual three-consumer wiring change, **not a completed installer**.
The initial Plan/transaction, renderer, commit/startup reconstruction and closed
state readers retain their old schemas and reject the new backend/launch form.
Do not replace only `launch.json` in an existing install: old verification must
fail rather than silently authorize a different committed composition.

A distinct versioned installer/transaction must generate and pin the exact V2
JSON+LF, update ingress/readiness pins coherently, and re-prove those same bytes
at commit and startup. It must join trusted source/candidate/retained-self build
and reader ABI, complete CURRENT per-tenant bytes/reservations/records/history
and FD/IO budgets, original state/WAL/FD authority, a typed file consumer and
same-FD handoff, same-PID health, genesis, durable prior admission/ingress release,
candidate failure and reboot-safe state-preserving rollback. Do not end this
work at permanent refusal or treat a report, signature or version label as an
activation capability.

New software controls exercise strict bytes, exact policy/argv joins, original
in-memory group/gateway models and early refusal. They do not instantiate a
backend or prove real KVM, systemd deployment, shipping ELF/ABI, performance or
the original long-load acceptance. Whole current CI and original native gates
remain required. The CI 25-minute outer cap, Go race 20-minute timeout, all old
cases/repetitions/order/matrix and host resource/IO limits are unchanged.
