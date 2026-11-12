# Bounded installation-prefix comparison scratch

Prototype; not a production/long-load/rollback qualification.

`filesystem.materialize` compares an already-existing unsealed output prefix
against the ORIGINAL memory/input FD before continuing the exact existing copy.
The old loop already reads `min(65536, remaining-prefix)` bytes at each iteration.
Allocate only `min(65536, max(0, original-prefix-size))` bytes for EACH of its two
buffers instead of always allocating two 64 KiB buffers. A fresh empty output
never enters that prefix loop and therefore needs no prefix-comparison storage.
The allocation ceiling stays 128 KiB total. This is per-call bounded scratch,
not a pool, cross-call cache, reused proof, external digest or alternate file.

The loop, original-source seek/FD, output open/stat/owner/mode/link validation,
copy bound and cancellation, fresh full hash, TWO file-sync barriers, chmod,
parent-directory sync and every original failure-injection point/order remain
unchanged. No buffering/verification/fsync/IO barrier is dropped. Neither zero
scratch nor short scratch admits a missing, ambiguous or mismatching prefix.

The Linux-only tests retain an independent EXACT 63c2ab5 implementation (only
its method name changes). Compare exact error objects, all stage hooks, full
owned-shadow file bytes/modes/owner/link inventory, source FD position/flags and
before/after identity+mtime/ctime, retained root offset, original memory and FD
inputs, boundary prefixes, already-sealed/unsealed files, wrong/short/long data,
all three materialization cuts, cancellation before/at cuts and a closed source.
Pure size tests include negative/zero/integer extrema and the 64 KiB boundary.
ALL pre-existing tests/workflows/cases/repetitions/order/timeouts are unchanged.
These owned-file models are not real VM/service/migration/rollback acceptance.

Source establishes a smaller requested scratch size, NOT an observed compiler
allocation/GC reduction or speedup. A prior Go20m timeout snapshot in materialize
was a one-time syscall stack, not a CPU/IO/GC cause or evidence that these buffers
caused the failure. Original Go20m/outer25m/40m failures remain failed. Actual
current original CI and whole native/KVM/load acceptance are still required;
no unpaired elapsed/green-count gain, deadline-fit or performance SLO claim.

The full state-preserving updater is still incomplete: result-aware maintenance,
ORIGINAL retained-state FD/WAL/current resource budgets, trusted builder/reader
ABI and SAME-FD/SAME-PID handoff, current policy/TLS epoch, durable admission and
ingress release, crash recovery and candidate-failure/reboot rollback remain.
Never delete bindings/history, silently rebind/normalize versions, rewrite old
gateway genesis or restore stale authority. No deployment authority is added.
