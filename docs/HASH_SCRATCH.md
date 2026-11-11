# Bounded fresh hash scratch (not a data cache)

The installer hashes each original file through an unchanged `contextReader`
wrapping `io.LimitReader(file, size+1)`. The inspected Go source uses a 32 KiB
fallback `io.Copy` scratch buffer; its small-`LimitedReader` allocation reduction
cannot see that reader through the context wrapper. Tiny files therefore request
32 KiB of scratch although their underlying file read is already limited to
`size+1`. This is a source-observed allocation opportunity, **not a CPU/IO profile,
measured speedup, timeout root cause, budget-fit or original acceptance claim**.

`hashFile` now uses `io.CopyBuffer` with a **fresh, nonshared** buffer:

- For `0 <= size < 32768`, request `size+1` bytes (always nonzero).
- Otherwise retain 32768 bytes, including negative sizes and `size+1` overflow.

No pool, memoized digest, shared data buffer, whole-file read or source validation
cache is introduced. Maximum requested scratch does not increase. The original
Seek-to-zero happens first. The unchanged context wrapper checks cancellation
before **every** copy read, still outside the exact original `size+1` limiter.
The limit already trims the underlying read requests for small files, so a
smaller outer scratch must preserve those requests and returned counts, partial
errors, EOF and context check timing. Large-file read chunking remains unchanged.
The original error-before-size precedence, `n == size`, SHA/hex and empty-result
on error remain. Negative/overflow semantics are preserved, not silently fixed.

Most importantly, **every fresh file/FD/owner/mode/link/source/WAL/proc/kernel
check and `f.verify`'s final `in.Sync()` remain unchanged**. No read or durability
step is skipped to satisfy a time limit. This helper is not a file-consumer,
activation, reclaim, or runtime isolation capability.

Five additional Linux tops run in the existing file CGO-free gate and whole
race suite. They compare an exact pinned `io.Copy` hash oracle to the candidate
using actual files, offsets, short/exact/extra contents, negative/overflow sizes;
trace every underlying reader request/return/error and context check through
fragmented/zero/partial-error/cancellation cases; cover closed descriptors,
pipes, directories, write-only descriptors and Seek-before-context precedence;
and confirm fresh checksum, mode and no-follow verification after mutations.
There are 178 leaf cases and 26 outer size groups. The source body of the old
context reader and the entire verifier/sync path is unchanged.

The initial source inspection was of an installed **Go 1.27.1** source tree, not
an execution or qualification of current CI. The actual Go 1.25/1.27 matrix and
pinned Go 1.27.4 CGO-free gates must demonstrate the exact read-trace/oracle
contract themselves. Standard-library fast-path changes must fail that contract
for review, not silently change cancellation or IO behavior.

All preexisting tests/cases/oracles/repetitions, workflows, race instrumentation,
Go 20-minute timeout, CI 25-minute limit and host resource/IO/acceptance budgets
are unchanged. No original host is loaded or deployed. New-source CI and real
Linux/KVM/long-load acceptance remain independent required evidence; old failures
and the published preview are not requalified. Full compatibility/budget,
same-FD handoff/health, admission/ingress release, rollback and production
readiness remain unfinished.
