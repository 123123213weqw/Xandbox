# Fixed identity and digest languages, unchanged authority

Ten private fixed-width regexps in six packages now use the existing
`fixedhex.Pattern`: node admission/maintenance, sandbox/result records, sessions,
backend configuration/inspection, readiness manifests and the Linux managed
policy envelope. Only the literal languages `^[0-9a-f]{32}$` and
`^[0-9a-f]{64}$` change implementation. Every call site keeps its original width
and `MatchString` check; the shared primitive and all other regexps are unchanged.

This does **not** compute or attest a digest, validate a whole record, prove
ownership, authorize file selection, or grant release/rollback authority. No
case folding, trimming, normalization, zero-ID exception, permissive decoder,
value cache or filesystem cache is added. All-zero input still matches the old
character language; existing higher-level nonzero and binding checks remain
mandatory. Wrong-width, uppercase, control-byte and non-ASCII input still fails.

## Independent controls

Each package has literal pre-change regexps, not aliases of the candidate or
widths inferred from it. Every changed private matcher is compared against its
own fixed literal, including valid/zero/boundary/Unicode/invalid-UTF-8 cases,
all 256 bytes at first/middle/last positions, deterministic raw and hex corpora,
and fresh concurrent repeated calls. The existing shared primitive's exhaustive
every-position tests for widths 32/40/64 are retained unchanged.

Additional caller-level baselines are pinned verbatim from the pre-change
source, except function names and explicit original-regexp/ref helper aliases:
admission state/command/maintenance owner, result reservation and V1/V2 closure
observations, complete session metadata/history validation and error strings,
backend instance-key values/errors, and readiness decoded values/errors/policy.
They do not call the new matchers for their expected identities or digests.
The old V2 result-checksum test's direct digest-syntax assertion also uses its
literal original instead of the candidate alias. No old assertion is removed.

The new controls are pure value tests: no file constructor, state lock, process,
service, VM, quota operation or shared test fixture is introduced. Gateway
controls are Linux-only, matching the original envelope implementation; they
must not be counted as having executed on macOS. The existing maintenance,
result and backend CGO-free selectors include the corresponding controls; all
applicable packages remain in the unchanged whole-package race command.

## Bounds and evidence

All production function bodies, IO, hashing/checksum comparison, JSON/schema and
version checks, revision/CAS/history/owner links, fresh source/FD/pidfd/lock proofs,
callback rechecks, journal writes and Sync operations are unchanged. No wire,
format, immutable backend budget, test case/repetition/order/matrix, Go race
20-minute / CI 25-minute limit, original host resource/IO or acceptance bound is
raised or removed. Device/path/compound regexps and unrelated guest/host-fixture
matchers are not part of this change.

The previous path-language candidate completed five whole race steps, but all
four Linux jobs still reached their original 25-minute outer limit. That is not
a CPU profile or proof that fixed-width regex work caused the delay. This change
must qualify on its own original CI; no measured gain, deadline fit, long-load
SLO or production-readiness claim follows from a syntax optimization. Previous
failures, full original/feature Linux/KVM acceptance, typed installed handoff,
admission release, startup and reliable rollback remain outstanding.
