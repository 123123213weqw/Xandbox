# Fixed ASCII path language, unchanged path policy

The installer, immutable release publisher and readiness gate previously used
the identical literal regular expression `^/[A-Za-z0-9_./-]+$`. They now share
only its byte-language predicate, `pathchars.Absolute`. Each caller retains the
original `filepath.Clean(value) == value && value != "/"` expression, on the
original string, and every other containment, size, schema, policy and authority
check. There is no normalization, new length ceiling, Unicode folding, decoded
value cache, filesystem cache or path-based authority token.

The primitive deliberately accepts `//`, `/a/` and `/a/../b`: those match the old
character language. The caller must still reject them with the original Clean
rule. The bare root, relative paths, NUL, CR/LF and every non-ASCII byte fail the
language predicate. Valid UTF-8 is not a substitute for the fixed ASCII language.

## Independent controls

The new package uses an independent **pinned literal regexp**, never its own
predicate, as the raw-language oracle. Each of the three adapters has a separate
pinned literal regexp plus the original Clean/root expression as its oracle.
Controls include all 256 byte values at multiple positions, malformed UTF-8,
Unicode, embedded control bytes, canonical/unclean/root/relative cases, long
inputs without an invented path-length ceiling, deterministic raw/allowed-byte
corpora and fresh concurrent calls. The installer's tests join the existing
File CGO-free gate; all packages join the original whole-package race command.

Four existing pinned policy/decoder oracles previously delegated their path
check to the candidate's `canonical` helper. They now call their package's
literal-regexp original-path oracle instead. Only that test-helper call changes;
all old oracle bodies, tests, vectors and assertions otherwise remain intact.
This prevents the new character implementation from defining its own baseline.

## Scope and evidence limits

Only the language-matching work changes in production. Filesystem reads, hashing,
stat/no-follow/link/mode checks, original FD/pidfd/lock ownership, callback
reproofs and persistence/Sync operations are not removed, cached or reordered.
No wire, filesystem format, caller budget, device grammar, test repetition,
case/order/matrix, Go race 20-minute limit, CI 25-minute limit, host resource/IO
or acceptance limit is changed. All old persistence/crash cuts remain required.

One of the three original `e57a7e4` 20-minute failure snapshots was in installer
`canonical`; the other two were in hashing or materialization. A single snapshot
is not a CPU profile, bottleneck attribution or proof that this change fixes the
timeout. Sharing an exact pure language can remove regexp work; no measured
whole-gate gain, deadline fit, long-load SLO or production-readiness claim follows.
The failed runs and original acceptance requirements remain unchanged.

This does not complete typed-file handoff, admission release, reliable rollback,
original Linux/KVM or long-load acceptance, nor requalify the published preview.
