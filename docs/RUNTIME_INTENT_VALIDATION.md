# Fresh intent and pin validation candidate — no weaker proof or release gate

This is an unmerged P0 candidate. Its predecessor's FIRST original-node
207-function / 828-repetition software attempt hit the original 300-second
accepted-work race command protection: 494 top-level passes, no reported failure
or race, 334 incomplete/not run. That remains a failed gate. The new code does
not turn partial results, local benchmarks or CI into original-node/KVM/long-load
acceptance. All historic missing/ambiguous ownership causes remain unknown.

## Fresh Drain/Stop intent decoding

The final Drain intent, Stop intent and complete maintenance scratch readers
still perform exactly the same single trusted file read, mode/type/owner/link/
no-follow and `MaxPlan` bounds, with the original inventory and semantic policies.
Only syntax/canonical validation of those already-read bytes changes:

- A closed union permits only the existing comparable Drain and Stop types.
- A fresh zero target may try private typed unmarshal and **full exact canonical
  encoding equality**, including LF. No unknown/folded/duplicate/alternate key,
  normalization or trailing form can be accepted by this comparison.
- A conservative total opening-byte gate of 64 selects the original path before
  deeply nested permissive parsing; brackets in strings can only select the old
  path, never independently reject a valid input.
- On **every rejected fresh candidate**, execute the exact original strict
  expression on the original zero target. Preserve partially populated or
  normalized values returned **with errors**, not only accepted values. Nonzero
  targets always retain the old merge expression, including pointer identities.
- Existing pure semantic predicates remain required. Their order relative to
  canonical syntax is rearranged, but they are side-effect-free on these closed
  values, do not mutate them and return only the original fixed failure class.
  All raw reader outputs, including errors, must match the pinned old readers.

The existing four Work/Close decoders are deliberately unchanged: their fresh
rejection publication contract differs. The general strict JSON library is
unchanged. No authority cache, second file read, cross-call decoded value,
caller-selected schema, lighter policy or source/process check is introduced.

## Fixed lowercase hexadecimal pins

The installer's existing byte predicate is moved verbatim to `internal/fixedhex`
and retained through a type alias. Launch and ingress keep width 64; release
store keeps digest 64, source revision 40 and request 32. Each recognizes exactly
its old anchored ASCII regexp language. Nothing trims, case-folds, decodes JSON
or certifies the source. Filesystem, CAS, receipt and release rules are untouched.

The existing launch/ingress/release typed-value test oracles now explicitly use
pinned literal regexps, **not** the candidate matcher. Tests retain all old cases
and compare every byte at every position, boundaries/Unicode/newlines/NUL,
deterministic data and immutable concurrent readers. Native installer controls
also bind actual launch/ingress/release digest and revision call sites. The
original unit/device/path/toolchain regexps are unchanged.

## Plan validation: preserve the special final-LF ceiling

Plan validation used to validate the same locally constructed node policy twice:
first `launch.ValidateLineValue(n)`, then the original ingress composition check
which calls `launch.ValidateValue(n)` again. These are **not identical budgets**:
line includes LF, composition checks bare JSON.

The candidate replaces only the first full semantic pass with an explicit
`json.Marshal` success and **bare size strictly below** `launch.MaxManifest`.
Thus one final LF still fits exactly. The same private, immutable node then
passes the **unchanged** original composition and entire node semantic policy.
The intermediate constructor is a pure fixed-field composition/hash with no
external callback or effects. The byte-budget helper alone never proves policy.

Controls include the pinned old Plan flow; all scalar/policy variants; immutable
closed node shape; otherwise-valid bare sizes `MaxManifest-1`, `MaxManifest` and
`MaxManifest+1`, including the case where bare succeeds but LF must refuse. No
public bypass or prevalidated-authority token is added.

## Evidence scope and required next gates

Same-binary local three-sample paired microbenchmarks retain all samples:

- Fresh syntax-only intent decoding: normal median time reductions about
  62–66%, race 54–55%, with lower allocations. This is not a whole file reader.
- Pin matching only: normal 90–94%, race about 99.5%. A tiny primitive's result
  is **not** a corresponding whole-command or sandbox speedup.
- Incremental Plan flow: about 6–8% median reduction, with the **same current pin
  matcher on both sides**. This comparison does not include other packages'
  old regexp cost. Allocation count is unchanged; small byte-count variance is
  retained. These improvements cannot be added together or extrapolated to SLOs.

Portable raw/error-output/schema/reference tests supplement actual Linux private
reader mode/link/no-follow/ceiling/scratch/partial/final-vs-scratch comparisons.
Each old intent reader is an independent exact pinned implementation. Linux
execution is not inferred from macOS or cross-compilation. No test/case is dropped
or moved; old complete race x3 and original twelve-vector counts/order/CGO and
300-second/900-second protections remain mandatory, including every new test.

All source/image/filesystem/proc/owner/state-FD/pidfd/manager/Stop/durability checks
outside the stated pure transformations remain unchanged. Shared-node Go2,
package1, soft512MiB, absolute self-only nice10, pidfd-owned priority and 1Hz RAM/
PSI/all-ancestor RAM+PID/disk/temp guards must not be relaxed for a pass. No VM,
ordinary daemon, real quota, GPU, offered workload or host configuration change
is implied by these software tests. Original-node full gate, complete resource
joins, compatible startup/activation/release/rollback, owned real KVM and ORIGINAL
long-load acceptance remain open. The PR stays Draft, not production ready.
