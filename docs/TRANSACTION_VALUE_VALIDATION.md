# Transaction value validation (unmerged P0 candidate)

This changes repeated **pure** validation, not the source of installation or
runtime authority. It does not enable updates, rollback, file activation, a
release, complete resource reclamation or production readiness.

## Preserve the policy and every filesystem observation

`validFileList` keeps the pinned `5f30a18` policy: request/version/revision,
plan, release identity/order, exact target set, duplicates, modes, size limits,
self/input/artifact hashes and artifact sizes. Source-pin construction and
artifact-path constraints are computed once per call rather than per file.
Artifact constraints remain a list of **all** matching requirements, not an
overwriting path map which could lose an alias constraint. There is no global
or cross-call value/authority cache and caller-owned values are not mutated.

Three pure declarations (configuration names, their version selector and plan
input descriptions) move verbatim to a common file so the actual production
policy can be differential-tested on every CI platform. File/effect methods
remain Linux-only.

Both verifier entry points still validate policy. When `verifyTargets` calls its
internal tail with the **same private immutable value**, only its redundant
second pure policy evaluation is omitted. The second root inventory, every
policy-envelope/override/file/hash/mode/link/generated-file/directory/pending
transaction check, and all original directory-sync barriers remain in the same
order. The internal tail is not a public bypass or an authorization token.

## Preserve raw canonical decoding and error values

`readTransaction` still performs the **same single** bounded trusted file read:
65,536 bytes, mode0600, existing owner/type/link/no-follow guards. The candidate
then tries fresh typed unmarshal, **full exact canonical re-encoding equality**
(including the LF), and the same semantic policy. No noncanonical bytes or
partially decoded candidate can pass this path. Closed-schema contracts exclude
ambiguous tags, custom JSON/text methods, unexpected pointers/slices, maps,
interfaces, floats and excessive schema depth.

The candidate is conservatively bypassed if total `{`/`[` opening bytes exceed
64, even when those bytes occur inside strings. This only selects the original
path; it never rejects an input itself or relaxes the old nesting limit before
processing malformed deep input.

On **any** rejected candidate the exact original strict expression is evaluated
on a fresh zero target. This preserves not only acceptance and errors, but also
the original partially populated/normalized transaction returned **with** an
error. Rejected input can cost extra pure parsing; it remains subject to the
same file/depth/resource limits. No file is reread for fallback.

Pinned independent old-policy and old-decoder oracles cover v1/v2, every target
field, pin/descriptor coupling, ordering/duplicates, limits, raw ambiguity,
normalization/truncation, malformed deep data and complete error-return values.
Tests also check fresh pointer/slice/string ownership and concurrent decoding.
Linux controls compare the original actual reader on file ceilings, modes,
links and pending-scratch inventory fences. Passing a raw/value check is not a
filesystem, process, kernel-lock, manager or stopped-resource proof.

## Fixed poll provenance, not a lock-owner fix

The close loop now labels `poll-input` and `poll-peers` immediately before those
existing calls. Previously a prior `actuator-reply` label could survive into a
later input/peer rejection. No new call/read/retry or changed decision is added.
Two private software-model negatives require no close RPC or Stop after either
rejection. This does not explain or fix the earlier missing/ambiguous kernel
owner observations; their causes remain unproven.

Same-binary old/new policy and decoder benchmarks measure CPU/allocations only.
They do not prove whole-command cap fit, sandbox switch/Stop/reclaim latency,
KVM behavior, cold recovery or an earlier long-load cause. Original complete
Linux gates and resource/time/priority/health protections must remain unchanged;
no case split/removal, cap increase or partial-fill qualification is allowed.
