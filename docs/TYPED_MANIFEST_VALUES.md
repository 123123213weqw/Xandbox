# Constructed manifest validation (draft)

This is an internal P0 performance candidate in the unmerged runtime-close
stack. It does **not** enable upgrades, rollback, activation, a new release, or
permission to execute. Real runtime reclamation and long-load acceptance remain
separate requirements.

## Preserve the wire boundary

`launch.Decode`, `ingresslaunch.Decode`, and `releasestore.Decode` remain bounded,
strict raw JSON entry points. Duplicate/folded/unknown fields, malformed values,
trailing objects and actual received-byte limits still go through the existing
strict decoder. A decoded manifest is not filesystem, process, manager, quota,
state-lock or image authority.

For values already constructed by the installer/composition code:

- `ValidateValue` preserves `Decode(json.Marshal(value))` semantics and its
  16 KiB serialized ceiling; it is not a parser or a cached authorization.
- `ValidateLineValue` (node launch and release manifests) also counts the final
  canonical LF, exactly like the installer's existing `encode` expression.
- The same semantic predicate is used by raw and constructed validation.
  Release normalization, sorting, per-file and aggregate limits are unchanged.
- Constructed release manifests detach the caller's file slice, including on
  error. Nil and non-nil empty slices retain their old returned-value behavior.
- Invalid UTF-8 falls back to the original raw decoder after marshaling. This
  preserves `encoding/json` replacement, including accepted Unicode launch paths
  and normalized values returned with errors. It does not create a new path rule.
- Ingress composition validates both manifests, then compares the **original**
  values and subtracts all five full node/ingress/reserve budgets from capacity,
  exactly as before. Capacity is accounting, not a shared kernel-enforced parent.

Raw limits and constructed limits are intentionally different boundaries: raw
JSON with unescaped `<` can be shorter than the HTML-escaped marshaled form.
Raw decoding must not acquire a new canonical-serialization size rejection.

## Checks and limits of evidence

Tests retain pinned pre-change `44edea3` policy/roundtrip oracles, scalar/schema
and UTF-8 field-roster contracts, raw JSON ambiguity controls, both sides of the
serialized ceiling (including the LF), accepted UTF-8 replacement, raw escape
expansion, detached slices, descriptor ordering, five-dimensional composition,
invalid/overflow budgets and version 1/2 installer integration. The installer
checks retain the `TestRuntimeFile` prefix so existing Linux/race gates include
those additions; no original cases are removed.

`BenchmarkTypedValueManifest44`, `BenchmarkTypedValueComposition44`, and
`BenchmarkRuntimeFileManifestValue{Descriptor,Plan}44` compare both expressions
in the same binary. These are CPU/allocation microbenchmarks, **not** sandbox
switch/stop/reclaim latency, long-load reliability, a whole-command time saving,
or evidence explaining a historical failure. Race instrumentation and native
resource/time/headroom guards must stay enabled for their existing gates.

No file reader, raw transaction decoder, filesystem/proc proof, journal step,
manager call, state-lock handoff, Stop deadline or host resource policy is changed
by this candidate. It cannot substitute for the still-required original-node
qualification, owned KVM acceptance, complete runtime inventory join, compatible
installer/startup handoff and failure/reboot-safe rollback.
