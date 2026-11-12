# Secret-gate controls: stable positive fixtures and closed failure diagnostics

This change concerns the **self-test of the pinned publication gate**, not the
sandbox runtime or the detection rules. The preceding PR run's self-test failed
without retaining its control phase, exception origin or synthetic input. That
original failure remains failed and its cause **UNKNOWN**. A local low-entropy
injection demonstrated a possible fixture-precondition problem; it did not
reproduce or diagnose the original Linux failure.

## Fixed synthetic positives, unchanged controls

The provider-format fixture now has 36 distinct ASCII alphanumeric suffix
characters. Each 64-character lowercase hex fixture comprises four separately
SHA-ranked permutations of the full 16-symbol alphabet: every symbol occurs four
times. Public versioned domain labels distinguish the provider, direct-hex and
merge-only fixtures. These are deterministic **synthetic test strings, not a
production credential generator**. They avoid unconstrained-random low-entropy
positives and make the same control inputs reproducible without storing values
in CI output. The actual pinned scanner must still detect them.

All twelve original controls, their order, detection/redaction assertions and
Git-history operations remain required: provider/direct hex, inline allowance,
exact public-alphabet exemption, neighboring provider token, ordinary text,
deleted binary-marked history with repository/environment overrides, forbidden
ignore inventory, graft, merge-only addition, shallow history and changed tool.
Success checks the exact complete roster. No detection rule, entropy threshold,
hash/path/token exemption, scanner/config pin, integrity check, full-history
scope, TLS policy or original CI/runtime test/resource/time limit changes.

## Failure output is data-minimized, not a traceback

The CLI records a closed control phase and a bounded pre-control source snapshot.
On failure it emits one JSON object to stderr and returns nonzero. It includes:

- fixed result/version, a whitelisted phase and exception category;
- SHA-256 of the bounded source snapshot, or null if unavailable;
- an actual module code-object role and bounded source line when mapped;
- explicit `clean_history_claim: false` and `sensitive_data_exported: false`.

It does **not** format an exception or its arguments, traceback text, arbitrary
function/file names, frame locals, argv/path values, synthetic strings, findings,
reports or third-party console. Mapping uses code-object identity, not a supplied
filename. A source hash identifies the observed script snapshot; it is not an
attestation against concurrent malicious-root replacement.

Argument errors are handled without argparse echoing arbitrary argv. Unknown
exceptions also fail closed; KeyboardInterrupt returns 130. An unavailable,
empty or oversized source snapshot fails closed without a false origin claim.
Python `-O`/`-OO` cannot disable the assertion controls: the entry point refuses
before invoking them. Help is not a successful control result or history claim.

Pure regression tests cover fixture invariants/reproducibility/domain separation,
the exact old roster, hostile exception/phase data, safe argv errors, actual
source-role mapping, unavailable/bounded source, interruption and optimized
Python. Actual pinned-scanner smoke and whole-history checks remain separate
required evidence. A passing local smoke or an injected failure never replaces
Linux CI or reclassifies the previous failure.

## Still not release or runtime acceptance

The current source needs its own complete original CI evidence. All original
failed native/long-load results remain failed; this Python-only change does not
fix the original-node 300-second accepted-work race cap, qualify KVM/resource
reclaim, enable an updater/rollback, or authorize merge/release/deployment.
Original-node limits, no host-exec fallback and production qualification gates
remain unchanged.
