# Private Plan node-line reuse (pure work, not authority)

`validatePlan` previously serialized the same private immutable node twice before
its unchanged final `CheckComposition`: once for the strict JSON+LF byte ceiling
and again for the ingress node digest. No callback, IO or mutation occurs between
those producer operations. It now retains the exact successful JSON+LF bytes
from the first operation and hashes those bytes for the ingress constructor.
This removes **one redundant producer serialization**, not any semantic policy,
source/FS read, process/FD proof, byte limit or effect check.

`nodeManifestLine` uses the same `json.Marshal` error/UTF-8/escaping behavior and
strict `len(bareJSON) < launch.MaxManifest` predicate as the retained independent
budget predicate. Only on success does it append the original single LF. A bare
manifest exactly at the ceiling still fails the line budget. Rejection returns
no partial line. The original complete `g.CheckComposition(n)` is still run on
the **same** private node; there is no cached or cross-call validation result.
The existing schema tests still require a closed comparable node with no custom
JSON/text codecs, references, mutable containers or new normalization rules.

The original `ingressManifest` wrapper still computes `digest(encode(n))` for
all its callers, including oversized/invalid inputs, and constructs the exact
same fields/value/bytes. Only the fixed literal construction is shared with a
private `ingressManifestWithNodeSHA` helper. Its three production callers (the
original wrapper, Plan validator and renderer) compute the digest themselves
from the same exact JSON+LF producer bytes. The renderer also retains its exact
node line for output; see [renderer node-line reuse](RENDER_NODE_LINE_REUSE.md). No caller can
supply a raw line/digest through a public API, decoder flag or effect permission.

**`CheckComposition` does not independently bind `NodeLaunch.SHA256` to `n`.**
It validates the digest's shape and semantic resource composition. Therefore the
private digest constructor and line-budget predicate are **not authority**, and
must not become report-only validators or file-consumer capabilities. Tests use
an independent pinned literal constructor and independent standard-library JSON,
SHA-256 and hex production, not either candidate builder, `encode` or `digest`.
They also show that semantic-invalid nodes can fit the byte budget and that a
well-formed but unrelated digest is not fixed by `CheckComposition`.

Five new tops in the existing file gate/whole race suite cover version/metrics,
multiple devices and nil/empty/different artifact maps; exact LF ceiling edges;
all nine string positions with escapes/Unicode/invalid UTF-8; fresh nonshared
bytes/caller mutation; and the semantic/digest non-authority boundary. There are
82 leaf cases plus nine outer string-field groups. All preexisting test bodies,
golden oracles, cases, repetitions, workflow commands, race/matrix, 20-minute Go
and 25-minute CI limits, and host resource/IO/acceptance limits are unchanged.
No original node is loaded or deployed by this change.

This is a source-proven removal of duplicate pure work, **not a CPU profile,
measured speedup, timeout root cause, budget-fit, original long-load or production
readiness claim**. New-source CI and real acceptance must be evaluated on their
own actual outcomes. Old failures remain failures; all result-state join,
compatibility/budget, same-FD handoff/health, release/rollback and original
Linux/KVM requirements remain independent gates. No published preview is
requalified by this code change.
