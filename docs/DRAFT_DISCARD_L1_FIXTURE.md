# Two limited actual owned-L1 draft-discard cases

The production Go operation and its [software-only proof](supersession-draft-discard.md)
are frozen at `df679bb`. The [new source-bound actual proof](validation/draft-discard-l1-v3.json)
uses all 23 actually rebuilt native artifacts, including the changed installer,
with harness `a536f482d546703ad9d1b2167b46e249d7683617`. Both separate named
cases have now passed their complete two-boot protocol and independent cleanup
audit. No older root-runtime report is re-signed to qualify the new command.
Full production readiness remains false.

## Separate cases, unchanged bounds

`draft-discard` and `draft-discard-cut` are independent fresh owned QEMU L1
compositions. Each retains the existing 16 GiB/12 CPU/24 GiB/no-NIC resources,
300-second sandbox TTL, 45-second execution budget, 60-second trace/CLI bounds,
two-boot protocol, and independent final process/generation/path cleanup audit.
The full original TLS/four-real-KVM/drain/source-free/CAS/warm/cold/Stop/reclaim
tail remains mandatory, including actual busy-writer and four-VMM incarnation
rechecks immediately before Stop. No substitute host execution is allowed.

1. A real ordinary rotation is cut before policy publication, leaving installed
   and durable runtime epoch 1 plus a typed future intent for 2. Its short-lived
   source expires and is removed under the existing exact known-DATA boundary.
2. A fresh replacement CLI is traced as its **own child**, with exact argv and
   ELF hash. Only its first `write(2)` to the fixed private, single-linked empty
   `.policy-supersession.next` inode is eligible. The fully prepared canonical
   record must bind the exact current payload, pending intent, replacement and
   replaced request IDs. The observer shortens only that syscall's count to a
   closed 64–160-byte prefix containing the complete new request ID. It observes
   the actual successful short write, exact resulting bytes/inode/hash and
   unchanged authority, then kills and reaps its child before publication.
   This is an explicit trace-injected short-write/process-cut fixture, **not**
   a naturally occurring media fault, normal CLI error return or power loss.
3. Remove only the exact known replacement snapshot DATA. A valid independent
   candidate with a different request ID must actually fail against the partial
   declaration before maintenance. Wrong draft hash and pending ID must also
   refuse without draft mutation or stopping ingress. No metadata is manually
   deleted, truncated, fabricated or adopted by the fixture.
4. Start the original-budget busy writer after fault creation/negative controls
   but **before** the actual administrative discard. Keep the same four guests,
   main process and persisted drain across that operation.
   During the intentionally stopped-ingress window, authenticated controller
   UDS guest-API reads prove counter progress and the original job still running;
   no unavailable TLS connection or host execution is substituted. After ingress
   recovery, the original mandatory TLS continuity and busy Stop probes remain.
5. `draft-discard` requires the actual distinct receipt with `draft_removed=true`,
   then an absent retry with a different requested hash and `draft_removed=false`.
   `draft-discard-cut` instead observes successful exact `unlinkat(2)`, then
   successful fixed root-directory `fsync(2)`, and kills the real CLI before any
   receipt. A fresh absence retry must return `draft_removed=false`.
6. In both cases, ingress must actually be stopped/empty/unfrozen and main still
   unchanged; policy, future intent, proposal DATA and immutable files stay
   byte-identical. Runtime epoch stays 1 and the real startup verifier must still
   refuse. Only a fresh normal replacement can consume epoch 2; subsequent
   ordinary hot rotation to 3 must retain its TLS revocation/continuity proof.

The prefix must include the new request ID: an empty/common header prefix would
not demonstrate the lost-source liveness failure. A complete pre-rename draft
would be a different named case, not evidence of a nonempty partial write.

## Evidence boundaries

Pure tests model trace register/entry/exit transitions, syscall count mutation,
wrong exit/fsync refusal, fd inode/mode/link/nofollow/size checks, closed arguments,
exact receipt types and ordering. They never execute ptrace, root services or KVM.
They are not hardware acceptance. The observer has no attach/service PID, arbitrary
path/count/fd/argv selector or production fault hook. It retains the existing
one-shot 60-second alarm, monotonic bound, restoration and bounded child reap.

## Frozen actual result and failed predecessors

Both successful originals exited zero. Each independently rehashed all 23 native
artifacts and 16 inputs, ran 269 Linux root pure tests with zero skips, and bound
all 15 guest harness source hashes before its own two actual boots. Across these
**two accepted scopes only**, four outer generations and all declared paths were
independently observed absent, without supplemental cleanup. The four VMMs,
original guest boots/main, progressing original busy writer and persisted drain
all retained their required continuity, including the final immediate Stop checks.

| Named case | Actual busy Stop sample (ms) | Durable reclaim sample (ms) |
| --- | ---: | ---: |
| `draft-discard` | 112.673962 | 384.410407 |
| `draft-discard-cut` | 113.951069 | 384.852278 |

These are independent **single samples**, not percentiles, switch latency,
benchmarks or production SLOs. Resources, task/TTL/trace/CLI deadlines and the
mandatory TLS/cold/cleanup predicates were not relaxed.

Two failed predecessors are preserved separately, not counted as accepted:

- [First actual attempt](validation/draft-discard-failed-v1.json), harness
  `36a11e3`, exited one after one boot. Its observer attempted a TLS busy check
  while ingress was correctly stopped. It was corrected to authenticated
  controller-UDS guest-API observation during only that stopped window; no
  production Go code or resumed-ingress TLS requirement changed. Its one outer
  generation/all paths were independently absent, without supplemental cleanup.
- A later private-runner version substitution referenced a nonexistent Ubuntu
  `v2` archive rather than the already verified `v1` asset. It failed **before
  any boot**; declared paths and zero generations were independently absent.
  Reusing the existing correct archive path required no host/source/runtime
  modification or download. The failed original and raw hashes remain recorded
  in the combined proof rather than being reclassified as a successful retry.

All 636 validation files public before this work remain byte-unchanged. These
new results do **not** complete the negative-kernel (populated/frozen), concurrency,
storage/media/pressure, full supersession fault matrix or production SLO gates.

## Pending descendant-kernel regression profile

The later `draft-kernel-guard` candidate must separately establish a populated
**child** while the unit's own `cgroup.procs` is empty, then an empty frozen
child whose parent reports `populated 0` and `frozen 0`. Both must actually refuse
discard and leave the draft/intent/policy/runtime/main unchanged. Only an inert
owned pipe-blocked child is migrated; only the exclusively created fixed test
leaf is unfrozen/removed. No metadata is removed by the fixture. The same request
may then run normally and still owes the full original two-boot/TLS/Stop tail.
This regression is not accepted merely because the two earlier cases passed.
