# New owned-L1 draft-discard protocol (hardware acceptance pending)

The production Go operation and its [software-only proof](supersession-draft-discard.md)
are frozen at `df679bb`. These new named fixture cases must use its 23 actually
rebuilt native artifacts, including the changed installer. No older root-runtime
report qualifies the new command. Full production readiness remains false.

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

Both actual cases and their independent cleanup audits must still finish and be
source-bound before any acceptance claim. Even then, the full negative-kernel,
concurrency, storage/media/pressure and production SLO matrix remains separate.
