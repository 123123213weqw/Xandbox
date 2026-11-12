# Runtime lock ambiguity: draft diagnostics, not a recovery policy

The historical global-row parser still requires exactly **one** matching active
exclusive BSD lock owned by the pinned original process. The current FD-bound
candidate changes the positive source; see [its mandatory FD witness and retained
global negative veto](RUNTIME_STATE_FD_PROOF.md). The statements below describe
the retained historical parser and its same-payload diagnostics, not an extra
positive acceptance path. Missing, duplicate,
foreign, blocked, malformed or oversized observations still fail closed. There
is no deduplication, extra kernel read, retry, fallback, owner-count relaxation,
new authority or change to any Stop/file/state-lock decision.

An ambiguous result can now append a closed diagnostic to the existing stage:

```
runtime proof:/state-lock-owner-ambiguous/lock-rows-two/exact-text
```

Only two private enum bytes survive in the error:

- Row count bucket: `two`, `three`, or `many` (four or more).
- Row shape: `exact-text` when all matching lines are byte-identical;
  `same-ordinal` when only their first field agrees; otherwise
  `different-ordinal`. This is a comparison of one already-read payload.

The summary retains no raw row, ordinal, PID, path, device, inode or hash.
Malformed enum combinations render only `lock-rows-unavailable`; errors without
summary data and unrelated stages retain their original text. Error-chain
formatting remains bounded to sixteen layers and never calls a private cause's
formatter. Existing `errors.Is`/`errors.As` behavior and private JSON fields are
preserved. Diagnostics are appended only after the entire original parser has
passed every per-row check, so a later malformed/foreign row cannot be hidden by
an earlier duplicate match.

## What it does not establish

These are counts of **observed rows**, not distinct kernel lock objects or
owners. In the pinned Linux v6.8 reference, `locks_show` uses iterator position
for the displayed ordinal; `locks_start`/`locks_stop` bound the relevant global
locking, and `seq_read_iter` can finish an iteration before a subsequent read.
See the primary [file-lock implementation](https://github.com/torvalds/linux/blob/v6.8/fs/locks.c)
and [sequence reader](https://github.com/torvalds/linux/blob/v6.8/fs/seq_file.c).
This motivates investigation of multi-read observations; it is **not** evidence
that a particular CI host ran that kernel, that an observed duplicate was an
iteration artifact, or that it is safe to ignore it.

The earlier `cab753e` push CI failed at `original-peers` /
`state-lock-owner-ambiguous`, but its matching kernel rows were not captured.
The precise reason remains unknown. New diagnostics must not retroactively
reclassify that failure, earlier generic conflicts or historical failed loads.

## Separate test synchronization correction

The cancellation test now holds the real model session journal and cleanup
independently: after accepted close and caller cancellation, it requires the
held `closing-sessions` phase, releases the journal, then uses the existing
bounded waiter to require **exactly** `closing-core` while cleanup remains held.
Only after releasing cleanup may valid terminal proofs appear. Original model
close deadlines and phase-wait budget are unchanged; no production hook is
added. Cleanup entry alone was not a coordinator phase-publication barrier.
This TEST-only correction is not a runtime/lock-ambiguity/long-load fix.

The PR remains an unmerged draft. Current-source Linux, KVM, complete resource
reclamation, installation/rollback and original long-load gates remain separate;
local parser/control tests or green CI cannot establish production readiness.
