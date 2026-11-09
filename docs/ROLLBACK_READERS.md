# Fixed backward-reader process gate

Status: **Mock software compatibility test, not a runtime update or rollback
executor, installation acceptance, KVM recovery, sustained-load pass or
production release**. The earlier unexplained metadata-smoke exit failure is
not explained or erased by this separate gate.

State-preserving rollback needs an older program to read state written by the
newer one. Restoring an earlier ledger, key file or policy to make the old
program start is not rollback. `scripts/reader_rollback_smoke.py` exercises the
actual fixed released/candidate/released/candidate daemon pair against **one
fresh disposable state directory**, without copying or restoring its history.

The first native software attempt stopped in a unit negative fixture, before
any daemon/operator artifact execution: the test incorrectly assumed renaming
an inode always changes its nanosecond ctime. On that Linux filesystem creation
and rename received the same coarse timestamp. The corrected control checks
the actual contract: the retained descriptor still holds the original inode
and complete bytes, while the replacement path names a **different** inode.
Explicit mode-drift and changed-byte controls still refuse. No executable pin,
verification, process exit requirement or test deadline was relaxed, and the
original failed attempt remains failed.

## Fixed inputs and execution boundary

This Linux/amd64-only test accepts file locations, not caller-selected digests,
source revisions, backends, commands, state roots or compatibility overrides.
Whole-file sizes and SHA-256 are fixed:

| Role | Bytes | SHA-256 |
| --- | ---: | --- |
| Released daemon | 12600219 | `5bfb2394f95a1b1c2f887b6e301357b92140586bde07448e3e09f2aa0ee3c11c` |
| Candidate daemon | 12622263 | `64883c528ba1d574aaa082c24b136e4938717c13c6abc122afcbddbb3b6c2abe` |
| Released operator CLI | 10471303 | `ea48602300fcde5aa90171e2dea3adf0f4ec36c8afd91b68aded103e04a69071` |

The released input is source
`46b625311828edfd8e3abed2d6bae56560346460` (`v0.1.0-preview.1`). The candidate
runtime is `1a78d4b2942f97ae945bafd6681c26470b438a8e`; subsequent fixture/Python
changes do not change that daemon. Canonical builds use Go 1.27.3,
Linux/amd64/v1, CGO=0, `-trimpath -buildvcs=false`. CI checks out the exact
released source **separately**, builds the two released files without running
them, and uses the already built fixed candidate file. Unknown builds refuse.

Each canonical, caller-owned, single-link regular executable is opened
NOFOLLOW/NONBLOCK, bounded and completely hashed through a retained descriptor,
with unchanged inode/owner/mode/link/size/mtime/ctime. The same descriptor is
passed through `/proc/self/fd` for execution after another identity check; a
later path replacement is not adopted. This is an input-drift control, not
protection against a malicious owner/root or proof of whole-program semantics.

All four daemon boots are **sequential** with the explicit Mock backend,
private Unix sockets and newly generated test credentials. The child environment
contains no inherited credentials. Only fixed Mock `echo` is exercised; Mock
never runs a host command. The test has a fixed 180-second whole-case clock,
15-second predicate/shutdown waits and first-failure stop, not retries or a
physical latency claim. Cleanup kills only a retained, un-reaped child if
necessary. No root/systemd/mount/cgroup/network/VM action is used. Only a fresh
0700 `/tmp/xb-reader-*` directory is managed, never an existing installation.

## Same-state sequence and invariants

1. **Released writer:** create one raw identity and one session, switch the
   session once, verify old session revision rejection and fixed Mock execution.
   Durably drain revision 1→2; cleanly stop and independently read all terminal
   files and the empty private Mock workspace directory.
2. **Candidate reader/writer:** start the exact same state drained at the same
   epoch/revision. Compare every old terminal ledger byte hash, session identity,
   key/spec hashes and full attempt history. Only the documented startup
   `updated_at` of an already-CLOSED session may advance. Resume 2→3, reject all
   permanent old raw/session keys, add new identities/history, drain 3→4 and stop.
3. **Released backward reader/writer:** consume the actual candidate-written
   state, not a synthesized schema or restored snapshot. Preserve all old and
   new records/keys/history/drain authority, resume 4→5, add new identities,
   drain 5→6 and stop.
4. **Candidate forward reader:** consume the actual older writer's additional
   state, retain all nine terminal ledger records and three CLOSED sessions,
   reject all old creation keys, resume 6→7 and drain 7→8. Exact node-command
   retries leave the committed state unchanged; unrelated stale CAS requests
   fail without mutation. The node epoch/identity is never replaced.

The fixture rotates its private startup auth file **forward once while stopped**,
before the first candidate start. All subsequent starts, including the older
binary, must reject the retired token, preserve the replacement file byte for
byte, and retain the same tenant ownership. This is startup auth preservation,
**not** managed ingress-policy/PKI rotation or a concurrent credential test.
Bounds and closed inventories reject nonterminal rows, pending/unknown files,
symlinks, overlarge rows and unreclaimed Mock directories. Raw state, tokens,
IDs, paths and diagnostic timestamps are not included in the result. Nonzero
shutdown remains a failure with bounded closed context, never a successful
rollback. Historical diagnostic tail context is not a cause certificate.

## Required remaining work

Passing proves only these exact two files can read/write this bounded
**terminal Mock-state** history. It does not certify all schemas or releases,
active/in-flight generations, core owner/quota/catalog/backend binding,
managed policy monotonicity, simultaneous old/new writers, media faults or
interruption/reboot. Do not use its result as an activation receipt.

The real executor still needs source-bound compatibility coverage of all
authorities, persistent drain plus independent full guest Stop/reclaim,
monotonic durable transition intents/CAS, multi-file activation and same-PID
health, interrupted/reboot recovery and state-preserving rollback drills in an
owned L1. Neither this gate nor artifact inventory authorizes installation,
production rollback, deployment or a new release. Original resource/asset/IO
ceilings and the 35-second actor/40-minute offered-load gate are unchanged.
