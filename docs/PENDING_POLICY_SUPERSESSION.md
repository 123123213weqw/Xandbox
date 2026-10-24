# Unconsumed policy proposal supersession — regression candidate

Later candidate: [hash-bound uncommitted supersession draft discard](supersession-draft-discard.md)
addresses partial declaration bytes plus lost source without deleting committed
authority or the future-intent startup fence. It needs separate fresh software
and actual owned-L1 qualification; no earlier hardware result qualifies it.

**Experimental implementation under new native regression, not production ready.**
The earlier [committed recovery software proof](MANAGED_POLICY_RECOVERY.md)
remains bound to its old source/artifacts. It does not qualify this new command,
changed gateway/installer, actual root operation, kernel observation or TLS/KVM.
The full production goal and independent hardware acceptance remain open.

Follow-up: [three independent limited named cases](MANAGED_POLICY_SUPERSESSION_L1_FIXTURE.md)
at frozen `8974967` now cover actual repeated unconsumed replacement, visible-file
recovery and ordinary hot rotation, with six boots/six independently absent
outer generations. The older diagnostic result and unattributed failed original
remain separate. Full syscall-cut/kernel-negative/media/runtime/SLO matrices,
the partial-declaration liveness gap and the production goal remain open. No
historical record is re-signed.

```text
xandbox-install replace-pending-policy -plan PRIVATE_PLAN -expected-revision N -request-id NEW -replaces-request-id PENDING
xandbox-install reconcile -request-id NEW
```

This is explicit maintenance on a fresh managed v2 installation, not an upgrade
of a v1/self-pinned node. `N` is the currently installed epoch, at least 1 and
less than uint64 max. The new and administrative pending IDs must be distinct
32-lowercase-hex values, not the initial installation request. The private plan
is the unchanged closed rotation plan, with a pinned **fresh Snapshot at N+1**.
All normal serving and new-admission checks retain actual time. Backend authority,
self/release/node/artifact pins, UID/GID, socket, address and SNI remain immutable.
No force, arbitrary path cleanup, service selection, host task argv or node resume.

## Proposal versus consumed epoch

- An ordinary pending rotation has file/runtime N and a future intent C for N+1.
  Replacing C requires **exact existing runtime N and its Snapshot digest**, not
  a commit/advance of C. Missing state, a different digest or runtime N+1 refuses.
- An uncommitted recovery C has file N, existing runtime N-1 or N and an old
  committed intent for N. Advance only the actual installed N, with the existing
  exact/+1 persistence primitive, then independently confirm exact N. Never
  advance the abandoned C, even if its full bytes are available.
- If the replacement file D at N+1 DID commit, that epoch cannot be reused.
  `replace-pending-policy` refuses. Explicit `recover-policy` must use expected
  N+1 and a fresh N+2 source, and can settle the exact visible supersession
  declaration without inventing an ACK for D.

`ConfirmManagedPolicyState` opens only the original existing gateway store under
its own EX lock. It validates complete inventory/binding and exact epoch/digest,
without Commit, bootstrap, collection or mutation. Persistence-only static checks
may inspect an expired predecessor at its leaf validity boundary; they produce
no serving Policy, listener, child descriptor or ACK. Normal paths never call
this primitive to waive time validation.

## Bounded declaration and safe ordering

One canonical `policy-supersession.json` (32 KiB maximum) binds base/config/initial
anchors, current file and Snapshot hashes, old administrative pending ID, typed
previous intent, optional old recovery-record hash, new request/source/payload.
It contains no Snapshot/key, previous supersession or recursive history. Its only
scratch is `.policy-supersession.next`. A successor envelope adds the optional
`replaced_pending_request_id`; it cannot also carry the committed-recovery marker.
Initial and ordinary envelopes without the new marker retain their encoding.

1. Hold operation **EX** on the original installer lock through declaration,
   ingress maintenance, files, real ACK and final receipt. File EX never spans
   manager calls. Re-prove self/base/full immutable files, all records and
   recognized scratch shapes before admitting a fresh candidate.
2. Persist the declaration before ingress-only stop. Reuse the fixed main pidfd
   pin, unit/dependency constraints and read-only real cgroup-v2 whole-subtree
   `populated=0`/`frozen=0` proof from committed recovery. No main or guest action.
3. Under stopped ingress and file EX, prove exact current runtime N (advancing
   installed N first only for an uncommitted recovery). A surviving supervisor's
   original gateway store lock independently refuses the operation.
4. Discard only abandoned **proposal data** if necessary, then CAS/sync the
   FUTURE new intent D **before** removing an exact old recovery declaration.
   The old file N always remains fenced by a future intent across that removal.
5. Sync/rename the fresh complete D envelope. Gateway startup and cap0 installation
   verification allow only exact file D + intent D + matching visible declaration;
   predecessor file N is never a serving-valid supersession view.
6. Start only ingress and require exact actual supervisor/child ACK. Re-prove
   files/current-time validity/ACK before removing the supersession declaration
   **first**, sync, then matching intent and sync. Main incarnation remains pinned
   through the callback/receipt. `production_ready` stays false.

### Explicit abandonment of private proposal data

An abandoned candidate's key/source may be gone and its `.policy.next` may be a
partial, opaque prefix. Unlike ordinary reconfiguration's exact-prefix extension,
this explicit abort-and-replace operation may unlink **only that fixed bounded
private single-link 0600 proposal-data file**, after proving installed/runtime N
under stopped ingress. It pins and checks the inode, length and content before
unlink and sync. A current replacement prefix/full candidate is retained, so a
complete candidate still supports source-independent exact retry. Oversize data,
links, different modes or raced-in inodes refuse without deleting them.

This is not adoption of opaque bytes as policy or authority, and is not an
automatic garbage-repair privilege for other operations. No opaque intent,
recovery record, supersession record or metadata scratch is discarded this way.
Unknown authority/inventory remains a refusal. In particular, a partial
**declaration scratch** with neither its full metadata/candidate nor original
source can still require external recovery; arbitrary metadata reconstruction or
blind deletion is not implemented. This candidate does not resolve every liveness
or media-loss case.

## Repeated uncommitted replacements

When D itself never published, a later explicit E can settle D without D's source
or key: prove current N, normalize the typed future intent D, remove any exact
old recovery only after that future intent is durable, then remove declaration D
**without ACKing it**. File N + future intent D still fences startup. Declare E
and proceed at the same still-unconsumed N+1. At most one recovery and one
supersession declaration coexist temporarily; there is no snapshot/history chain.

A cut while settling D is not evidence that E was declared. Exact E retry still
names D until the authoritative declaration actually changes. `reconcile` checks
supersession before an older recovery, drops its operation SH, then acquires EX
and re-proves the request; it never upgrades while holding a file lock. Ordinary
Apply/Reconfigure/committed recovery cannot bypass an uncommitted supersession.
A completed lost receipt uses the installed marker, exact request/source and
ordinary ACK reconciliation without another maintenance stop.

## Evidence still required

Current tests use real anchored shadow files/sync/rename/OFD/flock and separate
actual **test-process** exits. Their installer manager/ACK/store effects remain
models; the real gateway store has separate confirmation/inventory tests. No CLI,
environment or RPC accepts these alternate roots or model observations.

The [source-bound native software checkpoint](validation/pending-policy-supersession-native-v2.json)
has now passed Linux whole-package race x3/vet, all 17 meaningful focused parents
x3, 19 returned-error and 19 actual test-process cut boundaries x3, three actual
recovery-settlement process cuts x3 and both four-process CAS groups x3. The
empty process-helper entry is excluded from that parent count. All 23 designated
native artifacts were actually rebuilt and rehashed; seven independently
cross-built amd64 artifacts match byte-for-byte. macOS race x3/vet and two arm64
compile-only artifacts are separately identified. No arm64 runtime claim follows.

Runtime Go source is `9db9603`, native execution harness source is `6173527` and
the later two-case fixture source is `848b814`; all `cmd`, `internal`, `go.mod`
and `go.sum` bytes are unchanged between them. Native frozen-harness Python tests
passed 247/zero skips; later fixture pure controls passed 249/zero skips on Linux
and 249 with five platform skips on macOS. These are not root-runtime evidence.
All 627 older validation files remain byte-unchanged.

Beyond these limited named cases, this **unconsumed supersession command**
still requires the remaining source-bound root CLI,
real positive/negative kernel empty proof,
coherent TLS revocation, continuing KVM writer, unchanged main/guest incarnation,
persisted drain, source absence, actual cuts/ACK/cold and independent cleanup are
still required. Older software or hardware records must not be re-signed.


## Measured test-runner budget, not a runtime latency relaxation

The first frozen run at `9db9603` passed the new 17 meaningful focused parents
once, including actual test-process exits and process CAS groups. The full
unchanged `-race -count=3` invocation then exhausted its **cumulative 15-minute
package alarm** at 900.035 seconds. Its then-active root had run about 10 seconds
and subcase about 2 seconds; no earlier assertion failure was reported. Subsequent
qualification stages and all 23 designated release builds did not run. That
failed original is retained, not retagged as green.

The frozen package lists 77 normal-run roots: 63 existing roots and 14 new
supersession roots (including one empty process-helper entry, not substantive
coverage). A separate same-source baseline profile passed all 63 with race once,
required static-PIE input enabled and zero skips, in 209.227 seconds. The new
focused installtxn profile took 115.156 seconds. Their measured additive projection
for three repetitions is roughly 970 seconds, already beyond 900; profiling is
not itself full qualification. An earlier profile omitted that required input
and skipped one test; it is retained as incomplete and was corrected, not treated
as all-root success. The original full run had enabled the input.

The finite package budget is therefore now **20 minutes**, and the matrix CI
job budget **25 minutes**. All packages, roots and repetitions still execute in
the original whole-package `-race -count=3` run. No partition replaces same-process
cross-root/inter-iteration coverage, test is dropped, detector option changed or
failure hidden. Runtime service/guest limits, CLI/maintenance deadlines, owned-L1
resources and Stop/GC/switch limits are unchanged. The new entire run must still
actually finish successfully; neither a projection nor a larger alarm is a pass.
That second original has now exited zero, including the complete remaining
qualification/build stages. Its full installtxn race x3 package took 953.137
seconds. This is software-runner timing, not a sandbox switch/Stop/GC SLO.

A [fresh managed-v2 owned-L1 harness](MANAGED_POLICY_L1_FIXTURE.md) is now
implemented and subsequently passed two independent limited actual **committed
expired-policy recovery** cases: populated/empty gate and active-ingress stop,
with separate two-boot reports and absence audits. Frozen fixture `c665d4f`
uses the same Go bytes with 251 Linux pure tests/zero skips. Neither case can
satisfy the other's flags, and neither executes this unconsumed supersession
command. Its actual hardware/cut matrix remains an independent open gate.
