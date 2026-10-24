# Managed policy v2 — native candidate, not hardware acceptance

Follow-up: [forward-recovery foundation only](POLICY_RECOVERY_FOUNDATION.md) adds
existing-state/operation-lock prerequisites, **not an expired-policy recovery
command**. The native record below remains bound to its original source.

**Experimental, not production ready.** This adds a real code path from the
installer through the root gateway's durable store, sealed child transfer and
child ACK. It is not a new root CLI/systemd/TLS/KVM/cold-rotation qualification.
The [native record](validation/managed-policy-native-v1.json) binds the actual
source and software evidence; older hardware reports retain their original
sources and ELF hashes. In particular, a new gateway binary does not inherit
[the historical v1 initial-install proof](INITIAL_INSTALL_KVM.md).

This is a **fresh opt-in composition**, not permission to replace an old
self-pinned installer or convert an existing v1 node. Backend authority, node,
release, executables, self pin, tenant socket, UID/GID, listen address, SNI and
resource bindings stay immutable. No host task execution or fallback was added.

## Composition versions

- Plan v1 retains the original 25 targets and separate, immutable TLS inputs.
  Its existing SIGHUP protocol is unchanged for valid policies. It cannot use
  the managed reconfiguration command.
- Plan v2 requires `policy` (a private SHA256-pinned **initial PolicyEnvelope**),
  and zero legacy `certificate`/`private_key` assets. It installs 24 targets:
  the two TLS files are replaced by one `/etc/xandbox-install/gateway-policy.json`.
- Gateway Config v2 requires the fixed `managed_policy_file`, the exact
  `initial_policy_sha256`, base `policy_revision=1`, and no legacy certificate,
  key-file or inline-key inputs. A payload's actual epoch is not the base revision.
- Only this opt-in ingress unit adds a dedicated 0700 manager runtime directory
  for the [operator channel](POLICY_OPERATOR_COMPONENT.md). It stays outside the
  durable store's closed inventory; capability/resource limits do not expand.
- Existing source/config pins, static ELF role validation and the cap0 main-unit
  pre-start verifier remain mandatory. No mutable symlink release switch exists.

## One atomic authority and payload

A separate mutable policy file plus separate rotation authority leaves an
avoidable rename window. Instead, `gateway.PolicyEnvelope` is **both** the one
atomic authority and its complete Snapshot. The initial envelope has revision 1,
zero rotation metadata and whole-file bytes pinned by the immutable base config.
A later envelope binds all of:

- the unchanged initial install-commit SHA256;
- the canonical immutable managed Config SHA256 and original payload anchor;
- the exact next revision, its predecessor and a 32-lowercase-hex request ID;
- the private source Snapshot path and **raw input** SHA256;
- the complete coherent certificate/private-key/key-mapping Snapshot, with
  matching UID/GID/listen/SNI and epoch.

Envelope JSON is canonical and bounded to 512 KiB. The source Snapshot may have
ordinary JSON formatting: its raw SHA256 is distinct from the canonical Snapshot
digest reported by the operator. Marshal/size failures are rejected **before**
policy-store collection or commit, rather than hashing a failed marshal.

The original `commit.json` is never rewritten. Full verification recognizes only
this typed v2 policy authority as an override of **one** target. All other file
hashes/modes/inventories and generated manifests/units remain exact. A valid-looking
payload cannot waive a backend or executable pin. Initial payload sizes remain
checked against their original target record, too.

## Transaction and recovery order

The production CLI has one new fixed operation (syntax placeholders below are
not real credentials or an executable deployment plan):

```text
xandbox-install reconfigure -plan PRIVATE_PLAN -expected-revision N -request-id REQUEST
xandbox-install reconcile -request-id REQUEST
xandbox-install status
```

`RotationPlan` is closed `{version:1, policy:Asset}`. Its policy asset is a private
complete **Snapshot**, not an envelope: it must have epoch `N+1`. No shell, unit,
backend selection, reset/force flag or arbitrary target path is accepted.

1. Lock the original existing installation lock exclusively; never manufacture
   a missing lock. Check self/base/immutable targets. Fresh requests require an
   exact active policy observation. The initial request ID is reserved; the
   current last request cannot be reused for another revision.
2. Validate the source's actual bytes, coherent TLS pair, backend owners and
   immutable frontend bindings. Construct the full next envelope.
3. Persist a bounded typed `rotation-intent.json` binding old/new payload hashes,
   request, predecessor, base/config/initial anchors and source pin. Its only
   intent scratch name is `.rotation-intent.next`.
4. Write/resume `.policy.next` only as an exact byte prefix; sync it. Recheck the
   old installed file and inode, then rename the complete candidate over the
   fixed policy file and sync the directory. This rename publishes authority
   and policy together, not two independently mutable commit files.
5. Verify the complete installation again. **Keep the matching intent** while
   releasing the exclusive lock, then reconcile real activation. File publication,
   socket submission and a `waiting` response are not a completed activation.
6. After exact ACK observation, reacquire the exclusive lock, recheck the same
   base, request, source metadata, full files and current policy ACK, and remove
   only the matching intent with directory sync. Then return the closed receipt.

Recognized scratch files and an intent whose new payload is not visible refuse
startup and status confirmation; they do not revive an old credential policy.
Recovery accepts only the exact declared candidate/prefix. Unknown files, modes,
hard links, nonempty managed lock contents or mismatched intent bytes are not
repaired, collected, truncated or adopted.

A complete candidate scratch can finish recovery without rereading its source;
a partial scratch still needs the pinned original input. Once the authority is
published, exact retry and `reconcile` use the installed envelope/intent even if
source Snapshot files disappear. An absent plan file requires `reconcile`, not
reinterpreting missing arguments. Older requests cannot operate on a successor's
pending intent; there is no unbounded request-history registry.

## Runtime ordering and ingress-only recovery

The root gateway shares the **original installer lock inode**, including during
an ingress-only start, and holds the shared proof through the corresponding ACK.
It verifies the pinned base reference, envelope and any visible intent; it refuses
transaction scratches. A concurrent writer therefore cannot publish between an
older startup read and that startup's activation. This matters even when the main
service is already running and its pre-start verifier is not rerun.

The supervisor remains the single writer. A new command validates a complete
installed envelope, seals it, publishes `committing`, commits the real durable
policy store, publishes `waiting(next)` retaining the previous ACK facts, and
transfers the sealed descriptor over the unchanged child protocol. Only the exact
child `opReady` changes the observation to `active`. Postcommit failure fences
and closes ingress; it does not restart or resume the controller or guests.
An exact duplicate is an observation: no second commit, seal or transfer.
Managed v2 does not use SIGHUP; a stray SIGHUP closes this ingress path.

The installer checks root peer credentials and a pidfd-pinned manager incarnation,
exact gateway executable SHA256, argv and cgroup before/after the RPC, then checks
fresh manager and file state. `active` remains an ACK observation, not TLS health,
request cancellation or an SLO. A submitted command may outlive a response timeout;
a lost response is observed, not handled by blindly repeating a signal.

Policy recovery may start **only ingress**, while the observed main process must
stay active and the same incarnation. Its fixed administrative start uses
`--job-mode=ignore-requirements`: ordinary start could otherwise pull in BindsTo's
main after a concurrent stop. This omits requirement activation while retaining
ordering, as documented for [systemd v255](https://github.com/systemd/systemd/blob/v255/man/systemctl.xml).
There is no policy-recovery main start/restart/stop/reset or node `resume` command.
Initial installation reconciliation still explicitly starts main, as before.

Receipts keep five fields and `production_ready=false`. For v2, `revision` is the
current policy-envelope epoch, not a binary-release revision. `files_committed`
and `manager_reconciled` remain separate. An old ACK cannot certify a newer file
revision observed during final verification.

## Evidence and remaining gates

Native tests cover actual Linux durable policy-state files, sealed memfds and
inherited sequence-packet transfer; their ACK receiver is modeled. Installer
software tests use an anchored **shadow root**, model artifacts/manager responses,
real filesystem sync/rename/locks and actual test-process deaths. They are not
ordinary root CLI, real systemd, actual gateway child/TLS or KVM evidence.
Historical independent transport tests remain bound to their own source.

Required before feature acceptance: a fresh owned L1 composition, ordinary root
CLI, exact live supervisor/child/manager identity, coherent leaf plus external-key
rotation, old-key rejection on the same existing TLS transport, a continuing real
KVM writer, no controller/guest restart, exact retries/conflicts, persisted drain,
real cuts around publication/ACK, original-disk cold recovery and independent
cleanup audit. Any changed runtime artifacts need their own qualification; do
not re-sign old ingress or v1 installation reports.

Known unfinished edge: a committed policy that **never obtained its ACK and then
expires** cannot currently be superseded through this strict pending-intent API.
Forward recovery needs an explicit bounded design and tests; deleting the intent,
restoring an old credential policy or reusing an epoch is not a supported workaround.
Already-admitted requests may finish with an old snapshot; rotation is not guest
execution cancellation. Backend-authority migration, self-upgrade/rollback,
consistent backup/catalog operations, audit retention and saturation/SLO gates
also remain unfinished. This checkpoint does not complete the production goal.
