# Write-ahead runtime closure before update-only Stop

Status: **experimental internal installer composition; not an operational
updater, full-host reclaim proof, release or production qualification**.
No public command or file-selection consumer is added. Real owned-L1 KVM,
upgrade/rollback/reboot and original long-load acceptance remain incomplete.

## Actual sequence

`runtimeScope.finishAndStop` now calls the bound runtime-close actuator before
physical Stop, on its SAME original operation OFD. The existing finish-only
work intent, exact maintenance Before/owner, original process/state identities,
known-work completion and independent work anchor are preserved.

1. Reprove installed source, manager units, original live Unix peer/pidfd and
   original BSD state-lock holder. Require the known successful frozen cohort.
2. Persist and fsync `/etc/xandbox-runtime-close/intent.json` BEFORE BEGIN. It
   binds the original work intent SHA and full original v3 work/Stop plan, hence
   the source, maintenance Before/owner, original ingress/main and state root.
3. Call ONLY the pinned original `runtime-close` protocol. Poll status under the
   caller's bounded context; no file flock spans RPC or manager observations.
   The real Broker/Core actor retains its existing independent 5s + 5s budgets.
   An unsupported endpoint never falls back to physical Stop.
4. Require real `closed`, identical frozen work and both valid semantic closure
   observations. Rejoin source/work/manager/original process/state, query the
   same original terminal reply again, then persist/sync `complete.json` and
   the independent `/etc/xandbox-runtime-close.identity` SHA anchor.
5. Only then publish explicit **v4 Stop**, binding that exact close completion
   digest. Existing fixed ingress-before-main Stop, whole-domain exit checks
   and original BSD state-lock retention still run. All v1/v2/v3 canonical bytes
   and separate physical-only APIs remain unchanged; older versions cannot
   carry the new field. A legacy work-only receipt cannot satisfy v4.

## Recovery and refusal

The original known-close receipt plus its independent full anchor can survive
coordinator and original-daemon death. Fresh scope recovery must verify the
entire original source/work/drain/close chain, original state identity and live
original peers OR their numeric PID absence; replacements are not adopted.
The exact canonical full scratch records are re-synced/published before effects.
Unknown prefixes, duplicate final/scratch, modes, links, extra paths, foreign
plans, modified outcomes/anchors and mismatched process/state refuse unchanged.
No current paths, counts or replacement daemon can reconstruct unknown work or
closure. A full unanchored completion requires the SAME original live peer to
confirm its exact outcome before an anchor can be created. Known work alone is
no longer enough to initiate Stop after original-daemon death.

BEGIN is irreversible after acceptance; a caller timeout/disconnect does not
undo actor cleanup. The durable intent allows the same original peer to report
that outcome later, without spawning a new close. No missing reply is success.
Failed cleanup is sticky fenced, with no completion/Stop/file-selection proof.
This is process-crash recovery with honest fsync, not malicious-root rewriting
resistance or arbitrary media/power-loss attestation.

All close namespaces (including orphan/empty/scratch forms) fence the actual
cap0 startup, raw file-selection engine and read-only update inspection. They
are not deleted or automatically repaired. Normal install/update remains
fenced until the complete activation and recovery protocol exists.

## Remaining production work — not hidden by this receipt

The recorded hashes project sorted **semantic** terminal records from actual
runtime actors. They do not attest raw original state byte sets, all orphan
namespaces, complete UID/project/quota ranges, catalog/backing/pin authority,
or every control writer. Those original-state-held joins remain mandatory
before file selection. There is no production activation, maintenance release,
prior admission/ingress restoration, health handoff or rollback integration.

The file vector includes the installed installer itself: retained self/source/
schema compatibility or a compatible monotonic controller is still needed.
Blindly restoring old cap0 SelfPath and deleting fences is not rollback.
Normal Core Cleanup still discards in-memory outputs; successful task completion
is NOT client delivery or lossless update. Result retention/delivery and known
frozen failed-work policy still need explicit product/protocol decisions.

## Evidence boundary

New tests exercise real private files, fsync/OFD/BSD locks, private Unix and
pidfd, real controller/Broker/Core terminal paths and owned test-child death.
Actuator failure uses a controlled mock Cleanup error, not a host process or
VM. Manager/image/placement/cgroup/mount/IO/quota positives remain models.
Named error cuts are not SIGKILL; the separate coordinator crash cases perform
actual owned self-SIGKILL. Neither test form is real KVM/systemd acceptance.
No ordinary daemon, privileged backend constructor, real quota query/mutation,
VM/GPU, offered load, host configuration or deployment is run on the shared
original node. Current source requires its own acceptance evidence; older
software green checks do not qualify this new composition.
