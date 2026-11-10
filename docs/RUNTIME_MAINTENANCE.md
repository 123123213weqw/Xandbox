# Internal durable maintenance admission fence

Status: **begin-only coordinator component; no operational updater**. No
installer command, release or production coordinator uses this protocol yet.
Do not call it on an installation as a substitute for an updater: **there is
currently no release/end/resume path for a held maintenance fence**. It must not
be enabled in production before safe lifecycle integration and recovery exist.

Ordinary administrative drain is reversible by ordinary `resume`. That is not
an exclusive update lease. This component adds a persistent, immutable owner
which ordinary drain/resume cannot bypass once durably recorded, including after
process restart.
It does not stop accepted work, signal a process, select files, change budgets,
release backend resources or authorize activation.

## Durable protocol and ordering

The original admission `State` and normal `/v1/node` reply remain version 1.
A separate private Unix endpoint `/v1/node/maintenance` supports GET capability/
status and POST begin. POST binds an exact installed-commit SHA256 and operation
ID to the original admission epoch/revision and a distinct CAS request ID. The
caller must first persist its own operation WAL; **the installer WAL adapter is
not implemented here**. A digest in this request is an owner label, not proof
that installed executable/config bytes were verified.

1. Under the controller's original state ownership and serialization with all
   ordinary drain/resume commands, validate CAS, cache the immutable owner and
   close NEW admission **before any persistence**. Do not hold the controller's
   memory mutex over I/O. Status and accepted tickets remain usable.
2. Create fixed `admission/.maintenance-next` exclusively; write the complete
   canonical record containing request and before-state, fsync, rename to
   `admission/maintenance.json`, then fsync admission and root directories.
3. Persist a separate root `maintenance.identity` binding the canonical record's
   SHA256. Its independent anchor detects loss of a single final fence. Missing
   admission identity while maintenance artifacts exist is an error, not fresh
   initialization. This is NOT rollback protection against an arbitrary
   privileged restore of BOTH fence and anchor.
4. Only after these barriers, commit the exact original admission CAS to drained.
   If it was already drained, preserve original state/revision/last request,
   without a gratuitous transition. Reload and verify exact record and state
   before acknowledging success.
5. A failure/lost reply retains memory ownership and closed admission. The exact
   live owner may retry an identical prefix, never truncate/replace a foreign
   prefix. Unknown-owner empty/partial scratch after process death refuses
   startup **without repair**. A complete canonical scratch/fence is recoverable
   before the startup gate can open. Recovery must hold the original exclusive
   state lock, not a newly invented competing lock authority.

A failure before ANY durable byte can leave no maintenance artifact. The live
controller still fences, but after process death the original open state may
remain. Only the caller's independently durable WAL/startup fence can close
that gap. That mandatory integration is NOT supplied here. Never infer that a
failed begin alone durably fenced an installation, or deploy this endpoint as a
complete update protocol.

The file store independently refuses ordinary transitions while a fence exists.
There is no forced adoption, fence deletion, snapshot restoration, new epoch,
release or automatic restart-resume API. A blocked writer retains ownership:
controller Close must finish before a daemon releases its state lock. Accepted
cancellation never reopens admission, and Close cannot produce a late positive
acknowledgment.

## Private client, authority and compatibility

Only the existing Linux incarnation-pinned client exposes begin/status. It
requires exact SO_PEERCRED PID/UID, trusted private root/socket identity and a
live pidfd before sending and after reading the bounded response. Begin success
also requires the exact caller-supplied before-state, owner/request and derived
after-state, ready phase, closed admission and no pending request. Unsupported
legacy endpoints refuse; there is **no ordinary-drain fallback**. No tenant token,
TCP endpoint, arbitrary path, release route or unpinned fallback is added.

This does NOT verify process executable/source, manager ownership, cgroups or
health. Those remain separate caller prerequisites. The current isolated
`installtxn` core inventory rejects these new sidecars by its closed inventory;
it does not yet join or adopt them. Older source readers likewise fail closed
on the unknown admission entry. Unchanged v1 state is therefore **not a claim
that the old/new complete authority graph is update-compatible**.

## Qualification and remaining work

Tests cover exact restart replay, preexisting drain, all ten named write-ahead
error cuts, matching partial-prefix retry, foreign/missing/malformed/link/mode
bindings, closed and canceled writers, concurrent status and preserved accepted
tickets, strict HTTP/JSON and forged/legacy replies. Linux tests use real private
Unix sockets/pidfds and test-owned Go subprocesses with the original BSD flock
primitive. Eleven actual child self-SIGKILL boundaries include empty and partial
scratch: complete records recover; unknown prefixes remain refused. Parents reap
only their own children. These are process-crash tests, **not power-loss tests**.

CGO-free and race runs are additive to all inherited runtime gates. They execute
no systemctl, installer CLI, real backend/quota, VM, GPU or offered-load workload.
The shared-host software supervisor and headroom checks are NOT hard kernel
per-job quotas.

Still required: persist/join installer owner WAL and all mutable authorities;
coordinate accepted-work policy and real drain/Stop/state-lock handoff;
independent full backend reclaim; typed file selection; held-process startup/
health; source-bound release/restoration of prior admission and ingress;
state-preserving failure/reboot rollback; bounded owned-L1 systemd/KVM tests and
original long-load acceptance. All old failure evidence and resource/benefit
limits remain unchanged. This component is not a new release or production claim.
