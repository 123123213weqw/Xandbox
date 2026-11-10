# Internal scoped physical-stop protocol

Status: **incomplete coordinator component, no public updater command**. No
production entry currently invokes this maintenance sequence on an installation.
Software/model acceptance below is not actual systemd/KVM, upgrade, power-loss,
reboot or sustained-load acceptance. Never invoke the internal component on a
real host in place of the missing complete coordinator.

## One original operation scope, not nested locks

`runtimeScope` retains the original zero-byte installer OFD EX descriptor across
the actual write-ahead drain and physical-stop stages. It revalidates the root,
original lock inode/mode/size, serializes stages against close, and rejects a
closed/rebound/missing lease without recreating it. No public borrowed FD, root
selector, force or bypass flag exists. File flocks cover only on-disk proof and
records; none span operator RPC or manager jobs. Read-only startup does not take
this operation lock, avoiding a manager/ExecStartPre self-deadlock.

The scope is **not** permission to replace files. Standalone file selection
still refuses drain/stop maintenance namespaces. Complete accepted-work and
reclaim proofs plus the activation protocol remain required before integration.

## Physical stop is independent of full reclaim

The fixed production entry uses the original managed/enabled unit composition,
exact original genesis and protected files, current admission drain and its
intent-bound receipt. It verifies the selected live main process against the
committed ordinary daemon hash, exact argv and fixed node/control cgroup; the
ingress controller has its existing exact gateway/argv/cgroup verifier. Kernel
pidfds are opened before identity capture. A process incarnation is not by
itself executable or placement authority.

Persist/fsync the exact stop intent **before** any stop job: original base,
request, drain-intent digest and both expected process incarnations. Stop only
the fixed ingress unit, then the fixed main unit, using dependency-ignoring
manager jobs. No arbitrary process signal, unit, command or caller-selected
kernel path is exposed. Recheck both units/incarnations, source/protected bytes,
links and original lease before effects; foreign drift refuses without restoring
old authority or restarting a service.

New v2 intents additionally bind original state-root/controller-lock identity and
verify the original live main process's actual kernel BSD lock. The later owned
state lease and core inventory are described in [RUNTIME_STATE.md](RUNTIME_STATE.md).
Earlier v1 physical-stop recovery remains supported but cannot gain that stronger
state authority or be silently rewritten into a v2 proof.

Each stopped stage requires **all** of:
- expected manager composition and inactive/failed state with `MainPID=0`;
- still-open original pidfd reports actual exit (`POLLIN`, optionally `POLLHUP`),
  not merely an EOF, closed descriptor or successful manager response;
- a fixed, real cgroup-v2 parent plus complete bounded subtree emptiness and
  unfrozen state, not just root `cgroup.procs`, stats or the manager's PID.

The generic empty-domain helper accepts only the two fixed unit names. Ordinary
filesystem fixtures cannot impersonate kernel absence. These read proofs never
freeze, migrate, signal, delete or rewrite a cgroup. A persisted stop receipt is
rechecked against fresh manager/kernel observations on every retry.

The resulting `ExecutionStopped` is **not** `AcceptedWorkComplete`,
`ResourcesReclaimed` or `ActivationAllowed`; those fields stay false. Termination
does not mean requests succeeded, session/ledger state is terminal, jails/owners
and quota reservations were released, or a new runtime may start. No snapshot of
auth/policy/keys/node/session/ledger/catalog/owner/quota state is restored.

## Interrupted recovery

Records remain intact. Exact retries can finish matching intent/receipt prefixes
without reissuing a stop for an already stopped original unit. After the operator
is dead, recovery does not require a live RPC client: it requires the saved exact
drain/stop chain, unchanged installed files, inactive fixed units, kernel absence
of the original numeric PID or a matching live kernel lease, and empty domains.
A reused/different live process identity is a conflict, **never permission to
signal it**. Missing/unknown records, premature receipts, concurrent replacement,
frozen/populated groups, surviving original processes and uncertain reads fail
closed. No recovery command or automatic restart is exposed yet.

All maintenance namespaces remain startup and clean-inventory fences, including
an empty stop directory. Physical-stop success never removes them. No start,
resume, reset-failed, file selection or automatic admission restoration follows.

## Evidence limits and next integration

Software tests use real private Unix admission/file CAS, kernel pidfds and
parent-owned Go **test** subprocesses that the parent alone terminates/reaps.
Manager jobs, executable/placement ownership and cgroup contents in positive
controls are explicitly **models** in anchored, test-owned filesystems; the real
production proof rejects those model executables/domains before any stop job.
Thirteen selected error cuts exercise intent, stage ordering and receipt
recovery, including an already-dead operator. Four additional actual coordinator
self-SIGKILL cuts use bounded inherited pipes: the parent alone performs modeled
manager operations and terminates/reaps its own test helpers. Fresh coordinator
FDs recover even after the operator has died. These controls do not prove systemd
job semantics, media power loss or a real guest's Stop latency.
Existing inherited CI process-smoke gates separately execute ordinary binaries
in explicit Mock mode on ephemeral runners, not real services/KVM or deployment.

Next: source-bound all-authority compatibility; actual accepted-call completion;
independent full runtime/jail/cgroup/owner/quota reclaim under exclusive ownership;
held-PID health and cap0 overlay activation; prior-admission/ingress restoration;
failure/reboot state-preserving rollback; staging accounting and guarded owned-L1
qualification. Original long-load failures, unexplained metadata exit, resource/
asset/IO/benefit ceilings and actor/offered-clock requirements remain unchanged.
The full production goal is not replaced by a software/model physical-stop test.

## Explicit known-work composition

The internal [work-bound Stop coordinator](WORK_BOUND_STOP.md) adds explicit v3
intent binding to an independently anchored positive original-live cohort
receipt BEFORE Stop effects. All original v1/v2 canonical bytes and the ordinary
physical Stop result remain unchanged (accepted-work/full-reclaim/activation
flags false). v3 requires the strict completion/source/process/state plan link
on every Stop/state recovery, never caller counts or adoption of replacements.
This is not an operational updater, full reclaim or real KVM acceptance.
