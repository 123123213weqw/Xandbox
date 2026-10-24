# Opt-in fresh managed-v2 owned-L1 fixture — not yet executed

**Test harness implementation/pure controls only. No new root CLI, ptrace,
systemd, real kernel-positive, TLS/KVM or cold acceptance is claimed yet.**
The [new proposal supersession code](PENDING_POLICY_SUPERSESSION.md) and its
changed binaries cannot inherit old installation/ingress reports. Runtime Go
source remains pinned to `9db9603`; the launcher must require a successful fresh
native qualification, compare all declared current ELF hashes, and retain its
own separately frozen harness source/inputs and raw report.

`kvm_systemd_host.py --managed-assets PRIVATE_MANIFEST --managed-case CASE` is
exclusive with all older profiles. The closed cases are `populated-gate`
(default) and `active-stop`; each needs its **own fresh disk, launch and report**.
The case is stored in private image metadata, echoed in every closed reply and
bound across the original-disk cold checkpoint. A result from one case cannot
satisfy the other case's flags. Case selection without the managed profile is
rejected before image work. It starts only from `configure_root`, not an existing deployment.
The image stages exactly 13 release roles plus installer, publisher and the
opt-in managed PKI producer. No ordinary main/ingress unit, production state or
installation is preinstalled. Old v1 builder source pins are not reused for the
new programs. Each input must be regular, bounded and SHA-pinned; program roles
also pass the existing static-ELF validation.

The existing 16 GiB / CPU12 / 24 GiB disk, no-NIC, launcher UID/netns/cgroup/lease
bounds and test operator limits are unchanged. Building is offline extraction
and metadata assembly only: no chroot, downloaded userspace/VMM execution on L0,
shared host service/module/mount/quota/sysctl/network mutation or task fallback.

## Intended actual checks (not results)

1. Ordinary root publisher and Plan v2 initial installation with 24 targets.
   Trace only the operator's own freshly forked, exact-ELF installer at fixed
   commit-scratch entry; kill/reap it, then observe the real cap0/NNP pre-gate
   refusing before daemon/binding creation. Exact root apply recovers and starts
   both ordinary services automatically. Private observer copies retain raw Go
   backend/auth/launch bytes. Remove only the exact original source/bootstrap.
2. Four independent real TLS-created KVM guests, real UID/ELF/caps/seccomp,
   project quota and tenant/node refusals. Record actual main and four VMM
   incarnations plus guest boot identities.
3. Produce a one-minute synthetic leaf for policy 2. Trace the own root
   `reconfigure` child at **operator connect entry after file2 and intent2 have
   published**, then kill/reap it before activation. Ignore the normal precommit
   status connection, including absent intent. Require the real gateway durable
   store still at epoch1, existing ingress incarnation unchanged and file2 present.
4. ACK a real drain and wait for leaf2's actual NotAfter using the L1 clock; no
   clock changes. Generate valid policy3 from the installed immutable backend/CA.
   Admit the original 45-second busy writer **after** that wait, rather than
   pretending a job that expired during the minute is still running.
5. Run exactly the selected maintenance case:
   - **`populated-gate`:** stop only ingress using the fixed dependency-isolated
     administrative command. Fork one inert test child, place **only that owned
     child** into the fixed L1 ingress cgroup, and require actual `populated 1`.
     The manager must show no main PID/inactive. Root recovery3 must refuse,
     leave durable epoch1 and main intact, and have admitted its exact recovery
     declaration. Kill/reap only that child; require absent or real empty/unfrozen
     group and exact same-request recovery3 success with actual store/child
     epoch3. No cgroup freeze or production-process migration is introduced.
   - **`active-stop`:** require the original actual root/child ingress pair still
     active and the durable store still at epoch1 immediately before recovery3.
     Do **not** manually stop a service, insert a test process or write cgroup
     membership. Only the production root CLI performs maintenance. Require its
     exact epoch3 receipt, actual fresh child ACK/TLS and absence of both old
     process incarnations. The common checks still prove main/VMM continuity.
6. Same main/VMM incarnations, guest boots and busy execution still progress;
   the entire acknowledged drain commit is unchanged. New TLS leaf/key material
   is coherent, and the old token fails on a new policy3 TLS transport which then
   accepts the new token without replacing that transport. The old policy1
   transport is intentionally closed by maintenance; this is **not** an ordinary
   hot-rotation claim about retaining that old transport.
7. Remove the exact new source, reconcile the same request without service restart,
   and refuse a conflicting CAS. Resume only through a separate explicit root CAS
   **after** proving drain preservation. Observe physical Stop separately from
   durable DELETE/reclaim and capacity, then the existing warm-drain/session and
   original-disk cold workflows, no implicit resume, quota/private-resource release
   and independent external owned-scope cleanup.

All task argv crosses ordinary controller/guest APIs, never a host task route.
The inert negative-control child only blocks on its own pipe; it is not a task
executor. Raw credentials/refs/console/process identities remain private.

## Deliberately separate qualification gates

The `populated-gate` CLI sees an already stopped ingress for its population
differential; that case alone cannot qualify the active-unit production-stop
branch. The separately implemented `active-stop` case does not exercise the
population negative control. **Neither case has been executed yet.** Both
source-bound actual scopes and independent absence audits remain required.
Uncommitted supersession, its repeated-failure/cut matrix,
all remaining filesystem/media faults and current-artifact runtime/SLO matrices
also remain required. An eventual pass of this named profile must not be expanded
to any of those claims, a full production milestone or the whole goal.

The pure unit controls validate assembly exclusivity, closed messages/receipts,
trace predicates/guards, old-versus-new activation observation, timing order,
negative-control ownership, case isolation/cold binding and failure reporting.
They do not execute the above
actual checks. Only actual source-bound reports and independent resource audits
can change their acceptance status.

The frozen two-case source `848b814` passed 249 pure tests on Linux with zero
skips, and 249 on macOS with five platform skips; the native Go qualification
used `6173527` and its earlier 247 pure tests. All runtime Go bytes remain the
same `9db9603` composition. See the [separate software evidence](validation/pending-policy-supersession-native-v2.json).
Neither these pure tests nor rebuilt binaries make either L1 case an actual pass.
