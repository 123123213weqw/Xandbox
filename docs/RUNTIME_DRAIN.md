# Internal process-pinned write-ahead admission drain

Status: **incomplete update-coordinator component, not a public updater**.
No installer command or production coordinator calls `runtimeDrainAdmission`.
The ordinary operator CLI remains unchanged. Do not invoke this primitive on a
real installation instead of the missing lifecycle coordinator.

This is an effectful integration of the real private Unix operator protocol,
controller and persistent admission CAS, not a read-only report or a new
`stopped=true` override. Admission drain is **not** completion of accepted work,
physical Stop, process death, guest/jail/owner/quota reclaim or activation.

## Pin a process, not just a UID

The ordinary client authenticates the host UID and trusted private socket/root.
That is appropriate for administrative RPC, but insufficient to claim a reply
belongs to a particular manager incarnation. The additional Linux-only
`PinnedClient` opens a pidfd **before** reading the fixed kernel boot ID and
bounded process start ticks, checks liveness around metadata acquisition, and
requires both exact PID and UID from each connected Unix socket's SO_PEERCRED.
Its lease is checked before sending and after reading the bounded response.
Close is serialized with pidfd observations to avoid FD-reuse races; a closed or
dead lease cannot adopt a replacement server at the same path. Unsupported
platforms refuse rather than falling back to an unpinned client.

A nonblocking pidfd poll may return `EINTR`. It is neither process death nor a
successful liveness proof: repeat the same real probe at most four times while
holding the lease. An exhausted interruption budget or unsupported syscall is
still an error, never an unpinned fallback. The initial `4604e32` CI execution
observed interrupted-system-call failures in the new drain gate; those original
failures remain failed. Deterministic interrupted/live, interrupted/dead, signal
storm and unsupported-syscall controls accompany the corrective change; native
passes alone do not erase a CI failure or qualify the corrective commit.

The selected directory must also match the installer's independently anchored
fixed state-directory FD. The pinned client has **status, drain and maintenance begin/status**, no
resume or maintenance-release method. See [the durable maintenance fence](RUNTIME_MAINTENANCE.md). Drain success requires the exact expected epoch/revision/request
and closed admission, not merely a syntactically valid JSON response.

PID/incarnation binding still does NOT prove the process is the correct
executable, manager-owned, in its required cgroup, healthy, source-compatible or
permitted to operate the backend. Those are independent lifecycle prerequisites.
Exec in the same process does not change its incarnation. The tests do not claim
to induce kernel PID reuse or prove a real service's identity/placement.

## Write-ahead ordering and ambiguous outcomes

1. Hold the original installer operation OFD EX across the whole invocation.
   Take the original file flock only for on-disk proof/persistence; **release it
   before every operator RPC**. An internal typed `runtimeScope` can now retain the original operation
   lease across drain and the physical-stop stage without reacquisition. It
   serializes stages/close and rechecks original lock/root identity; it is not
   authority to select binaries.
2. Verify the exact original installation commit, installed/protected files,
   clean config inventory and anchored operator-root identity. This initial
   adapter refuses a runtime file-selection namespace. Repeat activation from a
   selected overlay requires the not-yet-implemented activation protocol.
3. Query ready, current node state without mutating it. Persist and fsync the
   complete intent under fixed `/etc/xandbox-runtime-drain`: original genesis
   hash, update request, exact process incarnation and original node state.
   Only then may a drain mutation be sent. The command is derived from those
   durable bytes, never regenerated on retry.
4. Requery current state. If still exactly original/open, send that one drain
   CAS. If it already equals the exact desired result, recover a lost response
   without advancing revision. Foreign changes, pending/fenced state, another
   request, process replacement or uncertain inventory refuse; never resume or
   overwrite the competing authority. A preexisting drained state is preserved
   byte-for-byte, without an extra mutation/revision.
5. Requery and revalidate installed bytes/identity before durably publishing the
   exact intent-bound drain receipt. Query the live current node again before
   returning. A saved receipt by itself is never current authority: a later
   foreign resume or dead/replaced process must not reuse it.

Unknown bytes, prefix conflicts, missing intent with a surviving receipt,
changed process/root or protected state are not repaired/deleted. Recognized
receipt/scratch bytes are verified against the exact intent BEFORE mutation;
a matching receipt with original/open authority is also a conflict, not
permission to replay an apparently rewound state. All records
remain for exact recovery. No policy/key/ledger/session/owner/quota snapshot is
restored. A post-commit error/cancellation/EOF is uncertain, not a rollback or
permission to send a different command.

The real startup gate and read-only clean-update inspection refuse this
maintenance namespace, **even if it is empty**. The standalone file-selection
engine also refuses it: a drain receipt is not permission to supply a modeled
stopped callback and start replacing binaries. No function removes this fence
or starts/restarts services. There is no operational recovery command yet;
offline/dead-daemon recovery, safe starting authority and lock-scope composition
must be completed before exposing a public executor.

## Software evidence boundary

Tests use actual private Unix sockets, SO_PEERCRED, pidfds and persistent
node-control file CAS, including same-UID wrong-peer/dead-peer replacement,
closed-lease/in-flight reply, exact command retry and valid-shape/wrong-CAS ACKs.
Installation executable bytes and manager ownership remain test-owned models;
the operator server runs inside a Go test ELF, not an ordinary sandbox daemon.
Reported resource counters are deliberately not treated as reclaim evidence.

Ten selected persistence/RPC error cuts and three real coordinator-child
self-SIGKILL cuts exercise recovery while the parent test operator server stays
alive with the same incarnation. Parents require a signaled SIGKILL exit, not
`os.Exit(137)`. These are software crash boundaries, not storage power loss,
daemon replacement recovery, a systemd gate, reboot or KVM/long-load acceptance.
Only known test children may be terminated; no unknown/shared host PID, service,
VM/GPU, network/mount/quota configuration or deployment is involved.

## Still required for the complete goal

Real manager/executable/cgroup ownership and held-PID health; source-bound
all-authority backward readers; accepted-work completion; physical Stop and
independent full cgroup/jail/owner/quota reclaim; retained-image activation and
failure/reboot rollback; safe ingress and prior-admission restoration; staging
budget and owned-L1 fault/long-load qualification. Existing failed sustained-load
results, resource/asset/IO ceilings and actor/offered-clock/benefit gates remain.
The broader production goal is not replaced by this admission-only component.

## Explicit exclusive-maintenance v2

The old v1 ordinary-drain adapter and canonical bytes remain unchanged. The
new [maintenance coordinator](RUNTIME_MAINTENANCE_COORDINATOR.md) writes an
explicit v2 intent and refuses v1 adoption or ordinary-drain fallback. Its node
CAS ID is distinct from the installation operation ID. Physical Stop and typed
core/backend joins must verify the v2 owner as well as admission state. Neither
version is a public updater or permission to select/activate runtime files.
