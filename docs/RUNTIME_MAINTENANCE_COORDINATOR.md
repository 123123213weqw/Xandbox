# Internal write-ahead maintenance coordinator

Status: **unexposed, incomplete lifecycle component, NOT an operational updater**.
There is no installer command, maintenance release, activation or reboot rollback
entry point. Runtime file selection continues to reject the drain/Stop namespace.
No ordinary administrative `resume` override or fence-deletion workaround exists.

## Actual effect ordering and old-format preservation

The new private `runtimeScope.maintain` stage holds the original installer OFD
operation EX across manager/proc observations, durable WAL, node RPC and receipt.
It acquires the original file flock only around file proof/persistence, releases
it before every manager/operator RPC, and does not reacquire an operation lease
inside the scope. Source/executable/argv/cgroup and fixed manager incarnation
proofs are required by the production adapter, not caller booleans.

The original drain WAL has an explicit **version 2** containing the entire
node-maintenance record: installed genesis digest, operation ID, original
process identity and original admission before-state. A domain-separated CAS
ID binds that complete input and differs from the operation ID. Original v1
canonical bytes and ordinary-drain adapter remain unchanged; neither adapter
silently adopts the other's journal. Unsupported node capability refuses before
namespace creation. There is NO ordinary-drain fallback.

1. Verify original installed/protected files, state-root binding and fixed
   main-unit process. Query maintenance capability/status without mutation.
2. Capture before-state once. Create/sync the original installer side namespace;
   persist/sync/rename/sync its full v2 intent **before any node write**.
3. Repeat process/manager/source and node-state proofs. Send only the recorded
   exact owner/CAS, or accept an exact already committed result. An inconsistent
   receipt, foreign owner, admission drift or peer incarnation refuses unchanged.
4. Requery and repeat proofs before persisting the exact intent-bound receipt,
   then requery again. A cached receipt is never current lifecycle authority.

A complete canonical original intent scratch can recover through a fresh root
FD/scope. Unknown empty/truncated installer intent refuses without inventing a
before-state or regenerating an owner from the current node. No namespace or
partial record is removed as a recovery shortcut. This is process-crash
recovery, NOT a proof of arbitrary hardware power-loss behavior.

The node's separate prewrite-failure model intentionally leaves no durable node
byte. The installer has already persisted its full intent/namespace at that
point: the **existing real cap0 startup verifier refuses that namespace**, even
if the original open node state remains. Tests execute that actual verifier
function, not a modeled stopped boolean. They do NOT qualify a real service
restart, a new source-compatible startup overlay or operational reboot recovery.

## Compose Stop, state ownership and exact pure authority joins

Physical Stop reads the original v2 WAL and requires a live matching maintenance
record, before/after state and pinned peer, not just ordinary drained status.
It still requires independent fixed manager, executable/placement and kernel
process/domain absence proofs. Stop is termination, NOT accepted-work success.
The original BSD state lease is acquired/retained only through the existing
Stop-bound identity contract. No replacement lock, unknown-PID signal or broad
resource cleanup is added.

Pure core readers accept maintenance files ONLY when joined to that exact v2
WAL. They require canonical `admission/maintenance.json`, the independent root
`maintenance.identity` hash, original admission epoch identity and exact drained
after-state. All state files retain bounded private single-link schema/path
checks; scratch/unknown/temp/link/mode/foreign-owner or drift refuses without
repair. Legacy v1 readers still reject both sidecars and an orphan root anchor.
No ordinary effectful constructor/Load is called as an inspection shortcut.

The complete core byte-set now binds admission state and both root identities
(and maintenance record when applicable), in addition to all ledger/session
bytes. It is reread across backend owner/jail/cgroup/project observations, so
semantically equivalent but byte-changed admission bindings cannot silently pass
a cached backend observation. The cold-only snapshot-nil installed policy and
metadata-only limitations remain unchanged.

The BEGIN/ordinary-drain/physical-Stop `AcceptedWorkComplete`,
`ResourcesReclaimed` and `ActivationAllowed` flags remain false. The separate
live finish-only stage is described in [accepted-work quiescence](ACCEPTED_WORK_QUIESCENCE.md);
it does not authorize Stop/reclaim/file selection/activation. A maintenance ACK, state lock or empty modeled backend observation
is not a successful work/full reclaim/activation certificate.

## Test boundary and missing operational work

The software tests use actual immutable installer files in private shadow roots,
real node FileStore/controller/Unix/pidfd/CAS, original OFD/BSD locks and owned
Go TEST subprocesses. Only manager/image/cgroup/mount/quota positive proofs are
modeled. Actual coordinator self-SIGKILL includes durable maintenance intent,
lost RPC reply, receipt rename, half-stopped ingress and retained state lock.
Every parent reaps only its own children. No systemctl, ordinary daemon, real
backend/quota query, VM/GPU, offered load, privileged host configuration or
installation deployment is executed by native qualification.

Existing guard, test repetition, resource/IO, source/secret-scan and historical
failure requirements remain unchanged. The lost-admission-directory + lost
epoch-identity/root-maintenance-anchor case now refuses BEFORE creating an empty
admission directory; it never recreates an authority and is covered by the
existing corruption suite.

Still required: complete all mutable-authority/version compatibility; explicit
durable lost-job outcome policy and real bounded owned-L1 Stop/reclaim; safely compose typed
file selection without nested locks or boolean gaps; source-bound maintenance
release restoring prior admission and ingress; held-process startup/health;
state-preserving failure/reboot rollback and original long-load acceptance.
The old startup fence always remains; real installs must NOT use this component
as an updater until these prerequisites and end-to-end acceptance are complete.
