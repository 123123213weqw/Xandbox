# Joined stopped-state inventory — still not file-switch permission

This internal component closes a specific missing connection: the known
original actor's terminal-record proof, the stopped-backend inventory, and the
**complete current installed cold Firecracker state namespace** were separate
observations. `runtimeScope.inspectClosedState` joins them under **one** held
scope mutex, original operation OFD lease and original daemon BSD state lease.

It does **not** make the existing file-exchange engine operational. That engine
still rejects maintenance namespaces, and startup remains fenced. Removing
those refusals before retained-self/source compatibility, result semantics and
activation/rollback recovery exist would be a bypass, not integration.

## Original authority and complete current namespace

Require a bounded context and the SAME live opaque stopped-work proof. Reuse
the original terminal and backend implementations; their bodies are extracted
without changing their validation, policy, wire, directory or effect behavior.
The old standalone wrappers still run their original validation and scope guard.
No report supplied by a caller, persisted digest or stopped boolean is accepted.

1. Rejoin the entire original v4 work/close/Stop/source/anchor chain, actual
   manager/kernel absence and original FDs; compare complete raw terminal
   records with the known actor closure, as before.
2. Enumerate the **entire** current state root, requiring controller lock,
   admission/identity/maintenance, ledger, sessions, cold Firecracker registry
   and diagnostics. Refuse every unknown, missing, temporary, catalog, result,
   mock-backend or other namespace rather than skipping it. Future persistent
   state requires an explicit compatible reader; this is not a generic walk.
3. Stream a bounded raw/stat footprint of every ordinary file, every directory
   and each optional fixed socket entry. Bind device/inode, owner/group, exact
   type/mode, hard links, size, modification/change times and all raw bytes.
   Ignore only access time. Use independent directory descriptions, complete
   sorted bounded names and no-follow stable FD/path checks. One bounded record
   at a time; existing ledger/session ceilings are unchanged.
4. Run the complete old stopped-backend inspector and require its resources
   absent, including all reserved-project observations. Its complete core raw
   authority must match the known terminal observation, not only record counts.
5. Rejoin the terminal observation. Repeat read-only quota/cgroup/jail absence
   after manager callbacks; then check original source/WAL/anchors without more
   manager/kernel-model callbacks. Finally reread the complete root footprint
   and require equality. A raw-format-only rewrite during the observation is
   drift too. Any failure returns **zero**, never a partial joined report.

The current installed composition is cold-only; no snapshot capability, catalog
or backing migration is silently enabled. Its unchanged source/genesis checks
still verify protected backend assets. This is not a reader for arbitrary
snapshot-enabled installations or a proof about unrelated host namespaces.

## Diagnostics and sockets are not operation results

Diagnostics must contain exactly the original empty private logger lock and
fixed-size event ring. A new **pure bounded byte-snapshot decoder** shares the
EXACT ordinary committed-window readers, via `io.ReaderAt`. It opens, locks,
syncs, repairs and creates nothing. Version/scope/CRC/frame/closed-enum checks
and torn-bank/staging semantics are unchanged. The footprint binds **all** ring
bytes, even staging bytes the ordinary reader does not treat as committed truth.
The snapshot parser alone proves no writer absence or durable operation result.

Optional `api.sock` and `operator.sock` may only be private single-link owned
socket entries. `metrics.sock` additionally requires the **original immutable
launch policy** to enable metrics. These entries are statted, never connected,
unlinked, claimed dead or adopted as a replacement endpoint. A socket's metadata
does not establish endpoint liveness/absence; this remains an observation, not
permission to replace it. Complete execution-domain proofs are separate.

The raw footprint binds this **one observation**, not exact historical raw
bytes. A fresh observation may accept a stable, ordinarily compatible format
rewrite; no new historical anchor or replay authority is invented. This does
not certify result retention/delivery, every diagnostic event, fsync/media
durability, erasure or malicious-root resistance.

## Safety and remaining product work

`ClosedStateJoined` denotes only the joined observations above.
`ResourcesReclaimed` and `ActivationAllowed` remain **false**, as do the original
component authority flags. No public CLI, lifecycle release, file consumer,
startup unfence, installer self-pin change, ordinary daemon/driver constructor,
mutation quota selector, repair, GC or deployment is enabled.

Positive manager/image/cgroup/mount/quota controls remain explicit **models**.
New tests use actual owned TEST-child Unix/pidfd/OFD/BSD and ordinary persisted
schemas; a Firecracker metadata label still wraps MockDriver, not a VM. The
diagnostic scope-bound integration ring is explicitly synthetic; separate tests
compare the pure decoder against the actual ordinary diagnostic writer/reader.

This adds fresh bounded reads, including repeated quota inventory. It is **not
a performance optimization**, same-IO change, hard syscall-deadline guarantee,
original-node cap fit or KVM/long-load qualification. Original test vectors,
cases, repetition/order, resource/IO ceilings and timeouts are not weakened.
All earlier native/long-load failures and unknown causes remain unchanged.

Still required before a runtime switch: compatible source/candidate/retained
self and startup overlays; bounded durable result retention; typed file
consumer; original state-FD handoff and same-PID health; durable release of
prior admission/ingress; failure/reboot-safe rollback; current full original-node
software, owned real KVM and ORIGINAL sustained-load acceptance. The full
production Goal remains incomplete. Do not restore/unfence an old cap0 self.
