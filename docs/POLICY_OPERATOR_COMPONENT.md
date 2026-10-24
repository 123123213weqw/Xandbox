# Policy operator transport — component only

**Not installed-node rotation.** `internal/policycontrol` is an independent,
currently unused building block. No existing command imports it, `RunRoot` does
not start it, and the v1 installer still accepts only its original immutable
25-target installation. Do not create the reserved runtime socket, alter the
install commit, replace pinned TLS files, or replay SIGHUP to use this component.
The [ordinary initial-install KVM evidence](INITIAL_INSTALL_KVM.md) remains bound
to its original source and artifacts; it is not a rotation or upgrade receipt.

## Why a separate operator channel

The existing privileged gateway commits its durable policy **before** transferring
it to its unprivileged TLS child. Its SIGHUP path requires exactly the next epoch;
a duplicate or invalid signal can close ingress. A signal, successful write, or
lost response cannot establish that both persistence and child activation finished.

This component defines a separate root-operator `SOCK_SEQPACKET` channel. It does
not widen the inherited, fixed 24-byte child capability protocol, add tenant HTTP
routes, select upstream sockets, execute commands, or modify a policy file. A
future supervisor must retain its existing exclusive policy-state lock throughout
the operator server lifetime. Only that supervisor may classify commands, validate
complete snapshots, perform commits/transfers, and report real child ACKs.

## Closed protocol and progress

- `status` has no mutation arguments. `activate` carries an expected epoch, its
  exact successor, and one lowercase SHA256 snapshot digest. No paths, credentials,
  certificates, process commands, environment, or arbitrary error text are accepted.
- The digest identifies a **canonical complete Snapshot**, not the raw private
  payload file. The eventual installer must separately bind and verify raw file
  bytes. This module deliberately does not parse, validate or hash TLS policies.
- Status reports the last successfully committed epoch/digest and the last
  child-acknowledged epoch/digest. `active` is an ACK observation, **not** current
  health, installation-commit proof, request cancellation, or an availability SLO.
- Valid progress is `waiting -> active -> committing -> waiting(next) -> active`.
  Epochs cannot skip, decrease or wrap. Equal observations are idempotent. Any
  non-fenced phase may become `fenced` without changing its last confirmed facts;
  an in-process fence cannot reopen itself.
- `Classify` admits a new CAS only from `active` at the exact expected epoch.
  A retry for the same durable target/digest is observational, including while
  waiting for its ACK: **do not repeat the commit or child transfer**. A different
  digest at the same epoch, stale/skipped request or a fence is not success.
  `Classify` is pure validation, not a filesystem CAS or transaction lock: the
  future single-writer supervisor loop must serialize and recheck every mutation.
- The client checks that an activation response names its exact target/digest
  and is not fenced. Callers must still inspect its phase and await the exact ACK;
  a valid `waiting` response is not completed activation.

A submitted activation may outlive its client's connection or response deadline.
Timeout/EOF is **unconfirmed**, not rollback or permission to replay SIGHUP. The
transport cannot manufacture an ACK: it queues a request for the supervisor and
accepts one validated response. The only error codes are `INVALID`, `CONFLICT`,
`BUSY`, and `UNAVAILABLE`; there is no arbitrary diagnostic payload.

## Local boundary and finite resources

The future root entry points use only the reserved
`/run/xandbox-ingress-control/operator.sock`, outside the policy store's closed
on-disk inventory. The directory must already be caller-owned 0700, the socket
single-link 0600 with the expected owner, and its ancestry private/trusted.
The public client requires real/effective UID 0 and a caller-observed manager main
PID; `SO_PEERCRED`, directory and socket identities are checked on connection.
This PID check is not, by itself, an executable/incarnation or manager proof.
Those checks remain the future installer's responsibility.

There are four admitted connection handlers and four queued activations. An
admitted status request reads an atomic observation without entering that queue;
this does **not** promise admission during connection saturation. Packets are
limited to 1024 bytes, socket operations to two seconds, and supervisor replies
to 1.5 seconds. Truncation, duplicate/unknown JSON fields and ancillary data are
rejected. Received SCM_RIGHTS use atomic CLOEXEC and are closed, including the
kernel-truncated-rights case. No descriptor is delegated by this protocol.

Startup rejects unknown files, socket aliases and live endpoints. A private dead
socket is removed only after a refused connection and matching inode observation;
this relies on the future caller's exclusive policy lock, not a second lock file.
Shutdown closes admitted connections, joins handlers, and removes only its own
still-matching socket inode. It must not unlink a replacement. This is not a
malicious-root filesystem isolation boundary.

## What was tested; what was not

The [machine-readable component record](validation/policy-operator-component-v1.json)
binds the exact source, private evidence hashes and rebuilt artifact comparison.
Tests use real Linux private named sequence-packet sockets, kernel peer credentials,
SCM_RIGHTS/truncation, response loss, saturation, deadlines and inode-safe shutdown.
Their supervisor, durable progress and ACKs are **synthetic**; no policy-store
commit, `RunRoot` integration, root fixed-path positive test, real frontend ACK,
installed root CLI, KVM continuity or cold rotation is asserted.

The 19 artifacts in the prior installer qualification are rebuilt and compared,
rather than treating new component tests as new KVM evidence. Historical hardware proofs remain unchanged.

## Next required integration gates

1. Define a new opt-in installed composition with one atomic complete private
   policy payload; keep backend/auth/node/binary/self bindings immutable. Do not
   retrofit a new executable into an old self-pinned install by fiat.
2. Implement bounded old/new install intents, file/digest/epoch CAS, crash recovery,
   commit/startup gates and source-independent exact retry. Hold an outstanding
   intent until the exact real child ACK; do not release it merely on a signal.
3. Wire the root supervisor's real commit/transfer/ACK events to this protocol;
   reject incompatible reload paths. Preserve controller state and persisted drain.
4. Qualify ordinary root CLI rotation with a live TLS connection and real KVM
   writer, old-token rejection on that same transport, no guest/controller restart,
   lost response, conflicts, filesystem/process crashes and original-disk cold
   recovery. Independently audit cleanup before claiming this feature supported.

Backend-authority migration, installer self-upgrade/rollback, consistent backup,
audit retention and saturation/SLO acceptance remain separate unfinished work.
