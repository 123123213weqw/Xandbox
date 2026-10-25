# Initial installation transaction — limited owned-L1 acceptance

`xandbox-install` connects a committed [artifact publication](RELEASE_STORE.md)
to fixed files and a fixed service-manager composition. It is **new, experimental
initial-install code**, not a production deployment recommendation. Its root CLI, capability-free startup gate and real PID1/cold-boot path now have
[a new finite owned-L1 qualification](INITIAL_INSTALL_KVM.md). This does not
certify upgrades, rotation, every persistence-failure window or full production
readiness. Older launcher/readiness/publisher reports do not certify it.

## Deliberately narrow contract

- Linux root, systemd PID1, CGO-free native installer; no shell, tenant argv,
  environment-selected manager, arbitrary unit name, remote systemctl, force,
  reset, uninstall, upgrade or task-execution fallback.
- Fresh node only: schema3 **cold** backend with mandatory node/quota/IO policy.
  Snapshot catalog/bootstrap, backend binding migration and existing deployments
  are refused, not silently adopted. Device/envelope settings are operator input,
  not automatically discovered or weakened.
- One durable installation revision, with expected revision **0** and an exact
  32-lowercase-hex request ID. A different request or plan cannot replace it.
- A pinned release ID and publication revision select the original publisher's
  committed reference. The consumer holds the **existing publisher lock inode**
  while checking/copying the selected bundle. Both retained bundles' complete
  inventory, ownership, modes, sizes and SHA256 are checked. Executable roles
  require native static ELF with a file-backed executable entry and no interpreter.
  Go roles retain ET_EXEC; only Firecracker/jailer may use ET_DYN static PIE,
  with DF_1_PIE and bounded program-header dynamic tags rejecting imports, loader
  search paths and audit/filter dependencies. Workspace must be exactly 128 MiB. This is not malware analysis
  or a malicious-root ELF trust boundary.
- Five private, hash-pinned operator inputs: backend, auth, gateway policy,
  certificate and key; plus the installer executable pinned to its actual
  `/proc/self/exe`. Before materialization, the ordinary service admission,
  tenant/backend-credential and TLS policy validators must agree. Source and
  target path choices are private operator data, never CLI output.

## Fixed layout and commit order

| Purpose | Fixed path |
| --- | --- |
| Private transaction/configuration | `/etc/xandbox-install/` |
| Immutable release assets | `/srv/xi/a/` |
| Ordinary ledger/runtime/policy | `/srv/xi/s/`, `/srv/xi/r/`, `/srv/xi/p/` |
| Gateway child root and executable | `/srv/xi/g/root/gateway` |
| Installer / launch / ready / ingress helpers | `/usr/libexec/xandbox-*` |
| Units | `/etc/systemd/system/xandbox{,-ingress}.service` |
| Runtime input snapshot | `/run/xandbox-inputs/` |

The private plan uses schema `installtxn.Plan`; no permissive ad hoc JSON/unit
template exists. It contains exact release/self/input SHA256 pins, `/dev/vdX`,
`/dev/sdX` or `/dev/nvmeNnN`, frontend limits and main/ingress/reserve/capacity
envelopes. It must be a root-owned private regular file. Secrets, runtime plans
and real request IDs must not be committed. There is intentionally no fabricated
ready-to-run plan with made-up block UUIDs or credentials.

1. Lock private installer state. Refuse foreign files, preexisting planned
   service assets/state and already loaded units/drop-ins/enablement. A bootstrap
   at the final installer path is accepted only if explicitly declared and
   already exactly hash/mode matched.
2. Persist a typed intent binding the exact plan, release descriptor and all
   **25 target** hashes/sizes/modes. File sync, rename and directory sync are
   distinct boundaries.
3. Copy only the selected/pinned sources through anchored NOFOLLOW descriptors.
   Resume a partial file only if its existing bytes are an exact prefix;
   unknown/corrupt/symlink/hardlinked content is not overwritten. Sync and seal
   executable/data modes. All non-unit files precede the guarded main unit;
   ingress is last. The sealed gateway child root is 0555.
4. Recheck hashes, fixed generated manifests/units and closed immutable
   inventories. Persist the commit, then remove only its matching intent.
5. **Release the installer lock before manager activation**, so ExecStartPre
   can acquire a shared proof without deadlocking the parent.
6. Fixed manager operations: `daemon-reload`, observe exact fragments/no drop-ins,
   `enable` both units, `start xandbox.service`, then observe both active/enabled
   main PIDs and exact enablement links. Never `restart`, `stop`, `reset-failed`
   or node `resume`. Recheck the durable transaction before a successful receipt.

The existing same-PID launcher, post-start readiness gate, budget generators and
ingress BindsTo/After/enablement composition remain unchanged. The installer adds
exactly one main-unit pre-start command:

```ini
ExecStartPre=/usr/libexec/xandbox-install verify
```

That process drops all threads' ambient/bounding/effective/permitted capabilities,
sets NNP, requires sole-process placement in this unit's `.control`, rejects
inherited authority FDs, and takes a shared **existing** installer lock. It
verifies the committed files and regenerated composition, without repairing,
creating a lock, activating a service or executing a task. **This placement and capability contract has a new limited real PID1
observation in the initial-install profile; it is not a complete fault matrix.**

## Receipts and recovery

Only these command shapes exist (placeholders are not literal arguments):

```text
xandbox-install apply -plan PRIVATE_PATH -expected-revision 0 -request-id REQUEST_ID
xandbox-install reconcile -request-id REQUEST_ID
xandbox-install status
xandbox-install verify
```

`verify` is silent. Other successful output is a closed object containing only
`version`, `revision`, `files_committed`, `manager_reconciled`, and
`production_ready` (**always false**). No private path, source/config/secret,
process identity or raw manager output is relayed. Errors report an unconfirmed
installation; they do not promise that nothing happened.

- Before commit: preserve the exact request, plan and pinned sources. Retry the
  same apply; if its release is no longer one of the publisher's retained two,
  stop for explicit operator recovery rather than selecting a newer release.
- After commit: `reconcile` needs installed metadata/bytes and the same installer
  executable, **not the original asset/config sources**. It can safely repeat
  manager start, but never clears persistent drain or repairs modified files.
- A manager transport error, timeout or process death may occur after files or
  enablement committed. Inspect/status and exact reconcile are separate from
  treating file commit as service health. `status` is observational and never
  manufactures a missing lock or calls activation operations.
- Existing independently proven drain/readiness semantics are reused in code,
  **now covered by the named finite installer profile, not full production acceptance**. No fast-stop, full
  reclaim, media-erasure or SLO claim follows from an installation receipt.

## Evidence boundary and remaining work

Tests distinguish pure policy/CLI controls, real generated ephemeral TLS and
ordinary policy validation, test-owned Linux filesystem transactions, simulated
manager responses and actual abrupt **test process** death. The model's FD-root
and persistence hooks are unexported; there is no production alternate-root or
test-hook flag. Model service assets are not executed and are not usable VMMs.
Returning a persistence-hook error is not process death, fsync failure injection,
physical power loss or hardware acceptance.

The [new named profile](INITIAL_INSTALL_KVM.md) runs the ordinary installer in
an owned systemd L1 with real artifacts/config/PKI, actual precommit child death,
cap0 pending-commit start refusal, exact reconciliation, unchanged drain,
TLS→KVM, source-path absence and original-disk cold recovery. Its scoped resources
were independently absent. It does not cover filesystem D/EIO during installation,
every manager crash boundary, malicious root, independent human reproduction or
production saturation/latency guarantees.

This revision is immutable **initial configuration only**. Manually rotating its
installed TLS/gateway/auth files would invalidate its commit proof; the older
manual hot-rotation fixtures do not establish installer rotation compatibility.
A separate consistent reconfiguration transaction is required. Upgrade/rollback,
cross-ledger/session/owner/catalog/policy backup, trusted key distribution,
catalog installation, reliable audit/retention, saturation and production SLO
acceptance remain unfinished. No M1–M4 completion box is changed.

## Earlier native qualification (frozen pre-PIE correction)

[Machine-readable evidence](validation/initial-install-native-v1.json) binds
source `4167804f75f6daf0169d22f5cb9b9f1cdf75c110` to actual Go 1.27.3 Linux full
`-race -count=3`/vet, 85 selected returned-error boundaries, eight abrupt test
process exits and fresh-handle recovery (three repetitions), four independent
same/competing-request processes, generated ephemeral TLS/ordinary policy
validation and retained-release/ELF/permanent-lock controls. Tagged fixture/helper
race and CGO-free quota-filter controls passed; Linux Python 219 tests had zero
skips. macOS full race/vet passed; its Python suite has five platform skips.

Both new amd64 CLI/test artifacts are native/cross byte-equal; arm64 cross builds
passed. All 15 previous artifacts were actually rebuilt and byte-equal, so their
prior source-bound reports stay unchanged, **not re-signed as installer tests**.
The first development run failed test-owned TempDir teardown at a sealed 0555
child root; its original failure log is retained. The test-only cleanup was fixed,
and 270 exact logged leftover test directories were removed with owner/inventory
checks. This cleanup is not runtime GC evidence. The final frozen suite includes
the later permanent-lock-loss refusal and observational status controls.

No privileged installer or actual manager mutation ran on the shared build host.
The later [native correction and owned-L1 profile](INITIAL_INSTALL_KVM.md) have
distinct source bindings; the earlier JSON is retained unchanged, not re-signed.
