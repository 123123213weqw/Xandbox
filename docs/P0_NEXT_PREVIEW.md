# P0: safe load diagnosis and reversible delivery

Status: implementation in progress. The public version remains
`v0.1.0-preview.1`; this work is **not** a new release, sustained-load pass,
production installation, or working in-place rollback implementation.

## 1. Protect the shared host before testing

`scripts/host_test_guard.py` is wired into **both**
`kvm_nested_host.py` and `kvm_systemd_host.py` (including the initial-install
and managed-policy profiles). It supplements, never raises, their existing
memory/CPU/pids/swap, lifetime, no-NIC and per-generation ownership limits.

- One cooperating privileged fixture holds a private `/run/xandbox-test-guard/lock`.
  The retained inode is never unlinked; a concurrent cooperating fixture refuses.
  This is not a lock on unrelated jobs or a host-wide resource reservation.
- Before owned directories, allocation or VMs: require the full declared peak
  memory plus `max(8 GiB, 20% host RAM)` still available; independently require
  current-process cgroup-v2 ancestor headroom. The test memory ceiling must fit
  within one quarter of host RAM. Leave at least half the affinity CPUs outside
  the test's configured CPU quota.
- Check `/srv`, `/var/lib`, and the log filesystem independently. Preserve
  `max(8 GiB, 10% capacity)` free bytes, plus twice the declared disk size at
  admission. Preserve `max(65,536, 10% total)` free inodes, plus 150,000 at admission.
- Once per second, check remaining headroom and PSI: memory `full avg10 < 0.5%`,
  I/O `full avg10 < 10%`. Missing/malformed observations fail closed. The outer
  monitor's fixed whole-run wall-clock cap is 900 seconds for these profiles;
  existing per-operation and kernel deadlines are unchanged.
- A violation latches failure: no subsequent launch. Close only the current
  generation's lifetime pipe and write only its already-open `cgroup.kill` FD.
  This also fences a launcher that has not yet created QEMU. No PID-name search,
  shared-host restart, arbitrary kill, cache dropping or quota-range clearing.
- Close the lease and stop the execution domain **before** diagnostic writes.
  Full/unwritable log storage must not skip the Stop attempt. Unconfirmed aborts
  remain failures; ordinary owned-resource cleanup and receipts remain separate.

Limits: samples can race other users, PSI is lagging, filesystem reads can block,
and uninterruptible kernel I/O cannot be preempted by Python. Setup subprocesses
retain their existing bounds and are not all covered by the VM abort callback.
This monitor is **not** a guarantee against host failure, I/O bandwidth isolation,
or a replacement for kernel ceilings. It is not yet integrated into every other
harness. The PR #23 long-load source is a separate, unmerged tree: do not launch
it until this guard has been explicitly integrated and independently qualified
there. Do not inherit historical KVM passes for either modified harness.

## 2. Diagnose the actual load failure, without changing the exam

The [twelfth failed attempt](https://github.com/123123213weqw/Xandbox/blob/faf3c0ace259ae3b5a09d689e335da073278423d/docs/validation/kvm-open-arrival-attempt12-failed-2026-10-28.json)
reached `canary_old_gc`, but open and switch had already taken approximately
17.36 and 16.87 seconds. Only approximately 4.2 milliseconds remained after the
fresh command. That label is **not evidence of slow GC**. Composite admission
and Prepare spans also contain rechecks, not only FIFO waiting.

Next gates, in order:

1. Deterministic, bounded software reproducer for a rotating canary's **two**
   creates competing with raw requests. Distinguish capacity waiting, Prepare
   waiting/work, persistence, activation, Stop and durable reclaim. No artificial
   sleep-based throughput claim; retain original failed evidence.
2. Review an actual admission/cost fix and cancellation/ownership/fairness
   regressions. Shorter overload waiting may be investigated; increasing actor,
   Prepare, VM count or resources to make a pass is not the fix.
3. Requalify changed software/source/ELF and the guard, then one small owned
   Linux/KVM case with cleanup/neighbor-continuation checks. First failure stops
   escalation. Shortened cases are **diagnostic**, never the full load pass.
4. Only after these gates and a fresh host check: retain the original 40-minute
   offered clock, rates, workers, 35-second actor, N=4, Prepare=1, 100 tail cases,
   synchronized inventory and original-disk cold recovery. A host-guard abort is
   an incomplete/failed run, never excluded from the result to improve latency.

All twelve historical sustained-load failures remain failed. The previously
rejected copy-cadence experiment is not being revived by this work.

## 3. Install/rollback: verify distributions, never rewind authority

New read-only tool: `scripts/verify_release_bundle.py` in the repository.
It checks a separately supplied SHA-256, version, OS/architecture and source
commit; bounded decompression; canonical regular-file members; binary inventory,
size/hash/architecture; `BUILD_INFO.json`; required docs/licenses. It rejects
symlinks, hardlinks, devices, traversal, duplicates, unknown executables,
unexpected metadata and nonzero trailing payload. It never extracts or executes.

From a trusted checkout, use independently confirmed release pins:

```text
python3 scripts/verify_release_bundle.py \
  --archive /absolute/path/to/Xandbox-VERSION-TARGET.tar.gz \
  --sha256 EXPECTED_ARCHIVE_SHA256 --version VERSION \
  --target TARGET --source-commit EXPECTED_SOURCE_COMMIT
```

Use the same verification for **both the candidate and retained previous
distribution**. A checksum downloaded from the same compromised origin is not
an independent trust anchor; no release signature is claimed. The tool is not
included in older binary archives. Verification success explicitly reports
`installed: false` and `production_ready: false`.

The existing `xandbox-install` is an exact fresh-install/reconcile transaction,
not a software upgrader. Do not overwrite `/usr/libexec/xandbox-*`, `/srv/xi`,
units or installer metadata, or switch service binaries using a shell symlink.
Do not restore an old ledger/policy backup: that could forget a later generation,
revocation or idempotency tombstone. `reconcile` repairs activation of the
**same committed installation**, not selection of an older version.

The new [read-only update inventory](UPDATE_INSPECTION.md) adds
`inspect-update`: it binds the exact installed commit/current managed policy,
candidate publication and retained **installed** release; verifies all their
immutable bytes under the original locks; and refuses drift/pending work.
It does not execute the candidate, inspect mutable authority as a consistent
snapshot, prove compatibility/drain/reclaim or authorize activation. This is
one prerequisite for the executor below, not an implementation of rollback.

Before any future runtime upgrade/rollback executor is enabled it must have:

- independently verified current/candidate/previous artifacts and a complete,
  private compatibility/binding inventory;
- persisted drain; confirmation of all accepted work stopped and fully reclaimed;
  zero unknown execution domains, owners or quotas; explicit downtime semantics;
- durable transition intent and monotonic CAS revision, exclusive operation lock,
  digest-bound exact retry, same-PID start verification and health confirmation;
- schema/binding/backward-reader compatibility checks. Incompatible rollback is
  refused, not forced. Binary rollback never rolls back authority/state history;
- owned-L1 install, failed activation, interrupted switch, reboot, retry and
  rollback drills, with exact independent cleanup and preserved failure evidence.

Until those gates pass, keep the old installation intact; evaluate new versions
only in a separately owned test environment. No automatic deployment, active
node replacement, or claims that in-place rollback now works.

## 4. CI runner maintenance (2026-11-09)

The initial P0 head `0fbdca9` used the released main's `macos-14` label.
Its [push run](https://github.com/123123213weqw/Xandbox/actions/runs/42610808470)
and [PR run](https://github.com/123123213weqw/Xandbox/actions/runs/42610875991)
each cancelled the macOS job before any test step, without assigning a runner.
The actual annotation reported an unsupported `macos-14-arm64-us-default`
configuration. Those original outcomes are retained, not passing tests.

GitHub's [official retirement notice](https://github.blog/changelog/2026-10-01-github-actions-macos-14-runner-image-retirement/)
announced removal on November 2. Change only the fixed macOS label to the
supported `macos-15`; preserve all six jobs, Go versions, test repetitions,
timeouts and security gates. No floating `latest`, paid larger runner or
self-hosted/shared-node runner is introduced. New-head CI needs its own results;
an old cancelled run is never reclassified as green. Updating the branch may
cancel remaining obsolete-head jobs through the existing concurrency policy.

This is CI infrastructure maintenance, not macOS 14 compatibility certification
or a Linux/KVM/runtime change. The six source files exercised by the 37 original
node software controls remain byte-identical in that CI-only commit; compare those exact hashes rather
than rerunning unchanged software or claiming new hardware qualification.

## 5. Monitor lifecycle refusal

A follow-up hardens the test guard's own lifecycle: a never-started monitor,
or one already stopped/closed, cannot authorize a launch even when no pressure
failure has been recorded. Two explicit negative controls check that the spawn
callback is never called. The ordinary service is unchanged. This changes the
guard and its tests, so the earlier 37-control native result is historical;
current software needs its own 39-control evidence, not an inherited pass.
