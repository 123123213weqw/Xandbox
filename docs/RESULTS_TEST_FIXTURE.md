# Results fixture initialization (TEST-only)

The result-close and result-bound Stop tests previously initialized an ordinary
main (including an empty core, broker, Unix server and `state/instances` model),
started ingress, killed/reaped the ordinary main, and finally started the actual
result-enabled main. Each case thus started three helpers for two subjects. This
is a source-observed redundant initialization, **not** a measured bottleneck or a
diagnosis of any previous Go/job/40-minute timeout. No speedup or budget-fit claim
is made by this change.

The common Stop fixture now accepts a TEST-only initial-main factory. Its default
path, manager/proof callbacks, main-before-ingress order, ownership and cleanup
are unchanged. The results fixture starts the real result-enabled TEST main from
the beginning. It does not substitute an in-process controller for that actor.
All existing result-close/Stop test bodies, fault cuts, cancellation cases, owned
coordinator SIGKILLs, pidfd/Unix proofs and original operation/state-lock checks
remain in place.

## Preserve the original state/reload boundary

A TEST-only bootstrap refuses **every** preexisting entry in the private owned
0700 state directory. It creates only an exclusive, no-follow, close-on-exec
0600 original `controller.lock`, acquires its actual BSD exclusive lock, and
uses the existing `nodecontrol.OpenStore` and `nodecontrol.New` to seed the same
valid open revision-one admission state. It starts no core, broker, server or
backend. The parent closes the seed lease before the actual results actor opens
the existing lock and reloads state through its unchanged daemon helper.

The fixture compares the actual pidfd-pinned Unix status with the **entire**
seeded control status before maintenance. It does not synthesize an epoch,
rewrite an old identity, initialize a used root, delete an unused namespace, or
relax production startup/recovery readers. The new bootstrap is not a public or
production API. A failure leaves any created prefix for inspection, not repair.

## Additional controls, not reduced acceptance

The existing `^TestRuntimeResultsWAL` gate also runs new tests for:

- The actual results main plus ingress, original seeded inode and FD-local BSD
  owner, exact status reload, retained result closure, and absence of the unused
  legacy backend **without deleting it**.
- Fifteen nonempty/unknown/used namespace, link, directory and mode refusal cases,
  comparing exact bytes/path/inode/mode/mtime/size before and after. These small
  filesystem-only negatives start no child or runtime.
- An explicit old ordinary main -> owned SIGKILL/reap -> result-main restart.
  Its original pidfd independently observes death, the new actor reloads the
  entire committed status and same state inode, the old backend namespace is
  preserved, and the existing result-bound physical Stop/retained-lease model
  must still succeed. Restart coverage is retained rather than repeated as the
  setup of every unrelated fault case.

A test's read-only observer of the original lock is **not** retained operator
state authority. Close that observer after capturing its identity, before Stop
acquires its own unique original state descriptor. The first version of the
explicit restart test retained both: all four Linux gates correctly refused
`state-fd-multiple`. Correcting that TEST FD lifecycle must not relax the
production uniqueness check or accept the earlier failed run. The existing
alias/unlocked/shared/foreign-owner negative controls remain unchanged.

The workflow, whole-package race x3, Go 20-minute timeout, 25-minute job limit,
all sixteen CGO-free gates, compatibility matrix and host resource/IO limits are
unchanged. No split, case drop, retry, race suppression or manual diagnostic run
is introduced. New-source ordinary CI must be evaluated on its own actual
outcomes; previous failures remain failures. Mock backend and manager/cgroup
positives remain **models**, not native Firecracker/KVM, full reclamation,
activation, rollback or production qualification.

## Closed-state model fixture uses the same original seed

The complete closed-state fixture had the same redundant ordinary-main
initialization. Its setup then removed that main's **empty TEST-only**
`state/instances` artifact before starting the actual
`closed-state-firecracker-model` helper. The default fixture now uses the existing
TEST initial-main seam and the **unchanged** strict empty-state seeder to start
that selected helper immediately. No unused ordinary main or backend directory
is created or deleted in this default path. The actual helper still opens its
own original lock and reloads the entire seeded control status before maintenance.

Only constructor selection is extracted. Original installed policy/rendered
bytes, optional metrics input, actual controller/Broker/Core, maintenance,
finish/close, fixed physical Stop and retained state FD, explicit diagnostic and
backend-format models, and full read-only closed-state inspection are shared
unchanged. Every preexisting test body and unknown-namespace/type/link/callback/
lease/context refusal case remains; the production reader still rejects
`instances` and preserves its bytes. The seeder continues to refuse all existing
entries; it is not a recovery, migration or adoption routine.

Two added `TestRuntimeCoreClosedFixture...` controls run both metrics-disabled
and metrics-enabled inputs in the existing Core gate and whole race suite:

- Correct initial populated TEST main plus ingress, exact seed reload, original
  inode/FD-local BSD owner, no unused backend, and complete strict state/backend
  **MODEL** join without mutation or reclaim/activation authority.
- Explicit former old-main -> owned SIGKILL/reap -> correct-main restart, old
  pidfd death, unchanged whole control status and original inode, the original
  empty-artifact test setup, full physical Stop/retained lease and strict complete
  read-only join. Observer lock descriptors are closed before operator Stop.

This retains restart coverage independently instead of repeating it as every
fixture's setup. It does **not** reduce old tests, arguments, repetitions,
assertions, process-proof strength, race coverage, or any timeout/resource/IO
limit. The workflow and Go command set are unchanged. It is not measured
performance evidence or a diagnosis of an old timeout. Native KVM, long-load,
complete result-aware installed consumer/handoff/rollback and production
qualification remain separate unfinished requirements.
