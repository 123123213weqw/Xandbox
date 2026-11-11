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

The workflow, whole-package race x3, Go 20-minute timeout, 25-minute job limit,
all sixteen CGO-free gates, compatibility matrix and host resource/IO limits are
unchanged. No split, case drop, retry, race suppression or manual diagnostic run
is introduced. New-source ordinary CI must be evaluated on its own actual
outcomes; previous failures remain failures. Mock backend and manager/cgroup
positives remain **models**, not native Firecracker/KVM, full reclamation,
activation, rollback or production qualification.
