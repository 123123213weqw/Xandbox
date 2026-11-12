# Start the intended terminal test actor first

This changes **test initialization only**, not a production path or acceptance
policy. The terminal fixture previously started an unused default main, closed
its client, ignored the return values of its setup kill/wait, then started the
actual populated model before any maintenance/work/close/Stop assertions.

For populated, explicit terminal metadata model, and cleanup-failure modes, the
fixture now uses the existing strict **empty private state** seed. The ordinary
store/controller creates exactly its original revision-one control state and
original BSD lock inode. The intended actual test actor opens that same inode
and state itself. The fixture checks the entire original control status, pinned
PID/incarnation, one initialization, and fresh unique FD-local BSD ownership.
The intended actor still creates the full ledger/session/backend namespace and
runs its original actual controller/core/broker lifecycle, not an empty/easier
substitute. The explicit backend label remains a **model**, not Firecracker/KVM.

The default and all other modes use the original initialization body verbatim.
In particular unsupported mode retains the old bootstrap's empty runtime
namespaces; it is not silently converted into a fresh namespace. Its existing
negative test is unchanged. `runtimeWorkChild`'s explicitly asserted bootstrap
death is also unchanged, as are all original Stop/close/coordinator crash cuts.

The original terminal helper's complete scope, maintenance, accepted-work,
closure, physical Stop and retained-state tail is unchanged. All its old test
bodies remain exact. Only two close tests use the new intended-actor setup;
their entire subsequent protocol/assertions and deferred client close remain.
No production file, wire, kernel/process proof, source/IO check, fsync, resource
quota, timeout, matrix, test case, repetition or workflow command changes.

Three new Linux tops add eight named cases: all three intended modes prove the
original seed and full protocol; all three retain explicit bootstrap
SIGKILL/reap/reload with an independent pidfd and same lock inode; default and
unsupported prove their original namespaces and protocol. Observation FDs are
closed before operator Stop acquires its unique retained state lease. Successful
terminal joins still grant neither reclaim nor activation. Mock backend and
failed/unsupported close must still refuse the corresponding authority.

This removes redundant actor initialization, **not a measured speedup, CPU/IO
profile, timeout root cause, budget-fit or SLO claim**. New-source CI must prove
its actual scope. All old tests and counts remain, CI stays 25 minutes, Go race
stays 20 minutes, and all original host resource/IO/acceptance budgets remain.
No V100 load or deployment is performed. Operational compatibility/budget,
same-FD handoff/health, ingress/admission release, rollback and original
Linux/KVM/long-load acceptance remain incomplete. The preview is not requalified.
