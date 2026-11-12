# Disposable runtime CPU diagnostic (not native qualification)

The original-node accepted-work race command exceeded its **original 300-second
cap**. Its last output was inside the second run of
`TestRuntimeWorkStopWriteAheadCutsRecoverExactPlanWithoutEarlyStop`; its first
complete run took 27.54 seconds. This is **not evidence of the CPU/IO cause**.
Previous local Darwin microprofiles did not establish the original Linux cause,
whole-gate fit, or a performance improvement. All failed native and long-load
results stay failed; their unknown causes remain unknown.

## Fixed, separate experiment

The existing registered `CI` workflow has an optional boolean
`runtime_cpu_diagnostic` dispatch input, default **false**. The extra job only
runs for a manual dispatch with that input true, on **GitHub-hosted Ubuntu**.
It is skipped on push/PR. All existing normal CI jobs, gates, cases, repetitions
and limits remain; manual diagnostics do not turn them off either.

After the current source's original PR/push runs are terminal, a maintainer may
dispatch the existing workflow against that exact branch. Do not dispatch while
an original run is active: the workflow's existing concurrency behavior can
cancel an older run. Do not rerun merely to obtain a green result.

The script accepts **no parameters** and refuses root, self-hosted, non-Linux
and optimized-Python execution. It selects the **entire existing parent and all
16 subcases**, once with race detection, Go 1.27.3, GOMAXPROCS=2, package
parallelism=1, soft GOMEMLIMIT=512MiB, absolute self-only nice=10. A single
300-second outer deadline includes revision/compiler checks, compilation,
testing and CPU-profile analysis; the test's inner timeout is 280 seconds.
Neither is a replacement or increase of an original-node budget. Capture and
profile sizes are bounded; only the session launched by the script may be
killed on failure/timeout. No arbitrary test selector, benchmark, host, executable
or profile path can be supplied.

The job downloads the public module dependencies before the separate bounded
diagnostic. Its eight-minute outer job timeout includes checkout/tool setup and
that download. This setup/cache difference is another reason not to infer an
original-node wall-time fit.

This is an **additional selected diagnostic**, not splitting/filling the native
acceptance command, changing its case roster, or qualifying any missing case.
No Go source/test, oracle, resource guard or production behavior changes. The
selected tests use private TEST children and model managers, not ordinary
daemons, systemd, KVM, GPUs, actual quota or deployment. Do not run it on V100.

## Export and interpretation boundaries

Raw JSON test output, stderr, binary and CPU profile remain in a private
temporary directory on the disposable runner. They are not printed, uploaded
as artifacts, committed, or sent to an external profiling service. Cleanup
must finish before a success summary is emitted. Exceptions only emit a fixed
failure enum; no exception text, argv, paths, test output or symbol text leaks.
Ambient credentials and Go experiment/hook configuration are not forwarded.

The single public JSON summary contains the exact source revision/test-file
hash, fixed test/cut names and validated numbers. It requires exactly one run
and pass for the whole parent and **every** cut, one package start/pass, no
skip/fail/race warning, and no unexpected test. A complete pprof flat table is
reduced to a closed set of categories: race instrumentation, Go runtime, JSON,
regexp, project, and other/unattributed. Arbitrary symbols influence only a
category; their text is never exported. Missing/dropped/unaccounted profile
rows fail closed. Cumulative CPU percentages overlap and are **not added**.

CPU samples cover only the profiled **parent test process**, not helper-process
CPU, compilation or IO wait. Separately labeled `getrusage` numbers cover
waited build/test descendants; maximum waited-child RSS is **not summed or
concurrent peak RSS**, and block-operation counts are **not fsync latency**.
GOMEMLIMIT is a soft runtime setting, **not a hard kernel memory quota**.
Sampling, race instrumentation, cache, hardware and filesystem differences
prevent inferring original-node cause, original cap fit, speedup, regression,
SLO, KVM isolation, full reclaim, activation, release or rollback readiness.

Pure Python unit tests use synthetic events/tables and launch no Go or VM.
Passing them is not an executed Linux profile. The whole production Goal and
current original-node/KVM/long-load/rollback acceptance remain incomplete.

References: [GitHub workflow dispatch syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onworkflow_dispatch),
[dispatch REST API](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event),
and [Go test profiling flags](https://pkg.go.dev/cmd/go#hdr-Testing_flags).
