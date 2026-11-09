# P0 fixed prepare-probe binding — data-only qualification

Status: **new test fixture binding, not a live calibration, sustained-load pass
or production release**. The historical [prepare calibration](NODE_PREPARE_TRACE.md)
reports retain their original source/ELF identities. Do not reinterpret them as
results for the current candidate or use this page to authorize a VM launch.

## Why this exact image

The isolated admission candidate's ordinary daemon was built natively on the
original selected Linux/amd64 node with Go 1.27.3, CGO=0, GOAMD64=v1,
`-trimpath -buildvcs=false`. The retrieved **12,622,263-byte file** was actually
compared byte for byte with the independent cross-build:

```text
64883c528ba1d574aaa082c24b136e4938717c13c6abc122afcbddbb3b6c2abe
```

Native input was runtime source `1a78d4b2942f97ae945bafd6681c26470b438a8e`.
The later private-umask test correction changed no Go/module source, and its
fresh cross-built daemon also matched that native file. This binding changes
only test-only fixture, verifier and documentation code; ordinary runtime Go,
module dependencies and original asset/resource/deadline policies are not
changed. A fresh fixture binary still needs its **own** build/source qualification.

Bounded static review compared all **132 instructions** in the three complete
probe-bearing symbols (293/173/41 bytes). Only direct CALL rel32 displacement
bytes were normalized, after resolving each decoded target to the same exact
symbol. Other instruction bytes/register and stack dataflow/internal branches
matched; no RIP-data masking was used. All nine points were complete instruction
boundaries. Algorithm negatives for changed registers/operands/CALL targets and
branch targets refused. That is **not** whole-program or live Go ABI proof.
The machine-readable [binding](validation/p0-prepare-probe-binding-v1.json)
records the nine fixed points and limits of that evidence.

## Verification before any tracing effect

`prepareTraceELFSHA` accepts exactly the image above, never a caller-selected
hash, old-program fallback, symbol/offset selector or environment-selected ABI.
`startPrepareTrace` keeps the existing owned-L1, fixed kernel, exact PID
incarnation/control-cgroup, empty tracefs registry and loss/hit-accounting gates.

The fixed asset is opened NOFOLLOW/NONBLOCK. A bounded regular descriptor of
exact size is read once into an immutable image. Both its SHA and ELF parsing
use that same image, with unchanged descriptor metadata checked around the read.
The verified inode/size/mode/owner/link/mtime/ctime identity is carried into the
live target checks; a later path rebind is not silently adopted.

ELF controls require static amd64 ET_EXEC, one unique defined function symbol,
the **whole selected instruction** inside the function/executable section, a
unique non-writable file-backed executable segment covering the function,
consistent section/segment offsets, bounded arithmetic and exact ReadAt byte
counts. Unknown, duplicate, overflowing, BSS-only, short, ambiguous or modified
inputs refuse before registration. Whole-image SHA remains mandatory even if a
change outside all nine selected instructions leaves structural checks passing.
This is defense against input mistakes/drift, not a malicious-root boundary.

## Purpose-specific pins: do not retarget fault injectors

The old probe constant was also used by FSYNC/shutdown/diagnostic notification
helpers. Updating it globally would silently authorize unqualified experiments.
Those helpers now use the **separate frozen** `observerOrdinaryELFSHA`:

```text
5bfb2394f95a1b1c2f887b6e301357b92140586bde07448e3e09f2aa0ee3c11c
```

Their accepted target is unchanged. They deliberately refuse the new candidate
until their own source/protocol/activation/cleanup prerequisites are qualified.
No generic multi-hash allowlist was introduced. The Python trace validator binds
the new trace ELF only and refuses previous ELF receipts. Historical reproduction
requires the matching historical source and assets, not the current verifier.

## Data-only controls and CI

The existing opt-in `XANDBOX_PREPARE_PROBE_ELF` test input remains **test-only**:
it points to a canonical absolute file named `sandboxd`. It cannot register
tracing, mount tracefs or execute that file. Unset input explicitly skips that
opt-in control; it is not a pass. CI now builds the pinned ordinary image with
the canonical Go 1.27.3 flags, supplies it to early CGO-free parser controls x3,
and also supplies it to the unchanged complete fixture race x3 gate. All other
jobs, repetitions, resources and timeouts remain.

Controls include the real complete ELF and descriptor identity; unrelated-byte
and selected-instruction mutations; truncation/append; duplicate/undefined/object
symbols and instruction straddling; interpreter/dynamic/writable/ambiguous/BSS
segments; offset overflow; non-executable sections; short ReaderAt responses;
and metadata/inode/mode/owner/link/time drift. They are software/file controls,
**not** live ABI, guest execution, VM-abort, Stop/reclaim or performance evidence.
No raw host identities or trace registers are published.

## Preserved CI failure and diagnostic follow-up

The binding commit `9d9db9be0deba1d8abb3e4f2c4d4ec6cd1e8e488` passed
its [original push run](https://github.com/123123213weqw/Xandbox/actions/runs/42658149841),
but its [original pull-request run](https://github.com/123123213weqw/Xandbox/actions/runs/42658162188)
failed the Go 1.25.14 process smoke gate. `metadata_smoke.py` rejected the final
graceful stop of the disposable imported 2048-record mock fixture. That original
assertion did not record the exit code or diagnostic view; its cause is **not
established**. The run remains failed, not an infrastructure exception or pass.

The follow-up adds failure-only integer exit status and the existing bounded,
closed diagnostic projection, with the exact disposable fixture directory.
Retained records can include earlier incarnations and are context, not proof
of this exit's cause. No raw logs, paths, identities, credentials or request
values are exported. Normal stop still requires zero, crash still requires
nonzero, and the original 15-second wait, 2048 records, partial-upgrade and
resume/metadata-cap gates remain unchanged. No retry or accepted-exit allowlist
was added, and no daemon behavior or diagnostic deadline was changed. Python
controls cover zero/nonzero/signal/timeout refusal and fixture-directory wiring.
A later green software run cannot establish the cause of this earlier failure,
nor can it qualify live shutdown, sustained load or state-preserving rollback.

## Required next gates

Independently qualify the changed fixture/helper bytes and exact source/asset
manifest, then a guarded small owned-L1 live calibration and independent
ownership/neighbor/Stop/reclaim observations. The old long-load harness has not
been ported to this isolated source. Its guard must cover the **entire original**
offered clock/tail/cold envelope; the nested fixture's default 900-second cap
must not be mistaken for 40-minute qualification or used to shorten the test.
Keep the original 35-second actor, 40-minute offered work, rates/workers, N=4,
Prepare=1, asset bytes, IO ceilings, 100 tails and synchronized/cold checks.
First failure stops escalation. Installation/state-preserving rollback and the
full production Goal remain incomplete; no merge, deployment or new release is
implied by a fixed probe table or green software CI.
