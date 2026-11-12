# Original-scope native program inspection

Status: **internal read-only prerequisite, not an installed runtime updater**.
After exact-byte administrator approval, `validateNativePrograms` checks all
nine borrowed original program descriptions using the **same complete static
native policy** as the existing installer. The existing `staticNative` body is
unchanged except for delegation to a shared `io.ReaderAt` implementation.
No old test, format, workflow, matrix, repetition, timeout or host cap changes.

This advances the actual program-format portion of installation/rollback
preflight. A signature alone previously accepted arbitrary signed DATA; this
additional stage requires native static ELF shape. It still does **not** prove
that the program works, was built from a claimed source, implements any reader
ABI, or is compatible with current state. There is no GoBuildInfo/version-label
shortcut, artifact execution, file selection, activation or ingress release.

## Bounded parsing without a metadata allocation race

The new parser contract supports ELF64 little-endian, canonical 64-byte header,
56-byte program headers and 64-byte section headers; at most 256 of each table;
no extended counts; and an uncompressed section-name table at most the existing
16-KiB `MaxPlan`. Sectionless binaries remain supported. These are **new explicit
image-reader limits**, not increases to any existing acceptance or IO budget.
The existing native class, machine, type, load bounds, file-backed executable
entry, alignment, interpreter and dynamic dependency/loader-tag checks all run.
The Firecracker/jailer static-PIE exception is not available to these Go roles.

A per-call ReaderAt envelope charges at most 32 KiB of metadata requests per
program, including repeated/failed requests; it checks context and exact file
range before reaching the original description. Only bounded header tables and
section names are loaded, never the whole image, arbitrary section payloads or
decompressed debug data. Table dimensions
and the string-table allocation bound are checked **before** `debug/elf` runs.
At most two 64-byte metadata pins are compared on every overlapping fresh read:
the file header and selected section-name-table header. They are not served as
cached bytes. A changed allocation-driving header is rejected before the parser
can use it, rather than relying only on a post-allocation stat check. The normal
complete program hash is neither cached nor omitted.

The envelope can reject a structurally valid ELF whose metadata exceeds it.
Such a refusal is not a claim of ABI incompatibility. Actual supported shipping
ELFs must still be qualified against this contract. An in-flight kernel read is
not context-interruptible; the byte bound is not a wall-clock deadline guarantee.

## Original ownership and final tail

The entry requires the authentic V2 result-close/Stop proof and original scope,
retained operation EX and **same BSD state FD**. Under that scope it freshly
repeats administrator signature, complete program bytes and initial record/FD
pins, then performs bounded ELF reads from those same descriptions. It does not
seek, duplicate, reopen or close them. After the final private test-cut point,
there is no injectable callback: authority/certificate file and linked-parent
pins, every original source inode/ctime, exact source/WAL, same state FD and
original-process absence are rechecked. There is no second redundant hash pass
or validation cache. A future full consumer must charge all these reads to the
unchanged original per-operation resource/IO/FD budgets.

Tests use structural ELF fixtures, never executed and not shipping artifacts.
They cover malformed/oversized tables, native-policy failures, allocation-header
races, exact ReaderAt budgets, cancellation/short reads and original FD offsets.
The actual current test ELF is compared against the unchanged static policy
(CGO-free positive or dynamic-race refusal), not treated as a shipping artifact.
One authentic owned actor/Stop history uses modeled backend/kernel positives:
valid inspection, revocation during the parser tail, explicit TEST administrator
renewal with a **new current-epoch certificate**, refusal of the old observation,
then retirement of the currently valid original scope. It never rolls authority
backward or restores an old key policy to make validation succeed.

Still required: trusted source/build evidence for source/candidate/retained-self;
actual reader contracts and complete current/per-tenant byte, record, FD and IO
budget compatibility; typed same-FD consumer/handoff, same-PID health, genesis,
durable prior-admission/ingress release and candidate-failure/reboot-safe rollback;
whole current CI, native KVM/long-load and actual shipping-ELF qualification.
The raw file engine's result-Stop refusal and startup fences remain unchanged.
