# Sequential installer readers

Five Linux installer loops consume `strings.SplitSeq` instead of materializing
the `strings.Split` result slice: anchored directory traversal, system-manager
observation, ingress empty-events, and the original kernel-lock owner/veto
parsers. Go 1.24 introduced this iterator; the module minimum remains Go 1.25.
The standard library specifies the same substrings without constructing the
slice: [strings.SplitSeq](https://pkg.go.dev/strings#SplitSeq).

Only each loop header changes. The original input, `TrimPrefix`/`TrimSuffix`,
order, empty fields, policy, maximum size, partial result, errors and diagnostic
payloads remain unchanged. An iterator is created afresh for each invocation;
none is retained or shared. There is no input normalization or data/FD cache.

Directory traversal still opens from the **original root descriptor**, checks
every parent and final descriptor, uses `O_NOFOLLOW` and `O_CLOEXEC`, and closes
every intermediate description. No fresh filesystem read, metadata check,
ownership proof, journal operation, hash, sync, source reproof, callback boundary
or resource/IO limit is removed. Lock parsers remain independent of actual
FD-local evidence; parsing an owner row or passing the negative veto alone is
not permission to stop, select files, activate or reclaim anything.

The new Linux-only tests retain literal pre-change function bodies and compare
actual callers, including returned directory identity, descriptor independence,
fresh path rebinding, invalid raw bytes, duplicate/empty records, complete error
and lock-ambiguity payloads, and fresh concurrent invocations. They are included
by the existing `TestRuntimeFile` CGO-free selector and whole-package race run;
no existing test, repetition, order, matrix or timeout is changed.

This is a bounded allocation opportunity, **not** a CPU profile, measured speedup,
identified timeout cause or evidence that CI now fits its 25/20-minute limits.
Source inspection is not execution qualification. The installed compatibility,
same-FD handoff, same-PID health, durable ingress release, reboot-safe rollback,
native KVM and long-load requirements remain incomplete.
