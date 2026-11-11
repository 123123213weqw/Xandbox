# Go toolchain security and rebuild boundary

## Finding and supported candidate baseline

The original push CI for `5dc05e0` reported a reachable standard-library
`net/http` vulnerability under Go 1.27.3: [GO-2026-6859 / CVE-2026-97054](https://vuln.go.dev/ID/GO-2026-6859.json).
The official advisory describes an HTTP/1 server panic when a request body read
and response header write occur concurrently after `MaxBytesReader` exceeds its
limit. It lists fixes in Go 1.27.4 and 1.26.11. Go 1.27.4 is present in the
[official stable release inventory](https://go.dev/dl/?mode=json).
The successful PR scan for the same source does not override that finding;
the difference between the two scan outcomes has not been diagnosed.

The current candidate build/security baseline is **Go 1.27.4**. The ordinary
CGO-free CI gates, Linux cross-build job, and vulnerability scan use that SDK.
The existing Go 1.25.x / 1.27.x matrix continues to check source compatibility;
its labels are not a claim that every SDK in those families is safe to ship.
All previous test selectors, repetitions, order, race checks and time limits
remain unchanged. No vulnerability exclusions or downgraded vulnerability DB
are introduced. The two original matrix job cancellations at their 25-minute
job limit remain failed/incomplete evidence; updating the SDK is **not** a
root-cause diagnosis or a claim that their timing issue is fixed.

## Explicit build and artifact checks

For a production candidate, start in a controlled build environment with a
trusted Go launcher, working TLS and module checksum verification:

```sh
GOTOOLCHAIN=go1.27.4 go version
GOTOOLCHAIN=go1.27.4 go mod verify
GOTOOLCHAIN=go1.27.4 make build
GOTOOLCHAIN=go1.27.4 go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
go version -m bin/sandboxd
```

Verify the actual compiler/build information for **every** distributable ELF
and record the source SHA, full artifact hashes and build environment. The
commands above do not by themselves build or qualify guest images, bundles,
kernels, Firecracker or other components. A passing format/checksum validator
is not a security attestation. Rebuild the required current artifacts with the
patched SDK, revalidate their ABI/metadata, and perform the required original
software/KVM/install/rollback/long-load acceptance before deployment. Do not
substitute a scan of new sources for the provenance of an old executable.

`Makefile` uses `GOTOOLCHAIN ?= go1.27.4` and exports it. Existing explicit
environment or command-line settings are intentionally respected, including
`GOTOOLCHAIN=local` in compatibility CI. This is a default, **not** a
non-bypassable release gate: use the explicit SDK assignment above for shipping
candidates. A raw `go build` does not consult the Makefile. The `go 1.25.0`
language minimum in `go.mod` is not a patched compiler requirement. The project
does not add a `toolchain` directive that would silently change historical
fixture compilers. See the [official selection rules](https://go.dev/doc/toolchain).

## Preserve historical evidence, not vulnerable production binaries

The published `v0.1.0-preview.1` is **not** rebuilt or requalified by this patch;
there is still no supported production release. No tag, release, service or
host SDK is changed. Original failed CI logs and partial coverage remain
preserved; later green CI cannot reclassify them.

Historical fixed-ELF/guest-image and systemd test-producer recipes retain their
original Go 1.27.3 declarations. Their exact ELF bytes, offsets, manifest hashes
and original compiler checks are part of that old evidence, **not** a current
production build path or permission to ship an unpatched executable. A new
Go 1.27.4 hardware fixture needs a genuinely rebuilt artifact and fresh ABI /
metadata / original-node acceptance, not a string replacement. Likewise,
release-bundle unit fixtures with an old `go_toolchain` string test the format,
not whether a compiler is safe.

The consumed optional CPU-diagnostic experiment and its complete workflow job
remain byte-identical with their fixed Go 1.27.3 compiler. Do not redispatch it
or treat that historical profile as a production qualification. Updating it
would require a separately designed experiment, not an unchanged retry.

There is no CI rerun, relaxed test budget, host-exec fallback, host deployment
or original-node load in this patch. Result-aware physical service Stop,
post-Stop state ownership, compatible bounded activation, state-preserving
rollback and full current original-node acceptance remain incomplete.
