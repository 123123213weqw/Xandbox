# Third-party notices

Xandbox source is MIT licensed. The experimental guest transport additionally uses the pinned Go modules below; their upstream license notices are retained in `LICENSES/`. Versions and integrity hashes are recorded in `go.mod` and `go.sum`.

| Module | License | Upstream |
|---|---|---|
| github.com/mdlayher/vsock | MIT | https://github.com/mdlayher/vsock |
| github.com/mdlayher/socket | MIT | https://github.com/mdlayher/socket |
| golang.org/x/sys | BSD-3-Clause | https://go.googlesource.com/sys |
| golang.org/x/net | BSD-3-Clause | https://go.googlesource.com/net |
| golang.org/x/sync | BSD-3-Clause | https://go.googlesource.com/sync |

The Go standard library is covered by the Go distribution's license. Binary distributions must retain the applicable upstream notices, not only this project's MIT notice.

Firecracker/jailer, the Linux test kernel, Alpine and BusyBox are **not redistributed in this repository**. The test asset manifest points to upstream downloads. Their respective Apache-2.0/BSD, GPL and package-specific license/source obligations must be handled when distributing images or bundled runtime artifacts. No claim is made that the experimental image builder is a complete production image distribution pipeline.
