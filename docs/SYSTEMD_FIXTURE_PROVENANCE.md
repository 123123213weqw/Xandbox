# TEST systemd composition provenance

The owned systemd fixtures declare the **actual source-bound composition**, not
an older source label combined with newly built programs. This changes only
TEST tooling/metadata and CI. It does not change the production installer,
publisher, daemon, guest executor, resource limits, failure windows or budgets.

`scripts/systemd_fixture_provenance.py` binds the complete fixed inventories:

- 9 deployment, 12 ingress, 13 readiness, 15 release or 16 initial/managed roles;
- the initial and managed setup helpers have distinct required digests;
- all 13 Go programs are checked against fresh canonical CI builds;
- external Firecracker/jailer/kernel/initrd/workspace digests are checked before
  assembling the actual KVM image, not claimed as available in hosted CI.

## Current scoped-revocation candidate (not KVM-qualified)

The current publication source is `9e2b5c9f772c5df673a0d71876da0ff286672d8c`.
The two-source release-CAS inputs use that revision and
`9aab936a09ed120f2050083f4664aae0a28bc228`.
[The two actual canonical native program inventories](validation/scoped-revoke-systemd-calibration-v1.json)
have byte-equal thirteen-role outputs; an independent cross build agrees.
The full role counts, distinct setup helpers, external image pins and two-source
CAS protocol are unchanged. No additional source override or accepted ELF hash
was added. This gate is **artifact coherence**, not a full source/KVM certificate.

The second source's first software batch exited **1** after its thirteen builds
and pair gate passed: `TestPrepareProbePinnedOrdinaryELF` rejected all three runs
because nine absolute probe addresses were still from the old ELF. The original
failure is retained, not reclassified as a passing fixture suite.
[Offline location calibration](validation/scoped-revoke-nine-sites-calibration-v1.json)
compares all 207 instructions in the three target functions, retaining source
lines, relative instruction boundaries, registers and symbolic control flow.
The nine fixed entry probes keep their exact opcode bytes/registers; only their
current absolute addresses move by 64 bytes. The whole-ELF/symbol/opcode checks,
owned-L1 guards and refusal to trace L0 remain. No live probes were registered
by that offline analysis; full current native and hardware validation is pending.

Hosted Linux CI now also runs that read-only ELF test three times against its
fresh canonical daemon, in addition to the pair and thirteen-program gates.
It does not mount tracefs, execute the input ELF or register live probes. A new
whole-file hash alone can no longer conceal stale instruction locations.

## Historical composition (not re-signed)

The historical publication source was `00dc99de10b52d6988b52f12760f61e3fd43fb3d` (Native22).
The two-source release-CAS experiment uses that source and
`bf405dccbead973eacadfa89a0c6866fcc266e36` (Native21). Those independently
qualified builds have byte-equal publication roles. Their host-fixture binary
differs, but it is **not** one of the thirteen published roles. Historical
hardware records keep their original sources; this does not re-sign them.
The original pinned external guest images remain external data, not a claim
that their guest code was built from this source or their memory is pristine.

Previously, initial and managed builders declared `4167804...` and `4587a9d...`,
and the release guest used two older source IDs. A publisher checks manifest
syntax and content digests, not a compiler/source attestation. Consequently a
stale source label could survive publication; passing syntactic validation was
not evidence of current-build provenance. This was found before launching the
current full systemd matrix, not by rewriting an old failed runtime report.

The actual harness rejects a missing, extra, crossed or mismatched role before
creating reports, receipts or resources. The image builder independently runs
the same gate before extraction or disk allocation. Within this gate, every
declared role is validated before any input is opened; bounded regular descriptors, exact
hashes, static amd64 ELF checks and before/after descriptor metadata are used.
No input is executed by this verifier. The existing builders also hash copied
bytes: a successful read is not a lease over a pathname that can later change.

The standalone CI reader emits a closed result without raw paths or errors:

```sh
python3 scripts/systemd_fixture_provenance.py --programs-dir /absolute/canonical-build-directory
```

This is a coherence gate, **not a security signature, compiler attestation,
systemd/KVM integration acceptance or production-readiness claim**. Rootfs,
kernel and module pins, all original resource profiles, controller inventory,
capabilities, real TLS/KVM execution, Stop versus durable reclamation, state
locks, original-disk cold recovery, all eight managed cases and the complete
production Goal still require their own actual evidence. Synthetic reader and
image-layout unit tests do not substitute for those gates.
