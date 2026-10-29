# TEST systemd composition provenance

The owned systemd fixtures now declare the **actual qualified composition**, not
an older source label combined with newly built programs. This changes only
TEST tooling/metadata and CI. It does not change the production installer,
publisher, daemon, guest executor, resource limits, failure windows or budgets.

`scripts/systemd_fixture_provenance.py` binds the complete fixed inventories:

- 9 deployment, 12 ingress, 13 readiness, 15 release or 16 initial/managed roles;
- the initial and managed setup helpers have distinct required digests;
- all 13 Go programs are checked against fresh canonical CI builds;
- external Firecracker/jailer/kernel/initrd/workspace digests are checked before
  assembling the actual KVM image, not claimed as available in hosted CI.

The publication source is `00dc99de10b52d6988b52f12760f61e3fd43fb3d` (Native22).
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
