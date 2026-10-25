# Opt-in owned-L1 PKI producer

Test input producer only, compiled with `xandbox_managed_fixture` on Linux.
It is not a production service or an acceptance report. Its presence does not
qualify the root installer, real ingress child, kernel empty-subtree proof or KVM.

The fixed `setup`, `rotation2`, `rotation2long`, `rotation3`, `replacement2a`
and `replacement2b` operations require root, systemd
PID 1, the exact managed-fixture marker and a private fixed output directory.
There are no task arguments, alternate roots, service actions or signals.
Setup emits a managed v2 initial config/envelope, two independent backend/external
authorities and a fresh synthetic CA. The CA private key is persisted **only in
the test image's private fixture directory** for the later test leafs. Never use
the generated credentials outside that disposable image or publish their bytes.

Rotation reads the actual installed base/config/envelope/backend authority and
only emits new private source/plan/client files. It cannot overwrite installed
policy/state. Epoch 2 deliberately has a **one-minute test-only TLS lifetime**;
epoch 3 can be generated after that leaf expires, but preserves backend tokens,
identity and the original CA. It rotates the external tokens and TLS pair.
The production admission path must still validate the new policy at actual time;
the old expired policy must not become serving-valid.

`replacement2a`/`replacement2b` read the **actual installed epoch1**, not an
abandoned epoch2 proposal, and emit separate fresh long-lived epoch2 material.
Their filenames are closed (`snapshot-replacement-2a.json`/`2b`, matching plans
and clients); each has independent TLS and external credentials, the original CA
and unchanged backend authority. They do not consume, publish, acknowledge or
reuse an installed epoch. They refuse if epoch2 has already been installed.
`rotation2long` uses the ordinary epoch2 filenames with a 24-hour synthetic leaf
for a separate ordinary hot-rotation case. All outputs remain exclusive-create;
it cannot overwrite a previous short `rotation2` or any installed file.

These additions only prepare inputs for future actual supersession/hot-rotation
cases. Producer tests, fresh material or an unchanged runtime binary are not
evidence that those root CLI/hardware cases have executed or passed.

The tagged unit tests generate real ephemeral PKI and check trust, expiry,
fresh credentials, fixed plan hashes, backend stability and malformed/foreign
authority rejection. They are pure producer tests, not execution of the root
operations or proof of a real interrupted recovery.
