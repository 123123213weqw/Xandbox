# Opt-in owned-L1 PKI producer

Test input producer only, compiled with `xandbox_managed_fixture` on Linux.
It is not a production service or an acceptance report. Its presence does not
qualify the root installer, real ingress child, kernel empty-subtree proof or KVM.

The fixed `setup`, `rotation2` and `rotation3` operations require root, systemd
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

The tagged unit tests generate real ephemeral PKI and check trust, expiry,
fresh credentials, fixed plan hashes, backend stability and malformed/foreign
authority rejection. They are pure producer tests, not execution of the root
operations or proof of a real interrupted recovery.
