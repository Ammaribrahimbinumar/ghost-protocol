# Ghost_Protocol

Privacy-focused Android messenger (calculator front-end, E2EE, invite-only, username-only) with a minimal Go relay.

**Status after session 1: a tested relay and an uncompiled Phase 1 Android client. Not a usable messenger yet.** Read `docs/FEATURE_REPORT.md` first.

- `relay/` — Go relay, built and tested (14 tests, race detector on).
- `android/` — Kotlin/Compose Phase 1 source (calculator, unlock, in-app keyboard, window hardening). Never compiled: the sandbox could not reach Maven Central, Google Maven or the Android SDK host.
- `docs/` — architecture, threat model, key management, permissions, privacy/retention, limitations, dependency inventory, build/signing, manual test checklist, feature report.

Next steps, in order: build and run the Phase 1 tests on a networked machine and record results; decide the AGPL question for libsignal; pin and verify dependency versions; then Phase 2 (libsignal integration) with the two-client E2EE test.
