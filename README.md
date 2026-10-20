# Ghost_Protocol

Privacy-focused Android messenger (calculator front-end, E2EE, invite-only, username-only) with a minimal Go relay.

**Status: tested relay; Phase 1 app compiles and passes unit tests in CI; libsignal crypto core tested in CI but not yet connected to the app. Not a usable messenger yet.** Read `docs/FEATURE_REPORT.md` first.

- `relay/` — Go relay, built and tested (14 tests, race detector on).
- `android/` — Kotlin/Compose app (calculator, unlock, in-app keyboard, window hardening) and `android/core-crypto` (libsignal wrapper, 15 protocol tests). CI builds and tests both; never run on a device.
- Licence: AGPL-3.0 (required by libsignal).
- `docs/` — architecture, threat model, key management, permissions, privacy/retention, limitations, dependency inventory, build/signing, manual test checklist, feature report.

Next steps, in order: build and run the Phase 1 tests on a networked machine and record results; decide the AGPL question for libsignal; pin and verify dependency versions; then Phase 2 (libsignal integration) with the two-client E2EE test.
