# Ghost_Protocol — decisions log

## 2026-10-20: Protocol and licence (delegated to Claude by the owner)
- **Protocol:** Signal protocol via libsignal (PQXDH + Double Ratchet, Sender Keys for groups, per-recipient fan-out for broadcast). No home-made cryptography.
- **Licence route:** libsignal is AGPL-3.0, so Ghost_Protocol will be released under AGPL-3.0 with source public (repo `Ammaribrahimbinumar/ghost-protocol`). Invitees can obtain source. Consequence: the design must stay secure with its source public (it should anyway).
- **Version pinning:** libsignal's current version lives in Signal's own Maven repository (`build-artifacts.signal.org/libraries/maven/`), which the sandbox cannot reach. Verify and pin it through the CI runner, then record it in DEPENDENCIES.md.
- **Build:** GitHub Actions (sandbox cannot reach Android/Maven hosts). Phase 1 compiled and unit-tested in CI (run 39322571415). Not yet run on a device.

## Security rules that must not be weakened
1. No default unlock code; verifier only (PBKDF2, salted); throttling; no recovery backdoor.
2. Private keys never leave the device; relay never receives keys or plaintext.
3. Never mark a security feature PASS without an executed test; keep FEATURE_REPORT honest.
4. No analytics/telemetry SDKs; minimal permissions (INTERNET, HIDE_OVERLAY_WINDOWS only so far).
5. Backups excluded; cleartext traffic off; system CAs only.
6. Identity-key changes must warn; safety-number verification is the defence against a malicious relay.
7. Debug APKs are for testing only; release signing keys never enter the repo or CI.

## Next steps
1. Phase 2: libsignal integration (identity, prekeys, sessions, safety numbers) with a two-client encrypt/decrypt/tamper/replay test run in CI.
2. Phase 3: relay client and end-to-end message flow against the tested relay.
3. Phase 4: SQLCipher storage, notification hygiene.
Open blocker: Claude's GitHub app lacks push access to the repo, so each change is hand-copied by the owner.
