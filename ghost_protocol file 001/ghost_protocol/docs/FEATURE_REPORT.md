# Ghost_Protocol — Feature Completion Report

Written at the end of the first working session. Categories:

- **TESTED** — a test was executed in this environment and passed.
- **WRITTEN, NOT COMPILED** — source exists but was never built or run.
- **NOT IMPLEMENTED** — no code.
- **BLOCKED** — cannot proceed without something outside this environment.

## Why the Android app is unbuilt

The sandbox's network policy denies `repo.maven.apache.org`, `maven.google.com` and `dl.google.com` (the proxy log records 403 on CONNECT for each), and no Android SDK is installed. The Android SDK is distributed only from `dl.google.com`. As a result **no Kotlin was compiled and no APK exists.** A standalone Kotlin compiler could not be obtained either. The relay is the only component that was built and run.

To unblock: run the build on a machine with Android Studio (or JDK 17 + Android SDK) and network access, or give this environment access to those hosts. See `BUILD_AND_SIGNING.md`.

## Relay (Go) — TESTED

Command: `cd relay && go vet ./... && go test -race -count=1 ./...` → 14 tests, all PASS.

| Feature | Status | Evidence |
|---|---|---|
| Invite-only registration, single-use invites, hashes stored not codes | TESTED | `TestInviteSingleUseAndUsernameCollision`, `TestPersistence…` |
| Username collision without burning the invite | TESTED | same |
| Admin token required to mint invites | TESTED | `TestAdminInviteRequiresToken` |
| One-time prekeys handed out once each | TESTED | `TestPrekeysArePoppedOnce` |
| Opaque payload stored and returned byte-for-byte; per-mailbox isolation; ack deletes | TESTED | `TestOpaqueRoundTripAndAck` |
| Ed25519 request signing: wrong key, unknown mailbox, stale/future timestamp, replayed nonce, tampered body, redirected recipient, malformed signature all rejected | TESTED | `TestAuthRejections` |
| Envelope size cap, queue cap | TESTED | `TestEnvelopeSizeLimit`, `TestQueueCap` |
| TTL expiry of queued ciphertext, purge from memory | TESTED | `TestTTLExpiryWithFakeClock` |
| Rate limits (per hashed IP, per mailbox) | TESTED | `TestRateLimits` |
| Account deletion removes keys and queue | TESTED | `TestDeleteAccountRemovesEverything` |
| No message body, username, invite, mailbox ID or IP in process logs | TESTED (regression guard; handlers log nothing) | `TestNothingSensitiveIsLogged` |
| Snapshot holds no queued ciphertext and no raw invites; mode 0600; queues do not survive restart | TESTED | `TestPersistence…` |
| TLS 1.3 only; untrusted certificate rejected by client | TESTED | `TestTLS13OnlyAndCertificateValidation` |
| Relay imports no symmetric-cipher or key-agreement packages | TESTED (structural only; not a proof of confidentiality) | `TestRelayImportsNoDecryptionPrimitives` |

**Test quality check:** each of 10 deliberate mutations of the relay (removing replay protection, timestamp check, signature check, body binding, single-use invites, TTL, TLS 1.3 minimum, prekey popping, queue cap; logging a username) was caught by the suite. This shows the tests can fail; it does not show the relay is free of other bugs.

**Relay not done / limits:** sealed sender (relay sees sender and recipient mailboxes, sizes, timing); attachment blob storage; group/broadcast-specific endpoints (broadcast is client-side fan-out over `send`); push notifications; accounts snapshot is a single JSON file (fine for a small invited group, not for scale); in-memory queues lose undelivered messages on restart (deliberate retention trade-off); no production deployment has been done or load-tested; no third-party review.

## Android client

| Feature | Status | Notes |
|---|---|---|
| Gradle project, manifest, backup/data-extraction exclusions, no-cleartext + system-CA-only network config | WRITTEN, NOT COMPILED | Versions in `libs.versions.toml` are unverified placeholders |
| Calculator (arithmetic, decimals, %, parentheses, delete/clear) | WRITTEN, NOT COMPILED | Unit tests written, never run |
| Configurable secret unlock (PBKDF2-HMAC-SHA256, 600k iterations, salt, exponential back-off, no default code) | WRITTEN, NOT COMPILED | Unit tests written, never run |
| Wrong/throttled/right input indistinguishable on the calculator | WRITTEN, NOT COMPILED | Controller test written, never run |
| Keystore-wrapped storage for the verifier record | WRITTEN, NOT COMPILED | Needs real-device testing (StrongBox/TEE behaviour varies) |
| In-app keyboard (QWERTY, symbols, shift) + numeric keypad, no IME | WRITTEN, NOT COMPILED | No language/layout selector |
| Zeroable input buffers | WRITTEN, NOT COMPILED | JVM `String` copies for drawing cannot be wiped |
| FLAG_SECURE, recents protection, overlay hiding, touch filtering | WRITTEN, NOT COMPILED | Not verified on any Android version |
| Accessibility/ADB/dev-options checks with warn/block policy | WRITTEN, NOT COMPILED | Default policy is warn-only (blocking would exclude TalkBack users) |
| Lock on leaving the app | WRITTEN, NOT COMPILED | In-foreground inactivity timer NOT IMPLEMENTED |
| Libsignal E2EE (identity, sessions, ratchet, safety numbers, key-change warnings) | NOT IMPLEMENTED | Library chosen (see ARCHITECTURE.md); needs network to resolve; AGPL decision required |
| Relay client, offline queue consumption | NOT IMPLEMENTED | |
| Encrypted Room/SQLCipher database, search, edit/delete, reactions, replies | NOT IMPLEMENTED | |
| Encrypted attachments | NOT IMPLEMENTED | |
| Groups, broadcast | NOT IMPLEMENTED | |
| Disappearing messages | NOT IMPLEMENTED | |
| Linked devices / revocation / transfer | NOT IMPLEMENTED | |
| Generic notifications | NOT IMPLEMENTED | No notification code exists yet |
| Tor/I2P routing | NOT IMPLEMENTED | |
| Decoy/duress mode | NOT IMPLEMENTED | |
| Screen-capture detection callback (API 34) | NOT IMPLEMENTED | |
| Conversation list, chat, group, broadcast, attachment, verification, linked-device, settings screens | NOT IMPLEMENTED | Only calculator, setup, corruption and a labelled placeholder screen exist |
| Signed APK | BLOCKED | No Android SDK / blocked hosts |

## Final acceptance criteria (spec section 22)

| Criterion | Status |
|---|---|
| Two installed clients exchange encrypted messages | NOT MET |
| Relay cannot decrypt contents | Structurally true (it never receives keys; relay tests pass). Not demonstrated end to end |
| Client detects tampering | NOT MET (no client crypto) |
| Contact identity verification works | NOT MET |
| Messages encrypted in local storage | NOT MET |
| No plaintext in logs/notifications | Relay: TESTED. Client: NOT MET |
| Calculator unlock works | Written, not compiled, not run |
| In-app keyboard composes and sends | Composes (written, not run); sending NOT MET |
| Screenshot protection on sensitive screens | Written, not verified |
| Groups/broadcast | NOT IMPLEMENTED (explicitly marked) |
| Backup exclusion verified | Rules written, NOT verified |
| Build/install instructions work | Written, NOT executed |
| Limitations document matches implementation | Written; see `SECURITY_LIMITATIONS.md` |

**Overall: this is a tested relay plus a small, uncompiled Phase 1 client. It is not a usable messenger, and no security claim about the client should be relied on yet.**
