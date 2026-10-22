# Ghost_Protocol — Feature Completion Report

Written at the end of the first working session. Categories:

- **TESTED** — a test was executed in this environment and passed.
- **COMPILED + UNIT TESTS PASS IN CI (not run on a device)** — source exists but was never built or run.
- **NOT IMPLEMENTED** — no code.
- **BLOCKED** — cannot proceed without something outside this environment.

## CI result (GitHub Actions, branch `claude/phase2-crypto`, run 39482322352, commit f0c959c)
On GitHub-hosted runners (ubuntu-24.04, JDK 21, Gradle 8.9, Kotlin 2.2.20): **relay job PASS (go vet + 14 tests, -race); android job PASS: 64 unit tests, 0 failures, 0 skipped (49 app tests + 15 crypto-core tests, counts read from the XML reports).** A debug APK is also built. The APK has not been run on a device; all on-device behaviour (FLAG_SECURE, Keystore, keyboard) remains UNVERIFIED. libsignal itself (the cryptography) is not tested by us beyond using it correctly; its correctness is assumed.

## Phase 3 relay integration (CI run on branch `claude/phase3-relay-client`, commit 8d43344) — TESTED IN CI
**75 tests, 0 failures, 0 skipped** (49 app + 15 protocol + 5 packet/encoding + 6 relay-integration). CI builds the real Go relay, starts it on loopback, and runs two Kotlin clients (separate identities, separate ECDSA P-256 relay-auth keys) through it over HTTP, then greps the relay's log.
Integration tests (`RelayIntegrationTest`): full round trip through the relay with ack; the bytes the relay holds do not contain the plaintext; **relay-side tampering of any single byte of a queued message is detected** (genuine message still decrypts); **relay replaying an unacknowledged message is rejected**; **relay substituting another user's key bundle is exposed by safety numbers** (first contact cannot prevent it; verification detects it); **a spoofed sender name cannot impersonate another user**; unsigned/wrongly-signed requests and oversized payloads are rejected. CI step: relay log contains no message text, usernames or mailbox IDs (clean).
Limits: clients are in-process JVM test clients, **not installed apps**; transport is plain HTTP on loopback for the test only (the client refuses non-https otherwise; TLS 1.3 server behaviour is covered by the relay's own test); relay-auth signing was moved from Ed25519 to ECDSA P-256 (2026-10-22) so the key can live in Android Keystore on API 26+; the app-side Keystore key creation is NOT yet implemented or device-tested; the sender username is visible to the relay in each packet (sealed sender NOT IMPLEMENTED); no persistent storage yet; no groups/broadcast/attachments; "Not run on a device".

## Phase 2 crypto core (`android/core-crypto`, pure JVM, libsignal-client 0.105.1) — TESTED IN CI
15 tests in `ProtocolTest`, all passing: two-party round trip both directions (20 exchanges); ciphertext does not contain plaintext and is randomised; **every single-byte modification of a message is rejected** and a failed forgery does not damage the session; truncated/empty envelopes rejected; replay rejected (DuplicateMessageException); out-of-order delivery works; wrong recipient and wrong sender address cannot decrypt; **changed identity key is rejected (UntrustedIdentityException), not silently trusted**; safety numbers match for honest parties and differ under a substituted key; independent one-time prekeys; session without a one-time prekey; prekey-message replay after key consumption rejected; malformed bundles rejected without crashing; forged signed-prekey signature rejected.
Limits: in-memory stores only (no persistence); two-party only (no groups/broadcast yet); forward secrecy and post-compromise recovery are properties of the Signal protocol/libsignal and are **not** independently tested here; not yet wired into the Android app (needs libsignal-android swap); no relay integration yet.

## Background: why builds run in CI, not in the sandbox

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
| ECDSA P-256 request signing (relay accepts only P-256 SPKI keys; P-384, Ed25519, truncated, trailing-data and garbage keys refused): wrong key, unknown mailbox, stale/future timestamp, replayed nonce, tampered body, redirected recipient, malformed signature all rejected | TESTED | `TestAuthRejections` |
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
| Gradle project, manifest, backup/data-extraction exclusions, no-cleartext + system-CA-only network config | COMPILED + UNIT TESTS PASS IN CI (not run on a device) | Versions in `libs.versions.toml` are unverified placeholders |
| Calculator (arithmetic, decimals, %, parentheses, delete/clear) | COMPILED + UNIT TESTS PASS IN CI (not run on a device) | Unit tests written, never run |
| Configurable secret unlock (PBKDF2-HMAC-SHA256, 600k iterations, salt, exponential back-off, no default code) | COMPILED + UNIT TESTS PASS IN CI (not run on a device) | Unit tests written, never run |
| Wrong/throttled/right input indistinguishable on the calculator | COMPILED + UNIT TESTS PASS IN CI (not run on a device) | Controller test written, never run |
| Keystore-wrapped storage for the verifier record | COMPILED + UNIT TESTS PASS IN CI (not run on a device) | Needs real-device testing (StrongBox/TEE behaviour varies) |
| In-app keyboard (QWERTY, symbols, shift) + numeric keypad, no IME | COMPILED + UNIT TESTS PASS IN CI (not run on a device) | No language/layout selector |
| Zeroable input buffers | COMPILED + UNIT TESTS PASS IN CI (not run on a device) | JVM `String` copies for drawing cannot be wiped |
| FLAG_SECURE, recents protection, overlay hiding, touch filtering | COMPILED + UNIT TESTS PASS IN CI (not run on a device) | Not verified on any Android version |
| Accessibility/ADB/dev-options checks with warn/block policy | COMPILED + UNIT TESTS PASS IN CI (not run on a device) | Default policy is warn-only (blocking would exclude TalkBack users) |
| Lock on leaving the app | COMPILED + UNIT TESTS PASS IN CI (not run on a device) | In-foreground inactivity timer NOT IMPLEMENTED |
| Identity + prekey generation, bundle encode/decode, 1:1 session setup and encryption via libsignal | TESTED IN CI (JVM, in-memory) | `core-crypto` ProtocolTest |
| Tamper detection, replay rejection, out-of-order delivery | TESTED IN CI | same |
| Identity-key-change rejection at crypto layer | TESTED IN CI | User-facing warning screen NOT IMPLEMENTED |
| Safety-number computation (match/mismatch) | TESTED IN CI | QR scan and verification UI NOT IMPLEMENTED |
| Persistent encrypted key/session storage; libsignal-android integration into the app | NOT IMPLEMENTED | Phase 4 / next step |
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
| Two installed clients exchange encrypted messages | PARTIAL: two in-process JVM clients exchange and decrypt through the real relay in CI; no installed apps |
| Relay cannot decrypt contents | Demonstrated in CI: relay never receives keys; bytes it holds contain no plaintext; its log is clean. (Not a proof; a relay can still see metadata) |
| Client detects tampering | Crypto layer TESTED IN CI (all byte flips rejected); not yet in the app |
| Contact identity verification works | Crypto layer TESTED (safety numbers, key-change rejection); no UI yet |
| Messages encrypted in local storage | NOT MET |
| No plaintext in logs/notifications | Relay: TESTED. Client: NOT MET |
| Calculator unlock works | Written, not compiled, not run |
| In-app keyboard composes and sends | Composes (written, not run); sending NOT MET |
| Screenshot protection on sensitive screens | Written, not verified |
| Groups/broadcast | NOT IMPLEMENTED (explicitly marked) |
| Backup exclusion verified | Rules written, NOT verified |
| Build/install instructions work | Written, NOT executed |
| Limitations document matches implementation | Written; see `SECURITY_LIMITATIONS.md` |

**Overall: a tested relay, a Phase 1 client that compiles and passes unit tests in CI, and a tested libsignal crypto core that is not yet connected to the app. It is not a usable messenger yet.**
