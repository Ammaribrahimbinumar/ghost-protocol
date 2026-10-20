# Ghost_Protocol — Architecture

Status legend used across all project documents:
**IMPLEMENTED** (code exists) · **TESTED** (a test was actually run and passed) · **NOT COMPILED** (source written, never built) · **NOT IMPLEMENTED** · **BLOCKED**.

Build note: the authoring sandbox cannot reach Android/Maven hosts, so builds and tests run on GitHub Actions. See `FEATURE_REPORT.md` for exactly what has been run.

## 1. Components

```
 Android client A ──TLS 1.3──┐                    ┌──TLS 1.3── Android client B
 (Kotlin/Compose)            ▼                    ▼            (Kotlin/Compose)
                        ┌───────────────────────────┐
                        │  Relay (Go, stdlib)       │  opaque envelopes only
                        │  - invite registration    │  short-lived queues (TTL)
                        │  - public prekey bundles  │  no message keys, no plaintext
                        │  - mailbox queues         │
                        └───────────────────────────┘
```

* **Client** holds all private keys and all plaintext. It is the only place decryption happens.
* **Relay** stores: public key material, hashed/random routing identifiers, and encrypted envelopes until acknowledged or expired. It is a trusted party for *availability and metadata*, not for confidentiality.

## 2. Cryptographic protocol decision

**Chosen: Signal protocol via `libsignal` (`org.signal:libsignal-android`)**
- 1:1: PQXDH/X3DH session setup + Double Ratchet (forward secrecy, post-compromise recovery, replay/tamper detection via AEAD + message counters).
- Groups: Sender Keys. Membership removal ⇒ every remaining member generates a new sender-key chain (new distribution ID) and redistributes it over pairwise sessions.
- Broadcast: no shared group object. The sender encrypts separately per recipient over each pairwise session (recipients cannot see each other).
- Safety numbers / QR: fingerprints computed by libsignal's fingerprint generator over both identity keys.

**Findings from checking the library (sources fetched during this session):**
1. License is **AGPL-3.0**. Distributing an APK that links it to invited users means those users must be able to obtain the app's corresponding source. Ghost_Protocol must therefore be released under AGPL-3.0-compatible terms. This is a real constraint, not a formality — decide before distributing. (Source: https://github.com/SignalApp/libsignal-client)
2. The project states "Use outside of Signal is unsupported" and that APIs may change without notice. Pin an exact version and re-run the crypto tests on every upgrade.
3. **Pinned version: 0.105.1**, the latest in Signal's own Maven repository (verified by a CI run; the Maven Central copy is stale). The JVM artifact needs JDK 21 and Kotlin 2.2+.
4. **Licence decision (owner delegated to Claude): AGPL-3.0 with public source.** (Source: https://central.sonatype.com/artifact/org.signal/libsignal-android)

**Alternative considered:** Matrix Olm/Megolm (vodozemac, Apache-2.0). Not selected because Android/Kotlin binding availability and maintenance could not be verified in this session. Mixing the two stacks is explicitly rejected (one coherent protocol).

Never implemented by us: any cipher, KDF, ratchet, or key agreement. Platform primitives are used only for local storage keys (Android Keystore AES-256-GCM, PBKDF2/Argon2-class KDF for the unlock verifier).

## 3. Identity and routing separation

| Identifier | Purpose | Who sees it |
|---|---|---|
| Identity key pair (per device) | E2EE identity, safety numbers | Contacts, relay (public half, inside bundle) |
| Relay auth key (Ed25519, separate pair) | Authenticating to relay | Relay |
| Mailbox ID (random 128-bit) | Message routing | Relay, contacts who message you |
| Username | Human-friendly lookup, *not* a secret | Relay, people who know it |

Keeping the auth key and mailbox ID separate from the Signal identity key means a relay operator cannot link routing records to cryptographic identities by key equality.

Registration: single-use invitation code + username + auth public key + prekey bundle. No phone number or email. No public directory: lookup requires knowing the exact username; the relay does not offer search or listing.

## 4. Message flow (1:1)

1. A fetches B's bundle from relay by username (relay hands out and deletes one one-time prekey).
2. A runs PQXDH locally, encrypts with the Double Ratchet, wraps into an envelope, posts it to B's mailbox (authenticated to relay).
3. Relay appends the opaque bytes to B's queue with a TTL (default 7 days).
4. B (authenticated) fetches, decrypts locally, acknowledges; relay deletes the envelope.

**Known metadata exposure (not hidden):** relay sees sender mailbox, recipient mailbox, envelope size and timing, and connecting IP (not retained by design). Sealed sender is **NOT IMPLEMENTED**; it would need a sender-certificate issuance flow. Listed as future work, not silently approximated.

## 5. Local storage (client)

- Room + SQLCipher (`net.zetetic:sqlcipher-android`; 4.18.0 release notes confirm Room 3 support; the exact Android package version must be pinned after verification).
- Database key: random 256-bit, wrapped with a non-exportable Android Keystore AES-GCM key (StrongBox where available). The wrapped key is stored beside the DB; the wrapping key never leaves the Keystore.
- Attachments: per-file random AES-256-GCM key in the message record; ciphertext files in app-private storage; no thumbnails written in plaintext.
- `android:allowBackup="false"`, explicit `dataExtractionRules`/`fullBackupContent` excluding everything.
- Disappearing messages: scheduled deletion of rows and attachment files, plus a sweep on every unlock.

## 6. Unlock, calculator, keyboard

- Calculator is the launcher activity. A configurable secret is verified on "=": PBKDF2/Argon2-class derivation with per-install salt, constant-time compare, exponential back-off stored in the Keystore-protected state. No default code exists.
- Duress credential: a second verifier opens a decoy workspace backed by a *separate* key and database. It never reveals whether the real vault exists. Destructive behavior is **off by default**.
- In-app keyboard: a Compose-drawn keyboard feeding `ByteArray`/`CharArray` buffers that are zeroed after send; `FLAG_SECURE` on all sensitive windows; no IME is invoked for message entry. It is *not* a system IME.
- Risk checks before revealing chats: enabled accessibility services, USB debugging, overlay-capable apps where detectable, active projection. Configurable policy: warn or block. Detection is best-effort only.

## 6.1 Honest limits
A calculator front-end is a discretion measure, not invisibility. Package list, permissions, notifications and network traffic remain observable to Android and to anyone with device access.

## 7. Repository layout

```
relay/      Go relay + tests            (IMPLEMENTED, TESTED)
android/    Kotlin/Compose client       (compiled + unit-tested in CI; not run on a device)
android/core-crypto  libsignal wrapper, pure JVM (tested in CI)
docs/       architecture, threat model, reports
```
