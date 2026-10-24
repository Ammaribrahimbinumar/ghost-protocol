# Key management

## Implemented in source (not compiled)
- **Unlock verifier key material:** the user's numeric code is never stored. A PBKDF2-HMAC-SHA256 hash (600,000 iterations, 16-byte random salt) is stored inside a record encrypted with a 256-bit AES-GCM key generated in Android Keystore (`KeystoreSecretStore`): non-exportable, StrongBox when available, random IV per write. If the key or ciphertext is missing/damaged the app reports corruption and does **not** silently reset.
- No default code. No recovery or escrow: forgetting the code means clearing app data.

## Design, not yet implemented
| Key | Generated | Stored | Purpose |
|---|---|---|---|
| Identity key (per device) | On device, by libsignal | Wrapped by a Keystore key | E2EE identity, safety numbers |
| Signed/one-time/post-quantum prekeys | On device | Private halves in encrypted DB; public halves on relay | Session setup |
| Relay auth key (ECDSA P-256) | On device, inside Android Keystore (StrongBox/TEE where available) | Non-exportable; private key never visible to app code | Signs relay requests; separate from identity key |
| Database key (256-bit random) | On device | Wrapped by Keystore AES-GCM key | SQLCipher |
| Per-attachment key (256-bit random) | Per file | In the encrypted message record, and sent inside the E2EE message | Attachment AEAD |

Rules: private keys never leave the device or go to the relay; purposes use separate keys; no key in preferences, logs or source; rotation of prekeys on schedule and after suspected compromise; identity-key changes always surface a warning.

## Update 2026-10-24 (implemented, CI-tested on JVM and emulator; NOT run on a physical phone)
- **Signal identity, prekeys (incl. post-quantum), sessions, pinned contact identities:** `PersistentSignalStore` serializes the full state after every change; `DeviceVault` writes it through `KeystoreSecretStore` (AES-256-GCM, non-exportable Keystore key, atomic file, excluded from backup). A missing/tampered file or missing Keystore key raises an error; the app never silently makes a new identity.
- **Relay auth key:** ECDSA P-256 generated inside Android Keystore (`KeystoreRelaySigner`), StrongBox if present. Whether a given phone backs it with secure hardware is UNVERIFIED (emulator is software).
- Limits: the snapshot is one file rewritten on each change (no per-record DB yet); the Keystore wrapping key is not tied to user authentication, so it protects against file extraction/backup, not against code running as the app on an unlocked, compromised device; the decoy/duress wipe is not implemented.
