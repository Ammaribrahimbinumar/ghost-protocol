# Key management

## Implemented in source (not compiled)
- **Unlock verifier key material:** the user's numeric code is never stored. A PBKDF2-HMAC-SHA256 hash (600,000 iterations, 16-byte random salt) is stored inside a record encrypted with a 256-bit AES-GCM key generated in Android Keystore (`KeystoreSecretStore`): non-exportable, StrongBox when available, random IV per write. If the key or ciphertext is missing/damaged the app reports corruption and does **not** silently reset.
- No default code. No recovery or escrow: forgetting the code means clearing app data.

## Design, not yet implemented
| Key | Generated | Stored | Purpose |
|---|---|---|---|
| Identity key (per device) | On device, by libsignal | Wrapped by a Keystore key | E2EE identity, safety numbers |
| Signed/one-time/post-quantum prekeys | On device | Private halves in encrypted DB; public halves on relay | Session setup |
| Relay auth key (Ed25519) | On device | Keystore-wrapped | Signs relay requests; separate from identity key |
| Database key (256-bit random) | On device | Wrapped by Keystore AES-GCM key | SQLCipher |
| Per-attachment key (256-bit random) | Per file | In the encrypted message record, and sent inside the E2EE message | Attachment AEAD |

Rules: private keys never leave the device or go to the relay; purposes use separate keys; no key in preferences, logs or source; rotation of prekeys on schedule and after suspected compromise; identity-key changes always surface a warning.
