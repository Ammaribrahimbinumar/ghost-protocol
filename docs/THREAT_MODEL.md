# Ghost_Protocol — Threat Model

Every row gives: protection, test method, residual risk, and the condition under which the protection fails.
"Test status" is **NOT RUN** unless a test was actually executed. Relay tests are in `relay/`; client tests are written but **NOT COMPILED/NOT RUN**.

| # | Threat | Protection (by design) | Test method | Residual risk / failure condition | Test status |
|---|---|---|---|---|---|
| 1 | Public Wi-Fi attacker | TLS 1.3 to relay + E2EE inside | Invalid-cert client test; packet capture shows only ciphertext | Attacker still sees that you talk to the relay, and traffic volume/timing | NOT RUN |
| 2 | Malicious network operator | Same as 1; optional Tor routing | As above | Operator can block, delay, or fingerprint traffic; Tor does not defeat global traffic analysis | NOT RUN |
| 3 | Compromised or malicious relay | Relay only holds opaque envelopes and public keys; clients verify identity keys end to end | Relay unit test: stored bytes are byte-identical opaque payloads; no key material in server code (grep audit); client tamper test | Relay can drop, delay, delete messages, and learn who talks to whom and when. A relay that substitutes public keys during first contact defeats unauthenticated sessions — **safety-number verification is the only defence** | Relay opacity: see relay tests. Client: NOT RUN |
| 4 | DNS manipulation | TLS certificate validation; E2EE identity keys independent of DNS | Wrong-host cert test | Pinning is optional and needs a rotation plan; without it a CA compromise permits relay impersonation (not decryption) | NOT RUN |
| 5 | Replay attacks | Double Ratchet counters reject re-delivery; relay deletes on ack | Replay same envelope twice into the client session | Relay replay is rejected by the client; replay within the skipped-key window depends on library behaviour | NOT RUN |
| 6 | Message tampering | AEAD with authentication in the protocol | Flip a bit in ciphertext; expect decryption failure | None beyond library defects | NOT RUN |
| 7 | Unauthorized group membership | Admin-signed membership changes; sender-key redistribution only over verified pairwise sessions | Add/remove tests | A malicious admin can add a rogue member; removed members keep earlier messages | NOT IMPLEMENTED (client) |
| 8 | Malicious or modified APK | Release signing; publish SHA-256 of the APK out of band; build is reproducible only if the toolchain is pinned | Verify signature with `apksigner verify`; compare hash | Invited users who install an unsigned or re-signed APK are fully exposed. Android does not prove provenance for sideloaded apps | NOT RUN |
| 9 | Database theft | SQLCipher; key wrapped by Keystore | Pull DB from a rooted emulator; confirm no plaintext strings | Unlocked-device or rooted-device attackers can use the running app. If the Keystore key is extractable (no hardware backing), protection is weaker | NOT RUN |
| 10 | Backup extraction | `allowBackup=false` + exclusion rules | `adb backup`/device-transfer inspection | OEM/device-transfer behaviour varies by version | NOT RUN |
| 11 | Notification leakage | Generic "New message" text only, secret-visibility on lock screen | Inspect posted notifications | Notification existence and timing remain visible | NOT RUN |
| 12 | Malware capturing app content | `FLAG_SECURE`, accessibility/overlay risk checks, no own accessibility service | Screenshot attempt; scan with a test accessibility service enabled | A compromised OS, root, screen-reading malware, or a camera defeats all app-level protection. Detection is best effort | NOT RUN |
| 13 | Rooted/modified OS | Best-effort detection and warning only | Manual test | Cannot be fully defended; do not claim otherwise | NOT RUN |
| 14 | Physical access, unlocked phone | Inactivity re-lock, calculator front, in-app keyboard buffers cleared | Manual test | An unlocked phone with the app open exposes everything on screen | NOT RUN |
| 15 | Coerced unlock | Optional duress credential and decoy workspace | Manual test | Decoy mode does not defeat forensic examination; package/state remnants remain; does not guarantee safety under coercion | NOT IMPLEMENTED |
| 16 | Relay abuse / spam | Single-use invites, per-IP-hash and per-mailbox rate limits, queue size caps | Relay tests | Distributed abuse from many IPs; a leaked invite is usable once | See relay tests |
| 17 | Keyboard/clipboard leakage | In-app keyboard; no clipboard writes by default; `FLAG_SECURE` | Inspect clipboard and logs | Copy/paste features, if enabled by the user, leak to the clipboard | NOT RUN |
| 18 | Temp-file leakage | App-private cache only, encrypted temp files, wipe on lock | Inspect app-private dirs after use | Process memory may retain data; wiping is best effort on the JVM | NOT RUN |

## Assumptions
1. libsignal is correct and used as documented.
2. The user's device is not already compromised at the OS level.
3. Safety numbers are compared out of band for any contact that matters.

## Explicit non-goals
- Hiding that Ghost_Protocol is installed from Android or an examiner.
- Anonymity against a global passive adversary.
- Guaranteeing deletion on the recipient's device.
