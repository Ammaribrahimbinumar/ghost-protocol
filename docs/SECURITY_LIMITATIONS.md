# Security limitations

Read together with `THREAT_MODEL.md` and `FEATURE_REPORT.md`.

## Current state
- The Android app is **not yet connected to end-to-end encryption**. The libsignal-based crypto core exists and passes its tests in CI, but nothing in the app sends or stores messages yet, so the app should not be treated as protecting messages.
- The Android code compiles and its unit tests pass in CI, but it has **never been run on a device**. Every on-device claim below is a design intent until tested on real phones.
- No external security review or penetration test has been done. None is claimed.

## Known gaps in the current implementation
- The sender username is sent in clear inside each packet and the relay sees which mailbox sent it. Sealed sender is not implemented.
- First contact is trust-on-first-use: a malicious relay can substitute keys at first contact; only comparing safety numbers detects it (tested: the numbers differ).
- The relay-auth key is ECDSA P-256 so it can live in Android Keystore on every supported phone (minSdk 26). The Keystore-backed key class is written in the crypto core only as a generic signer; creating the hardware-backed key in the app is not yet implemented, and the real hardware backing is unverified until tested on devices.

## Inherent limits (even when finished)
- **Not undetectable.** Android exposes the package name, permissions, notifications and network connections. The calculator label is a discretion measure only.
- **Metadata.** The relay can see who connects, when, how much data, and (without sealed sender) which mailbox sends to which. Encryption does not hide that. Tor/I2P reduces IP exposure but does not defeat traffic analysis by a strong observer.
- **Relay trust.** The relay can drop, delay or delete messages, and a malicious relay can try to substitute public keys at first contact. Only out-of-band safety-number verification defeats that.
- **Endpoint compromise.** Malware, root, a modified OS, an unlocked phone, a screen-reading service or a camera pointed at the screen all bypass app-level protections (FLAG_SECURE, in-app keyboard, risk checks). Detection is best-effort and cannot prove a device is clean.
- **Screenshots/recording.** FLAG_SECURE blocks standard capture paths only.
- **Disappearing messages and deletion** cannot remove copies a recipient or compromised device already has.
- **Removed group members** keep what they received before removal.
- **Duress/decoy mode** does not defeat forensic analysis or guarantee safety under coercion. Someone who knows the app has a decoy mode can demand the real code; flash storage may retain remnants after erase; the relay account and queued messages are untouched by a wipe.
- **Groups** use pairwise fan-out; the relay sees each member message separately, and only the creator can change membership. **Attachments** are 1:1 only, ≤1 MiB.
- **Not implemented:** linked devices, notifications, Tor/I2P, sealed sender, SQLCipher, group attachments. Never run on a physical phone; no security audit or penetration test exists.
- **No recovery path.** A forgotten unlock code means wiping app data; there is deliberately no backdoor. With backups disabled, lost devices mean lost history.
- **Throttling uses the wall clock;** someone who can move the device clock forward can skip a lockout.
- **JVM memory.** Zeroing buffers reduces exposure, but Strings drawn to the screen and runtime copies cannot be wiped.

## Library constraints
- `libsignal` is AGPL-3.0 and states that use outside Signal is unsupported and its API may change without notice. Distributing the APK to invitees means they must be able to obtain the app's source.
- Library versions in the project are unverified placeholders until resolved on a networked machine.

## Added 2026-10-26 (messaging client)
- Keys and decrypted messages stay in process memory while the app process lives; locking hides the UI and clears UI state but does not wipe memory or the Signal store. Rooted/instrumented devices can read them.
- The relay sees sender username, recipient mailbox, size and timing for every message (sealed sender NOT implemented) and the account list.
- Trust-on-first-use: the first identity key seen for a username is pinned; a malicious relay present at first contact could substitute keys until users compare safety numbers (the UI makes this a one-tap flow but it is manual).
- A tunnel service used for testing can see connection metadata. Use your own server + certificate for anything real.
- Debug builds permit cleartext to 127.0.0.1 only (for emulator tests); release config does not.
- No notifications and no background fetching: messages arrive only while the app is open and unlocked.
- Chat state snapshot is a single file rewritten on every change; a crash mid-write is handled by Android AtomicFile, but large histories will be slow.

- **Notifications and background check:** the app now wakes about every 15 minutes (or later) to fetch and decrypt messages while closed, so messages are decrypted on the phone even when the calculator is locked, and the relay sees a connection from your IP on that schedule. The notification text is generic, but its existence and timing show that the app received something, and the icon and package name remain visible to Android and anyone holding the phone. Switch it off in Settings to stop background activity. No push service is used.
