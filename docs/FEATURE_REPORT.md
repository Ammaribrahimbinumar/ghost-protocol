# Ghost_Protocol — Feature Completion Report

Updated 2026-10-29 at commit f45f8da (main). Statuses:

- **PASS (CI)** — an automated test ran on GitHub Actions and passed. Says what ran: JVM, emulator (Android 34 x86_64, google_apis), or R8-minified emulator.
- **BUILT, NOT TESTED** — code compiles; no test exercises it.
- **NOT RUN ON A PHYSICAL PHONE** — applies to everything. No physical device has been used. Emulator Keystore is software-backed.
- **NOT IMPLEMENTED** — no code.
- **BLOCKED** — needs something outside this environment.

No security audit and no penetration test has been performed by anyone. Nothing here is a proof of security.

## CI results (run 40817788199, commit f45f8da)
- relay job: PASS (`go vet`, 15 tests, `-race`). Cross-compiled relay binaries for Windows/Linux/macOS are produced as an artifact with SHA256SUMS.
- android job: PASS — 128 JVM tests, 0 failures, 0 skipped (crypto core, client, groups, attachments, tamper, persistence, unlock verifier, controller).
- device-tests job: PASS — 24 emulator tests, 0 failures: debug build plus an R8-minified release build (crypto pass).

## Features
| Feature | Status | Notes |
|---|---|---|
| Signal protocol (libsignal 0.105.1: PQXDH + Double Ratchet), no hand-written crypto | PASS (JVM + emulator + R8 release) | libsignal's own correctness is assumed, not tested by us |
| Relay: invite-only registration, per-request ECDSA auth, TTL queues, rate limits | PASS (Go tests) | Relay sees sender, recipient, size, time; sealed sender NOT IMPLEMENTED |
| Private keys never sent to relay | PASS (relay integration test: relay holds no keys, no plaintext, clean log) | |
| 1:1 send/receive through the real relay | PASS (JVM clients; emulator controller vs real relay) | Plain HTTP on loopback in tests only; client refuses non-HTTPS otherwise |
| Persistent encrypted identity + sessions (Keystore AES-256-GCM) | PASS (7 JVM + 5 emulator) | Tamper / missing key reported as corruption, never silently replaced |
| Message history storage | BUILT, partly tested | Stored in the same encrypted client record; SQLCipher/Room NOT IMPLEMENTED; no search/edit/reactions/replies |
| Key-change detection and blocking; safety numbers | PASS (JVM) | UI exists; QR scan NOT IMPLEMENTED; UI not emulator-tested |
| Tamper resistance (exhaustive single-byte flips never change plaintext) | PASS (JVM TamperTest) | |
| Disappearing messages | PASS (JVM) | Deletion is best-effort; the recipient can copy or screenshot-by-camera |
| Groups (pairwise fan-out, creator-only admin) | PASS (12 JVM + 1 emulator with two peers) | Not Sender Keys. Removed members keep earlier messages. Membership control is creator-only |
| Broadcast (individual 1:1 sends) | PASS (JVM) | Recipients cannot tell it was a broadcast beyond content |
| Encrypted attachments (≤1 MiB, 1:1 only, per-file key inside E2EE message) | PASS (12 JVM + 1 emulator: file on disk is ciphertext) | Group attachments NOT IMPLEMENTED |
| Calculator disguise, user-configured code, no default, PBKDF2 600k, back-off | PASS (JVM + emulator UI) | Appearance never reviewed by a human on a real screen |
| In-app keyboard, no TextField / system IME | PASS (emulator UI interaction) | JVM `String` copies used for drawing cannot be wiped |
| FLAG_SECURE, touch filtering | PASS (emulator reads the window flags) | Actual screenshot/recents blocking NOT RUN ON A PHYSICAL PHONE |
| Accessibility / overlay / ADB risk checks (warn-only by default) | PASS (JVM unit) | Detection is best-effort and can be evaded |
| Decoy code (separate empty profile with own keys/files) | PASS (verifier JVM tests; settings UI emulator test) | Decoy profile end-to-end behaviour via the calculator is BUILT, NOT TESTED beyond that |
| Duress code (erases real data, opens decoy) | PASS for erase-everything primitive (emulator: files + Keystore aliases gone, late writes do not recreate, new identity possible); calculator→duress path BUILT, NOT TESTED end-to-end | Not forensic-proof; flash wear levelling may keep remnants |
| Erase everything now | PASS (emulator) | Relay account and queued messages are not touched |
| Release hardening (R8, libsignal keep rules, log stripping) | PASS (release crypto pass on emulator) | Found and fixed a real JNI crash |
| Signed release APK | BLOCKED here | Signing key must exist only on your machine; see BUILD_AND_SIGNING.md |
| Windows admin app (GhostAdmin.exe): start relay + Cloudflare tunnel, invite codes, user list with addresses | BUILT. PASS on a Windows CI runner: 16 tests (encrypted vault round-trip, wrong password, single-byte tampering, nothing readable on disk, gate delays, tunnel-address parsing, the real relay driven through the app's classes incl. admin port not on public port, snapshot restore, window capture exclusion flag read back) | The window layout, buttons and the start/stop/invite/user-list screens were NEVER run or seen by me; the tunnel start from the app is untested against real Cloudflare. Unsigned exe. Not audited |
| Per-action password prompt in the admin app | BUILT, gate logic PASS (JVM-style unit tests); the dialog flow itself NOT RUN | |
| Linked devices / revocation | NOT IMPLEMENTED | |
| Launcher icon (generic calculator, adaptive + themed) | BUILT; resources compile and the build passes; rendered preview checked by me | Not yet seen on a real phone launcher |
| Generic notification "Calculator got an update" | PASS (emulator: only on arrival while off-screen; title/text fixed; no sender, text, count or buttons; none while app is on screen; none when switched off) | Real-phone behaviour NOT RUN |
| Background check (JobScheduler, ~15 min or later) | PASS (emulator: job scheduled; erase-everything cancels it) | Not instant. Doze/battery saver can delay it a lot; OEM battery managers may kill it. Real timing NOT RUN |
| Tor / I2P routing | NOT IMPLEMENTED | |
| Sealed sender | NOT IMPLEMENTED | |
| Group attachments, Sender Keys, SQLCipher | NOT IMPLEMENTED | |
| Screen-capture detection callback (API 34) | NOT IMPLEMENTED | |
| In-foreground inactivity auto-lock | NOT IMPLEMENTED | App locks on leaving it |
| Layout / appearance on real screens | NOT RUN | Never viewed by a human |

## Acceptance criteria (spec section 22)
| Criterion | Status |
|---|---|
| Two installed clients exchange encrypted messages | PARTIAL: emulator app controller exchanges with JVM peers through the real relay. Two installed phones NOT RUN |
| Relay cannot decrypt contents | Demonstrated in CI (not a proof; metadata visible) |
| Client detects tampering | PASS (JVM) |
| Identity verification works | Crypto PASS; UI built, not emulator-tested |
| Messages encrypted in local storage | PASS (encrypted client record; emulator checks file contents) |
| No plaintext in logs/notifications | Relay PASS. Client logs stripped in release; notifications don't exist |
| Calculator unlock, in-app keyboard | PASS (emulator) |
| Screenshot protection | Flag verified; real behaviour NOT RUN on a phone |
| Groups, broadcast, attachments, disappearing | PASS at the levels above |
| Backup exclusion | Rules written; NOT verified with a real backup |
| Build/install instructions | Debug and R8 release builds PASS in CI; signed APK on your machine NOT RUN |
| Limitations document matches implementation | See SECURITY_LIMITATIONS.md |

**Overall: a working prototype verified in CI and on an emulator. It has not been audited, and it has not been run on a physical phone. Do not rely on it for life-critical secrecy.**
