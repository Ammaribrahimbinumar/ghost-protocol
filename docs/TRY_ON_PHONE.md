# Trying Ghost_Protocol on your own phone (test build)

**Status:** the app sends and receives end-to-end-encrypted messages in CI (JVM + Android emulator, against the real relay). It has NOT been run on a physical phone yet; you will be the first. Use throw-away usernames and test messages only. There is no external security review. See `FEATURE_REPORT.md` and `SECURITY_LIMITATIONS.md`.

You need two things: the **app (APK)** and a **relay** that your phone can reach over HTTPS. For a first test, run the relay on your computer and expose it with a tunnel.

## 1. Get the files from GitHub Actions
Repo -> **Actions** -> newest green run of `build-and-test` -> **Artifacts**:
- `android-results` -> contains `app-debug.apk`
- `relay-programs` -> contains `ghost-relay-windows-amd64.exe` (or the Linux/Mac build) and `SHA256SUMS.txt`

(Artifacts are zip files. Only download from your own repository's runs.)

## 2. Run the relay on your computer
Pick a long random admin password (at least 32 characters) and keep it private.

Windows PowerShell:
```
$env:GHOST_ADMIN_TOKEN = "put-32-or-more-random-characters-here-xxxxxxxx"
.\ghost-relay-windows-amd64.exe -insecure-dev -addr 127.0.0.1:8443 -ip-rate 5 -ip-burst 100
```
Mac/Linux:
```
chmod +x ghost-relay-*; export GHOST_ADMIN_TOKEN="put-32-or-more-random-characters-here-xxxxxxxx"
./ghost-relay-linux-amd64 -insecure-dev -addr 127.0.0.1:8443 -ip-rate 5 -ip-burst 100
```
`-insecure-dev` means the relay itself speaks plain HTTP, but only on your own computer (127.0.0.1). The tunnel below adds HTTPS. The relay keeps messages only in memory; stopping it deletes them.

## 3. Give the relay an HTTPS address (tunnel)
Install Cloudflare's `cloudflared` and run:
```
cloudflared tunnel --url http://127.0.0.1:8443
```
It prints an address like `https://something-random.trycloudflare.com`. That is your **relay address**. Trade-off: the tunnel company can see connection metadata (not message contents, which are encrypted on the phones). This is for testing; a real deployment should use your own server with its own certificate (`-tls-cert`/`-tls-key`).

## 4. Make invitation codes
Each person needs one single-use code. In another terminal (replace the address and password):
```
curl -X POST -H "Authorization: Bearer YOUR_ADMIN_PASSWORD" https://something-random.trycloudflare.com/v1/admin/invites
```
It returns `{"invite":"..."}`. Make two codes if two phones will join.

## 5. Install the app
Copy `app-debug.apk` to the phone, open it, and allow "install unknown apps" for that file manager/browser when asked. (Play Protect may warn about an unknown app; it is your own unsigned debug build.)

## 6. Use it
1. Open the app: it is a calculator. First run asks you to set your **secret unlock** (digits, you choose; no default exists). If you forget it, the only way back in is clearing the app's data, which erases everything. This is by design.
2. Type your secret then press `=` to open the real app.
3. **Join a relay:** relay address, invitation code, username. Everything is typed on the in-app keyboard.
4. **Add contact:** the other person's exact username. Send a message. They see it within about 5 seconds, while their app is open and unlocked, or after a delay of about 15 minutes or more via the background check (which shows only a generic notification).
5. Open **Safety #** in the chat. Both phones must show identical numbers. Compare them out loud or in person, then tap **Mark as verified**.

## What to report back (PASS / FAIL / not tried)
Android version + phone model, and:
- Screenshots and screen recordings come out black on every screen? (Recents thumbnail blank?)
- Wrong secret on `=` looks like a normal calculator result?
- Message arrives and replies work between two phones? After force-closing and reopening, is history there?
- Safety numbers identical on both phones?
- Uninstall and reinstall one person's app with the same username: does the other person get a key-change warning and is sending blocked?
- Anything crashing, freezing, or confusing.

## Known limits of this build (so you are not surprised)
Notifications are generic ("Calculator got an update") and delayed (about 15 minutes or later, not instant). Groups, broadcast, attachments, decoy/duress codes and disappearing messages exist but have not been tried on a real phone. No linked devices, no Tor/I2P, relay can see which usernames talk to each other and when (sender names are not hidden), keys stay in memory while the app process lives (locking hides the screen but does not erase memory), debug build only (allows plain HTTP to 127.0.0.1 for tests; the release build will not).
