# Manual security test checklist

Record **PASS / FAIL / NOT RUN** with date, device, Android version and tester. Nothing here has been run. Use synthetic accounts and messages only.

| # | Test | Steps | Pass if |
|---|---|---|---|
| 1 | Screenshot block | Open each sensitive screen; take a screenshot and a screen recording | Capture is black/blocked on calculator, unlock, setup and chat screens |
| 2 | Recents preview | Open app, press Recents | Thumbnail is blank |
| 3 | Backup exclusion | `adb shell bmgr backupnow com.ghostprotocol.app` then inspect; try `adb backup`; do a device-to-device transfer | No app data present |
| 4 | Database at rest | On a rooted emulator copy `/data/data/com.ghostprotocol.app`; run `strings` on every file | No message text, no unlock code, no plaintext keys |
| 5 | Unlock throttling | Enter 5 wrong codes, then the right one | Right code does not unlock during back-off; screen looks like a normal wrong result |
| 6 | Calculator unaffected | Run arithmetic including digit-only entries | Normal results; no hint that a secret exists |
| 7 | Logcat | Use the app with `adb logcat` running | No input, codes, keys, or message text |
| 8 | Notifications | Receive a message with the device locked | Generic text only |
| 9 | Accessibility check | Enable a screen-reading accessibility service, unlock | HIGH warning shown; policy respected |
| 10 | Overlay/tapjack | Use an overlay test app over the unlock/send buttons | Touches are dropped |
| 11 | Invalid TLS | Point the app at a relay with a self-signed or wrong-host certificate | Connection refused; no fallback to cleartext |
| 12 | User-installed CA | Install a proxy CA in the user store (mitmproxy) | Relay traffic cannot be intercepted |
| 13 | Tamper/replay | Modify or replay a captured envelope via a test relay | Client rejects; no crash |
| 14 | Key change | Reinstall a contact's app | Warning shown; messages not silently trusted |
| 15 | Group removal | Remove a member, send a message | Removed member cannot decrypt new messages |
| 16 | Disappearing messages | Set 1 minute, wait | Rows and attachment files gone |
| 17 | Crash/restart | Kill app during send | No plaintext left in cache; no data corruption |
| 18 | Clipboard | Compose in the in-app keyboard | Nothing written to the clipboard |
| 19 | Rooted device | Run on a rooted device | Documented limitations match observed behaviour |
