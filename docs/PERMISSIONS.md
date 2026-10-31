# Permission justification

| Permission | Why | Notes |
|---|---|---|
| `INTERNET` | Reach the relay over TLS 1.3 | Normal permission, no runtime prompt |
| `POST_NOTIFICATIONS` | Show only a generic "Calculator got an update" notification (Android 13+ runtime prompt, asked once after you join a relay) | No sender, text, count or buttons; you can switch the background check off in Settings |
| `RECEIVE_BOOT_COMPLETED` | Lets the periodic background check keep its schedule after a reboot | Normal permission, no prompt |
| `HIDE_OVERLAY_WINDOWS` | Ask Android to hide other apps' overlay windows over Ghost_Protocol (tapjacking protection, API 31+) | Normal permission, no runtime prompt; visible in the package's permission list |

Not requested, by design: contacts, phone/number, SMS, location, storage (app-private storage only), camera, microphone, accessibility service, device admin, VPN, advertising ID, foreground-service types.

When a feature that needs one is built (camera for QR scanning and photos, microphone for voice notes), the permission is added then, requested at the moment the user triggers the feature, and listed here.

Android exposes the installed package, its requested permissions and its network use to the OS and to anyone examining the device. This list is not hidden by the calculator front-end.
