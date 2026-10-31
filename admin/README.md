# Ghost admin (Windows)

A desktop program for the person who runs the relay. Nothing to type in a console:

1. Open `GhostAdmin.exe`. First run: choose an admin password (no recovery exists).
2. Click **Start server + tunnel** (password asked). It starts the relay and Cloudflare's tunnel and shows the address.
3. Click **Request invite code** (password asked). Copy the invite message and send it to your user yourself.
4. **Show registered users** (password asked) lists usernames and the last address each connected from.

Every window is excluded from screenshots/screen recording. All data this app keeps lives in
`%LOCALAPPDATA%\GhostAdmin\vault.bin`, encrypted with AES-256-GCM under a key derived from the password (PBKDF2-HMAC-SHA256, 600,000 rounds).

Needs `ghost-relay.exe` next to `GhostAdmin.exe` (the download includes it) and Cloudflare's `cloudflared`
(`winget install --id Cloudflare.cloudflared`). See `docs/ADMIN_APP.md` for what is and is not protected.
