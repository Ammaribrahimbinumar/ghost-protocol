# Ghost_Protocol relay

Minimal, stdlib-only Go relay. It stores public key material and opaque encrypted envelopes; it never receives private keys or message keys.

`go vet ./... && go test -race -count=1 ./...` — 14 tests. See `../docs/FEATURE_REPORT.md` for exactly what they cover and their limits.

## API (JSON, TLS 1.3)
Unauthenticated (rate-limited per hashed IP):
- `POST /v1/admin/invites` — `Authorization: Bearer $GHOST_ADMIN_TOKEN` → `{"invite": "..."}`
- `POST /v1/register` — `{invite, username, auth_pub, bundle, one_time_prekeys[]}` (byte fields base64) → `{mailbox_id}`. Username `^[a-z0-9_]{3,32}$`, `auth_pub` = 32-byte Ed25519 key
- `GET /v1/bundle/{username}` → `{mailbox_id, bundle, one_time_prekey?}` (pops one prekey)

Authenticated (per-request Ed25519 signature):
- `PUT /v1/prekeys`, `POST /v1/send/{mailbox}` (raw opaque body ≤ 64 KiB), `GET /v1/inbox`, `POST /v1/ack` `{ids[]}`, `DELETE /v1/account`

Headers: `X-Mailbox`, `X-Timestamp` (unix seconds, ±60 s), `X-Nonce` (8–64 chars, single use), `X-Signature` = base64 Ed25519 over
`METHOD \n PATH \n TIMESTAMP \n NONCE \n hex(SHA-256(body))`.

No search or listing endpoint exists; a username must be known exactly. See `../docs/BUILD_AND_SIGNING.md` for running and deployment, and `../docs/PRIVACY_AND_RETENTION.md` for what is kept.
