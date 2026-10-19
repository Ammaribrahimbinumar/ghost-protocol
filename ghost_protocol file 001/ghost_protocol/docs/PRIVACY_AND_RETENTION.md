# Privacy and data-retention policy (relay + client)

Describes what the **implemented relay** does today and what the client is intended to do.

## Relay — implemented and tested
| Data | Kept? | Where | How long |
|---|---|---|---|
| Message ciphertext | Yes, until acknowledged or expired | Memory only | Default 7 days (`-ttl-hours`); never written to disk; lost on restart |
| Username, mailbox ID, Ed25519 auth public key, public key bundle, one-time prekeys | Yes | `accounts.json` (0600) | Until the account is deleted |
| Invitation codes | Only SHA-256 hash until used; deleted on use | `accounts.json` | Until used |
| Client IP address | Not stored or logged | Used transiently; rate-limit keys are HMACs under an in-memory salt rotated every 24 h | Minutes |
| Request signatures/nonces | Nonces kept to block replay | Memory | About 2 minutes |
| Request logs | None written by the relay | — | — |
| Analytics, telemetry, third-party SDKs | None | — | — |

The relay learns, for each request: which mailbox is acting, which mailbox it sends to, payload size and timing. Without sealed sender (not implemented) it can build a social graph of mailboxes while it is running. Operators should not add logging, and any reverse proxy in front must have access logs disabled.

## Client — intended, not yet implemented/verified
- Messages, keys and attachments stay in app-private encrypted storage; no cloud backup; no phone number, email or contacts access.
- Disappearing-message expiry removes rows and attachment files locally.
- Notifications show generic text only.
