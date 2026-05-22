# 🔐 Secrets Manager

A secure, per-principal key-value store for secrets on the Internet Computer, exposed as an MCP server. All secret values are encrypted at rest using **vetKey identity-based encryption (IBE)**.

## Overview

Secrets Manager gives agents and users a private, persistent vault on the Internet Computer. Each authenticated identity gets its own isolated namespace — no databases, no external services, just on-chain storage scoped to your principal.

All values are encrypted at rest using ICP's vetKD threshold protocol. The canister derives a unique encryption key per principal — no single subnet node ever possesses the decryption key.

**Canister:** `h55lw-dyaaa-aaaal-qxb5q-cai`  
**MCP URL:** `https://h55lw-dyaaa-aaaal-qxb5q-cai.icp0.io/mcp`

## Tools

| Tool | Description |
|------|-------------|
| `set_secret` | Store or update a named secret (upsert). Value is encrypted at rest via vetKey IBE. |
| `get_secret` | Retrieve and decrypt a secret by key. Returns the plaintext value. |
| `list_secrets` | List all your secret keys with metadata (values are never returned). Supports label filtering and pagination. |
| `delete_secret` | Permanently delete a secret. Idempotent — safe to call on non-existent keys. |
| `get_secret_metadata` | Get metadata (timestamps, labels) without exposing the value. |
| `update_labels` | Update labels on a secret without changing its value. |

## Security Model

- **vetKey encryption at rest** — all secret values are encrypted using ICP vetKey IBE before storage
- **Threshold key derivation** — encryption keys are derived via the vetKD protocol; no single node ever sees the raw key
- **All tools require authentication** — no anonymous access
- **Per-principal isolation** — each identity can only access their own secrets
- **No admin backdoor** — even the canister owner cannot access other principals' secrets
- **Canister-side encryption** — the canister encrypts on `set_secret` and decrypts on `get_secret`; plaintext is momentarily visible to the canister during these calls

## Limits

| Limit | Value |
|-------|-------|
| Key length | 1-128 chars (alphanumeric, `_`, `-`, `.`) |
| Value size | 10 KB max |
| Secrets per principal | 1,000 max |
| Labels per secret | 10 max |
| Label length | 64 chars max |

## Development

```bash
npm install
mops install
dfx start --background
dfx deploy
npm test
```

## License

MIT
