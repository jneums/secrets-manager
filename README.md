# 🔐 Secrets Manager

A secure, per-principal key-value store for secrets on the Internet Computer, exposed as an MCP server.

## Overview

Secrets Manager gives agents and users a private, persistent vault on the Internet Computer. Each authenticated identity gets its own isolated namespace — no databases, no external services, just on-chain storage scoped to your principal.

**Canister:** `h55lw-dyaaa-aaaal-qxb5q-cai`  
**MCP URL:** `https://h55lw-dyaaa-aaaal-qxb5q-cai.icp0.io/mcp`

## Tools

| Tool | Description |
|------|-------------|
| `set_secret` | Store or update a named secret (upsert). Supports `encrypted` flag for client-side encrypted values. |
| `get_secret` | Retrieve a secret by key, including its value. |
| `list_secrets` | List all your secret keys with metadata (values are never returned). Supports label filtering and pagination. |
| `delete_secret` | Permanently delete a secret. Idempotent — safe to call on non-existent keys. |
| `get_secret_metadata` | Get metadata (timestamps, labels, encrypted flag) without exposing the value. |
| `update_labels` | Update labels on a secret without changing its value. |

## Security Model

- **All tools require authentication** — no anonymous access
- **Per-principal isolation** — each identity can only access their own secrets
- **Client-side encryption support** — set `encrypted: true` when storing pre-encrypted values
- **No admin backdoor** — even the canister owner cannot access other principals' secrets

> ⚠️ **Note:** Canister memory is theoretically visible to subnet node operators. For highly sensitive secrets, encrypt values client-side before storing. V2 will integrate ICP VetKeys for transparent on-chain encryption.

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
mops install --lock ignore --no-toolchain
icp build secrets-manager
npm test
```

## Deploy

```bash
icp deploy secrets-manager -e ic
```

## License

MIT
