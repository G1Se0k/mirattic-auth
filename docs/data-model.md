# Data Model

## users
```text
id UUID PK
display_name VARCHAR(64)   -- ≤ 20 units, ASCII 1 / other 2 (10 Korean, 20 English); new accounts cut, renames refused (also in Flow). Older longer names kept
status ACTIVE | SUSPENDED | DISABLED | DELETED   -- SUSPENDED: admin (admin.md); DISABLED: deletion fence
created_at
updated_at
```

## user_identities
```text
id UUID PK
user_id UUID FK
provider LOCAL | KAKAO | NAVER (GOOGLE | APPLE later)
subject VARCHAR(...)
email VARCHAR(...) NULL
password_hash VARCHAR(...) NULL
created_at
updated_at

UNIQUE(provider, subject)
```

Rules:
- LOCAL subject = normalized email
- OAuth subject = provider stable subject ID
- never derive UID from email
- same email does not automatically mean same account


## password_reset_tokens
Same one-time, expiring, hashed-token pattern.

## oauth_clients
May be config-backed initially.

Conceptual fields:
```text
client_id
client_name
client_type
redirect_uris
grant_types
scopes
enabled
```

## Refresh / Authorization State
Prefer Spring Authorization Server's authorization model unless a concrete need requires custom tables.

Stored via `JdbcOAuth2AuthorizationService` wrapped by `HashedTokenAuthorizationService`:
every token value column (code, access, refresh, ID token) holds `sha256:<hex>`, never the raw value.
Requires refresh rotation (`reuse-refresh-tokens: false`; enforced at startup).

Rotated-away refresh tokens: `rotated_refresh_tokens(token_hash, authorization_id → oauth2_authorization ON DELETE CASCADE)`.
Presenting one again removes the authorization.

Requirements:
- rotation
- revocation
- optional reuse detection
- session/client association

## signup_ips
```text
ip_hash CHAR(64) PK        -- SHA-256 of IPv4 address / IPv6 /64
last_signup_at DATETIME(6)
```
One LOCAL signup per network per 24 h; rows purged after a day.

## Auth Browser Sessions
Spring Session JDBC tables `SPRING_SESSION` / `SPRING_SESSION_ATTRIBUTES` (V3, bundled schema).
`PRINCIPAL_NAME` = users.id.

## Sessions
For account-center display:
```text
session_id
user_id
client_id
created_at
last_used_at
expires_at
device_name?
revoked_at?
```

Collect only necessary metadata.

## Signing Keys
- private key outside source code
- public keys via JWKS
- `kid`
- rotation metadata

## Product DBs
Products reference Auth UID through token `sub`.
Do not create cross-database foreign keys.
