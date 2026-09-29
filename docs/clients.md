# Registered OAuth Clients

Single source for client IDs and redirect URIs. Config: `src/main/resources/application.yml` (prod),
`application-local.yml` (dev redirect URIs, same client IDs).

## Decisions (2026-09-29)
- Clients: **Mirattic Sync**, **Mirattic Flow**. No platform suffix (`-extension`, `-web`) in client IDs.
- **Desktop app is not served** → no desktop client, no loopback redirect in prod.
- Redirect path is `/auth/callback` on each product's own domain.
- **Confidential clients**: each product backend receives the callback and exchanges the code with its
  client secret (+ PKCE). Tokens never reach browser JS. Refresh tokens are issued natively.

## Clients
| | Sync | Flow |
|---|---|---|
| client ID | `mirattic-sync` | `mirattic-flow` |
| prod redirect URI | `https://sync.mirattic.com/auth/callback` | `https://flow.mirattic.com/auth/callback` |
| dev redirect URI | `http://127.0.0.1:8080/auth/callback` (Sync server local port) | `http://127.0.0.1:3000/auth/callback` (Next.js dev) |
| type | confidential, `client_secret_basic` + PKCE S256 required | confidential, `client_secret_basic` + PKCE S256 required |
| grant types | `authorization_code`, `refresh_token` | `authorization_code`, `refresh_token` |
| scopes | `openid`, `profile`, `email` | `openid`, `profile`, `email` |
| consent screen | none (first-party) | none (first-party) |
| token `aud` | `mirattic-sync` | `mirattic-flow` |
| access token | JWT RS256, 15 min | JWT RS256, 15 min |
| refresh token | opaque, 30 days, rotated on every use | opaque, 30 days, rotated on every use |
| secret env (Auth, hash only) | `SYNC_CLIENT_SECRET_HASH` | `FLOW_CLIENT_SECRET_HASH` |
| dev secret (local profile) | `dev-sync-secret` | `dev-flow-secret` |

## Client Secrets
- Auth stores only the BCrypt hash; the raw secret lives only in the product backend's env.
- Prod Auth refuses to start without both hash env vars.
- Generate:
  ```bash
  openssl rand -base64 32                                              # raw secret → product backend
  htpasswd -bnBC 12 "" '<raw secret>' | tr -d ':\n' | sed 's/^/{bcrypt}/'  # → Auth *_CLIENT_SECRET_HASH
  ```
- Rotate: new secret → update hash in Auth + raw in product, restart both (no overlap window yet).

## Token Behavior
- Any token issuance (code exchange or refresh) requires the account to be `ACTIVE`.
- Refresh rotation: the used refresh token stops working. Concurrent refreshes with one token: exactly
  one wins (row-locked compare-and-swap), the others get `invalid_grant`.
- Reuse detection: a rotated-away refresh token presented **more than 10 s after** its rotation, by the
  owning client, revokes the whole authorization (all tokens of that login, incl. the newer refresh
  token); the user's other logins are untouched. Within 10 s it is only refused (retries / overlapping
  requests look identical to the legit winner). Clients should still refresh single-flight.
- Password change/reset deletes all of the user's authorizations → refresh fails.
- `/oauth2/revoke` (client auth) revokes a refresh token.
- Replaying an already-used authorization code revokes the tokens it issued.
- All token values are stored hashed (`security.md`).
- Claims: `sub` = Mirattic UID; `profile` → `name`; `email` → `email`, `email_verified: false`.
  `/userinfo` (Bearer access token) returns live values, limited to that access token's scopes
  (a refresh with a narrower `scope` narrows UserInfo too), and 401 for non-ACTIVE accounts.

## Rules
- Redirect URIs match exactly (scheme, host, port, path). No wildcards.
- Dev URIs are registered only under the `local` profile; prod config never contains them.
- Dev uses `127.0.0.1`, not `localhost` (Spring Authorization Server rejects `localhost` redirect hosts).
- Loopback exception (Spring default, RFC 8252): for `http://127.0.0.1` redirects the **port is ignored**
  (scheme/host/path still exact). Affects dev only, since prod has no loopback URIs.
- Resource servers (Sync/Flow backends) validate `iss` = Auth issuer and `aud` = their own client ID.

## Open
- Flow prod domain assumed `flow.mirattic.com` (Flow's `.env.prod.example` still says `flow.example.com`).
- Sync: decided — extension holds Auth tokens, Sync relays refresh (`migration.md`). Flow: decide in Phase 4.
