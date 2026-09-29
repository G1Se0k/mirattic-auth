# Migration Plan — Sync / Flow

## Goal
Move authentication ownership into Mirattic Auth without moving product-domain data.

## Sync
Sync already separates UID and login identity conceptually, which is favorable.

Preferred strategy:
- preserve existing user UUIDs as global Mirattic UID where practical
- import identities into Auth
- keep Sync product data keyed by the same UUID

## Decision (2026-09-29): Auth tokens end to end (option B)
The extension holds **Auth** tokens; Sync validates Auth JWTs and only relays refresh.
Rejected: Sync keeps its own session after an Auth login (option A) — account disable/logout would take
up to 30 days to reach Sync, and the account center could not see Sync sessions.

```text
login
  extension ─ chrome.identity.launchWebAuthFlow ─▶ https://sync.mirattic.com/auth/start
  Sync  ─▶ auth.mirattic.com/oauth2/authorize (PKCE + state, kept server-side)
  Auth  ─▶ https://sync.mirattic.com/auth/callback?code=…
  Sync  ─▶ POST /oauth2/token (client secret + code_verifier)  → Auth access / refresh / ID token
  Sync  ─▶ https://<extension-id>.chromiumapp.org/?handoff=<one-time code>   (no token in any URL)
  extension ─▶ Sync POST /api/auth/handoff {code} → Auth access + refresh token

API     extension ─ Bearer <Auth access token> ─▶ Sync (validates via Auth JWKS: sig, iss, aud=mirattic-sync, exp)
refresh extension ─▶ Sync /api/auth/refresh {refreshToken} ─▶ Auth /oauth2/token (+ client secret)
logout  extension ─▶ Sync /api/auth/logout ─▶ Auth /oauth2/revoke (+ client secret)
```

- Refresh token stays in `chrome.storage.local` (TRUSTED_CONTEXTS), as today. Client secret only on Sync server.
- Account disable / password change / logout reach Sync within one access-token lifetime (15 min).
- Auth-side prerequisites: confidential client, rotation, hashed storage, ACTIVE check, **refresh reuse
  detection (family revoke)** — all done (Phase 2 + Phase 3 prep).

## Migration Phases

### A. Build Auth beside existing login
- create Auth
- copy/import account identities (Sync `users.id` → Auth `users.id` unchanged; `user_identities` LOCAL rows
  incl. `{bcrypt}` hashes → Auth as is; `display_name` from Sync `users`)
- verify password-hash compatibility (Sync uses DelegatingPasswordEncoder → compatible)
- keep legacy login temporarily

### B. Dual Acceptance
Sync temporarily accepts:
- legacy Sync token (HS256, iss `mirattic`)
- Mirattic Auth token (RS256 via JWKS, iss = Auth URL, aud `mirattic-sync`)

Both map to same UID (`sub`).

### C. Client Cutover
- extension login → Auth (client `mirattic-sync`, see `clients.md`; desktop is not served)
- new accounts created only in Auth

### D. Remove Legacy Auth
Remove from Sync:
- signup
- login
- refresh (own tokens; the Auth refresh relay stays)
- password reset
- credential storage (`user_identities`, `refresh_tokens`, JWT secret)

Keep product profile/friend/room/chat data.

## Sync-side Work List (NOT started — Sync code changes need explicit approval)
1. `/auth/start`, `/auth/callback`, `/api/auth/handoff` (one-time code, short TTL, single use)
2. `/api/auth/refresh`, `/api/auth/logout` → relay to Auth token / revoke endpoints
3. JwtDecoder: accept Auth RS256 (JWKS) + legacy HS256 during dual acceptance
4. user sync: first Auth login of an unknown `sub` → create Sync `users` row (product fields only)
5. extension: `identity` permission, "Mirattic 계정으로 로그인" button, drop password forms
6. import existing Sync accounts into Auth (one-shot, dry-run first — destructive-migration approval needed)
7. remove legacy auth after stabilization

## Flow
If Flow has separate accounts:
- inspect UID model
- identify overlapping real users
- never auto-merge by email
- provide explicit linking/migration UX when necessary

## Password Hashes
If compatible, migrate hashes directly.
If not:
- temporary legacy verification or
- forced password reset

Never migrate plaintext passwords.

## Rollback
Before cutover:
- DB backup
- dry-run migration
- user/identity counts
- feature flag for legacy login where practical
- token rollback plan

## Final State
```text
Mirattic Auth
- users / identities / credentials / sessions

Mirattic Sync
- UID reference / friends / rooms / chat / presence

Mirattic Flow
- UID reference / workspaces / projects / issues
```
