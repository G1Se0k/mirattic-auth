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

### B. Dual Acceptance (done, then ended by D on 2026-09-29)
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

## Sync-side Work List (approved 2026-09-29; Sync `docs/progress.md`, `docs/protocol/rest.md`)
1. ✅ `/auth/start`, `/auth/callback`, `/api/auth/handoff` (one-time code, 60 s, single use, bound to the
   extension's own PKCE verifier; state bound to the browser by a `sync_login` cookie)
2. ✅ `/api/auth/refresh`, `/api/auth/logout` → relay to Auth token / revoke endpoints (legacy tokens told
   apart by their DB hash; only Auth `400 invalid_grant` becomes 401, other failures 502)
3. ✅ JwtDecoder: Auth RS256 (JWKS, aud `mirattic-sync`, access tokens only) + legacy HS256, picked by `alg`
4. ✅ user sync: first Auth login of an unknown `sub` → Sync `users` row (product fields only)
5. ✅ extension 0.0.13: `identity` permission, "Mirattic 계정으로 로그인" button, password forms dropped;
   legacy Sync sign-up returns 410 in production
6. ➖ import skipped (2026-09-29, user decision): production Sync had no real accounts (one test account,
   which keeps its legacy login until step 7).
7. ✅ legacy auth removed (2026-09-29, user request): Sync sign-up/login/refresh tokens/passwords/JWT secret
   gone, V15 drops `refresh_tokens` and `user_identities`; API accepts Auth access tokens only; `/api/me` email
   read live from Auth UserInfo. Sync account deletion re-authenticates at Auth (`prompt=login`, `auth_time`
   ≤ 5 min, same `sub`); deletes the Sync profile only, the Mirattic account stays.

## Flow (decided and done 2026-09-29, Phase 4)
- Kakao / Naver moved into Auth (`oauth-oidc.md` "Social Login"); Flow no longer talks to them.
- Existing Flow accounts were test data (5 users, 1 workspace): **not imported**; production Flow DB backed up,
  then recreated. No linking UX needed.
- Flow keeps its numeric `users.id` (every FK uses it) and adds `mirattic_uid` (unique) = Auth `sub`.
- Same model as Sync (option B), adapted for a web app: the Flow backend is the confidential client
  (`/auth/start`, `/auth/callback`), the browser holds Auth's access / refresh token only in HttpOnly cookies
  (`flow_at` 15 min path `/`, `flow_rt` 30 d path `/api/auth`), the backend validates the access token via JWKS
  (aud `mirattic-flow`, access tokens only) and relays refresh / revoke. Cookie CSRF: unsafe `/api` requests need
  `X-Requested-With: flow`. WebSockets authenticate with the handshake cookie and are closed at token `exp`.
- Removed from Flow: signup, login, Kakao / Naver clients, refresh tokens, passwords, JWT secret, email / password
  change. Flow account deletion ("탈퇴") deletes Flow data only (the Mirattic account stays) and only through an Auth
  re-authentication (`prompt=login`, same user, `auth_time` after the start); it then ends the Auth session.
- Flow users record the `auth_time` of the login that created them, and each withdrawal (UID hashed): tokens of older
  logins are rejected and a re-join needs a login newer than the withdrawal (`oauth-oidc.md`).

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
