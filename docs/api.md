# Account API Plan

OAuth/OIDC endpoints follow standards/Spring Authorization Server.
This file records Mirattic-specific account APIs.

## Account Pages (Phase 1, implemented)
Passwords are typed only on Auth's own pages, never into product clients, so signup / reset / profile
are server-rendered forms on `auth.mirattic.com` (form POST + CSRF token), not JSON APIs.

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET/POST | `/login` | – | Spring Security form login (`username` = email). Any failure → `/login?error` (one generic message). After login the saved `/oauth2/authorize` request resumes. |
| GET/POST | `/signup` | – | `email`, `displayName`, `password`. Creates user (UUID) + LOCAL identity, then → `/login?signup`. No auto-login. One per network per 24 h. |
| GET/POST | `/password/reset` | – | `email`. Same response whether or not the account exists. One mail per account per 24 h. |
| GET/POST | `/password/reset/confirm` | reset token | `token`, `password`. One-time, 30 min. → `/login?reset`. |
| GET | `/account` | session | email, UID, display name. |
| POST | `/account/name` | session + CSRF | `displayName` |
| POST | `/account/password` | session + CSRF | `currentPassword`, `password`; ends the user's other Auth sessions |
| POST | `/logout` | session + CSRF | → `/login?logout` |

Validation:
- email: trimmed + lower-cased, `x@y.z` shape, ≤ 254
- display name: 1–64 chars after trim
- password: ≥ 8 chars and ≤ 72 UTF-8 bytes (BCrypt limit; longer is refused, not truncated)

Password change / reset deletes the user's `oauth2_authorization` rows (refresh tokens die).

A JSON `GET /api/account/me` was dropped for now: products get identity from ID token / UserInfo. Add it with the account center if needed.

## Devices (Phase 5, `Devices`)
Server-rendered on `/account` ("로그인된 기기"), no JSON API.
- Browser: each Auth browser session of the user (Spring Session). The browser and OS ("Chrome · Windows", from
  User-Agent) and the sign-in time are stored on the session at sign-in (password or Kakao / Naver); older
  sessions show "알 수 없는 브라우저". Identified in the page by SHA-256 of the session id (the id is the cookie).
- App: each `oauth2_authorization` of the user with a live refresh token, named by the client (Mirattic Sync /
  Flow). Last used = last refresh.
- `POST /account/devices/end` (session + CSRF, `id`): ends that browser session or deletes that authorization (its
  access token lapses within 15 min). Only the user's own; this browser is ended by `/logout`, not here.

## Sign-in Methods (Phase 5)
Server-rendered on `/account` ("로그인 방법"). Rules in `security.md` "Account Linking".
- `POST /account/link/{kakao|naver}` (session + CSRF): → `/oauth2/authorization/{provider}` → back to `/`, or
  `/account?link_error=taken|exists|failed`. Stale sign-in (> 10 min): `/login?reauth`.
- `POST /account/unlink/{kakao|naver}` (session + CSRF): `/account?unlinked`; refused for the last method.

## Account Deletion
`DELETE /api/account`

Initial behavior:
- disable/delete Auth account
- revoke sessions
- notify/queue deletion event for product services
- each product applies its own data-deletion policy
